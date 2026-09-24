from flask import Flask, request, jsonify
from queue import Queue
from threading import Thread
import requests
import websockets
import asyncio
import uuid
import time
import json

app = Flask(__name__)

# FIFO queue
job_queue = Queue()

import os
HOST = os.environ.get("BASE_HOST", "127.0.0.1:8080")

def run_ws_task(file_id):
    async def _task():
        ws_url = f"ws://{HOST}/ws"
        cookies = f"apk_name={file_id}; User=debug"
        headers = [("Cookie", cookies)]
        print(f"[WS] Connecting to {ws_url} with headers {headers} ...")

        async with websockets.connect(ws_url, extra_headers=headers) as ws:
            # Step 1: send packname
            pack_payload = {"packname": file_id}
            print(f"[WS] → Sending PACKNAME: {pack_payload}")
            await ws.send(json.dumps(pack_payload))

            # Wait a short moment to let base assign apkinfo
            await asyncio.sleep(2)

            # Step 2: send start
            start_payload = {"action": "start"}
            print(f"[WS] → Sending START: {start_payload}")
            await ws.send(json.dumps(start_payload))

            # Step 3: wait for server start
            while True:
                msg = await ws.recv()
                data = json.loads(msg)
                print(f"[WS] ← {data}")
                if data.get("status") == "ServerStart":
                    print("[WS] Server started.")
                    break
                elif data.get("status") == "FAIL":
                    print("[WS] Server failed to start (package_name missing?)")
                    return

            # Step 4: send auto until ready
            while True:
                auto_payload = {"action": "auto"}
                print(f"[WS] → Sending AUTO: {auto_payload}")
                await ws.send(json.dumps(auto_payload))

                msg = await ws.recv()
                data = json.loads(msg)
                print(f"[WS] ← Message: {data}")

                if data.get("msgdata") != "Dynamic Analysis Not Ready!!":
                    print("[WS] Dynamic analysis ready.")
                    break
                else:
                    print("[WS] Dynamic analysis not ready, retrying in 5 seconds...")
                    await asyncio.sleep(5)

            # Step 5: wait for CANSHOWACG
            while True:
                await ws.send(json.dumps({"action": "getOutput"}))
                msg = await ws.recv()
                data = json.loads(msg)
                print(f"[WS] ← {data}")
                if data.get("status") == "CANSHOWACG":
                    print("[WS] Analysis completed.")
                    break
                await asyncio.sleep(3)

    asyncio.run(_task())


def worker_loop():
    while True:
        job_id, file_bytes, filename, file_hash, response_holder = job_queue.get()
        try:
            # 1. Upload APK
            files = {"upload_file": (filename, file_bytes, "application/octet-stream")}
            print(f"[{job_id}] Uploading {filename}...")

            load_resp = requests.post(f"http://{HOST}/upload", files=files)
            load_resp.raise_for_status()
            
            if load_resp.status_code != 200:
                raise Exception(f"Upload failed with status {load_resp.status_code}")
            if "apk_name" not in load_resp.cookies:
                raise Exception("Upload response missing 'apk_name' cookie")
            uploaded_apk_name = load_resp.cookies["apk_name"]
            print(f"[{job_id}] Uploaded APK as {uploaded_apk_name}")

            # 2. Run WebSocket actions
            print(f"[{job_id}] Running dynamic analysis (start → auto)...")
            run_ws_task(uploaded_apk_name)

            # 3. Fetch result
            max_retries = 10
            retry_interval = 3     # seconds
            result_resp = None
            cookies = {"apk_name": uploaded_apk_name, "User": "debug"}

            print(f"[{job_id}] Retrieving report...")
            for attempt in range(max_retries):
                try:
                    result_resp = requests.get(f"http://{HOST}/result?format=json", cookies=cookies)
                    if result_resp.status_code == 200:
                        print(f"[{job_id}] Report ready!")
                        break
                    else:
                        print(f"[{job_id}] Result not ready yet (status={result_resp.status_code})")
                except requests.exceptions.RequestException as e:
                    print(f"[{job_id}] Attempt {attempt+1} failed: {e}")
                time.sleep(retry_interval)
            else:
                raise Exception("Result never became available after multiple attempts")

            response_holder["response"] = (result_resp.json(), 200, {"Content-Type": "application/json"})

        except Exception as e:
            print(f"[{job_id}] Error: {e}")
            response_holder["response"] = (jsonify({"error": str(e)}), 500, {})
        finally:
            job_queue.task_done()


# Start worker thread
Thread(target=worker_loop, daemon=True).start()


@app.route("/analyze_dynamic", methods=["POST"])
def enqueue_job():
    """
    Accepts APK file + hash, queues full dynamic analysis (start → auto → result).
    Blocks until report is ready.
    """
    if "file" not in request.files or "hash" not in request.form:
        return jsonify({"error": "Missing file or hash"}), 400

    file = request.files["file"]
    file_bytes = file.read()
    filename = file.filename or "unknown.apk"
    file_hash = request.form["hash"]

    job_id = str(uuid.uuid4())
    response_holder = {}

    job_queue.put((job_id, file_bytes, filename, file_hash, response_holder))

    print(f"[{job_id}] Job queued for {filename}")

    # Wait for result
    while "response" not in response_holder:
        time.sleep(0.3)

    return response_holder["response"]


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
