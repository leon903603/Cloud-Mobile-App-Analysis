import os
import io
import json
import base64
import logging
import boto3
from flask import Flask, request, jsonify
from tasks import analyze_apk
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("/var/log/wrapper.log"),
    ],
)
log = logging.getLogger(__name__)
app = Flask(__name__)
S3_BUCKET = os.getenv("S3_BUCKET", "cmaa-s3-islab-sydney")
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-2")
def get_s3_client():
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
@app.route("/analyze_apk", methods=["POST"])
def enqueue_job():
    file_bytes = None
    filename = "unknown.apk"
    file_hash = None
    s3_key = None
    if request.is_json:
        data = request.get_json() or {}
        s3_key = data.get("key")
        file_hash = data.get("hash")
        filename = data.get("filename", "unknown.apk")
        bucket = data.get("bucket", S3_BUCKET)
        if not s3_key or not file_hash:
            log.warning("JSON request rejected: missing key or hash")
            return jsonify({"error": "Missing key or hash"}), 400
        log.info("Downloading APK from S3: s3://%s/%s ...", bucket, s3_key)
        try:
            s3 = get_s3_client()
            buf = io.BytesIO()
            s3.download_fileobj(bucket, s3_key, buf)
            file_bytes = buf.getvalue()
            log.info("Downloaded %d bytes from S3 for %s", len(file_bytes), filename)
        except Exception as e:
            log.error("Failed to download from S3: %s", e)
            return jsonify({"error": f"Failed to download from S3: {str(e)}"}), 500
    elif "file" in request.files and "hash" in request.form:
        file = request.files["file"]
        file_bytes = file.read()
        filename = file.filename or "unknown.apk"
        file_hash = request.form["hash"]
    else:
        log.warning("Request rejected: invalid payload format")
        return jsonify({"error": "Missing file or S3 key"}), 400
    task = analyze_apk.delay(
        base64.b64encode(file_bytes).decode(),
        filename,
        file_hash,
        s3_key
    )
    log.info("Job %s queued for %s (s3_key=%s)", task.id, filename, s3_key)
    return jsonify({"job_id": task.id}), 202
@app.route("/status/<job_id>", methods=["GET"])
def job_status(job_id):
    task = analyze_apk.AsyncResult(job_id)
    if task.state == "PENDING":
        return jsonify({"status": "pending"})
    if task.state == "STARTED":
        meta = task.info or {}
        return jsonify({
            "status": "running",
            "step": meta.get("step"),
            "total": meta.get("total"),
            "message": meta.get("message"),
        })
    if task.state == "SUCCESS":
        result = task.result
        if isinstance(result, str):
            try:
                result = json.loads(result)
            except Exception:
                pass
        return jsonify({"status": "success", "result": result})
    if task.state == "FAILURE":
        log.error("Job %s failed: %s", job_id, task.info)
        return jsonify({"status": "failed", "error": str(task.info)}), 500
    return jsonify({"status": task.state.lower()})
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5001)
