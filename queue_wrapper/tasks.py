import os
import base64
import logging
import requests
import json
import boto3
from celery_app import celery
log = logging.getLogger(__name__)
ANDROGUARD_BASE = os.getenv("ANDROGUARD_BASE", "http://android-static-backend:8010")
PDF_API = os.getenv("PDF_API", "http://192.168.50.53:15148/api/report")
S3_BUCKET = os.getenv("S3_BUCKET", "cmaa-s3-islab-sydney")
AWS_REGION = os.getenv("AWS_REGION", "ap-southeast-2")
def get_s3_client():
    return boto3.client(
        "s3",
        region_name=AWS_REGION,
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )
@celery.task(bind=True)
def analyze_apk(self, file_bytes_b64: str, filename: str, file_hash: str, s3_key: str = None):
    job_id = self.request.id
    file_bytes = base64.b64decode(file_bytes_b64)
    log.info("[%s] Job started: %s (hash=%s, size=%d bytes, s3_key=%s)", job_id, filename, file_hash, len(file_bytes), s3_key)
    def update(step, total, message):
        log.info("[%s] Step %d/%d — %s", job_id, step, total, message)
        self.update_state(state="STARTED", meta={"step": step, "total": total, "message": message})
    # Step 1: upload APK
    update(1, 4, f"Uploading {filename} ({len(file_bytes)} bytes)")
    files = {"file": (filename, file_bytes, "application/octet-stream")}
    load_resp = requests.post(f"{ANDROGUARD_BASE}/load_apk", files=files)
    load_resp.raise_for_status()
    log.info("[%s] Step 1/4 — Upload complete (status=%d)", job_id, load_resp.status_code)
    # Step 2: run Maldroid
    update(2, 4, "Running Maldroid analysis")
    maldroid_resp = requests.post(f"{ANDROGUARD_BASE}/run_maldroid")
    maldroid_resp.raise_for_status()
    log.info("[%s] Step 2/4 — Maldroid complete (status=%d)", job_id, maldroid_resp.status_code)
    # Step 3: get JSON report
    update(3, 4, "Retrieving JSON report")
    json_resp = requests.get(f"{ANDROGUARD_BASE}/get_json", params={"hash": file_hash})
    json_resp.raise_for_status()
    log.info("[%s] Step 3/4 — Report retrieved (status=%d, size=%d bytes)", job_id, json_resp.status_code, len(json_resp.content))
    report_data = json_resp.json()
    report_data["file_name"] = filename
    if "system" in report_data and isinstance(report_data["system"], dict):
        report_data["system"]["file_name"] = filename
    # Step 4: 預先生成 PDF 報告並直傳 S3
    update(4, 4, "Pre-generating PDF report")
    if s3_key:
        try:
            log.info("[%s] Requesting PDF generation from %s...", job_id, PDF_API)
            pdf_resp = requests.post(PDF_API, json=report_data, timeout=90)
            if pdf_resp.status_code == 200:
                pdf_bytes = pdf_resp.content
                s3_pdf_key = s3_key.replace("uploads/", "reports/").rsplit('/', 1)[0] + "/static.pdf"
                
                s3 = get_s3_client()
                s3.put_object(
                    Bucket=S3_BUCKET,
                    Key=s3_pdf_key,
                    Body=pdf_bytes,
                    ContentType="application/pdf",
                    ContentDisposition=f'attachment; filename="{filename}.pdf"'
                )
                log.info("[%s] [+] PDF pre-generated and uploaded to S3: %s (%d bytes)", job_id, s3_pdf_key, len(pdf_bytes))
            else:
                log.warning("[%s] PDF generator returned status %d: %s", job_id, pdf_resp.status_code, pdf_resp.text[:200])
        except Exception as e:
            log.error("[%s] [!] PDF pre-generation failed: %s", job_id, e)
    else:
        log.info("[%s] s3_key not provided, skipping S3 PDF upload", job_id)
    log.info("[%s] Job completed successfully", job_id)
    return report_data
