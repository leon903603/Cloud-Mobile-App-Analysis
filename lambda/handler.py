import json
import os
import boto3
from botocore.exceptions import ClientError
import report

s3 = boto3.client('s3')
REPORT_BUCKET = os.environ.get('REPORT_BUCKET', 'cmaa-s3-islab-sydney')

def handler(event, context):
    try:
        report_key = event.get('report_key')
        lang = event.get('lang', 'zh-TW')
        output_key = event.get('output_key') or report_key.replace('.json', '.pdf')
        filename = event.get('filename') or os.path.basename(output_key)

        if not report_key:
            return {'ok': False, 'error': 'Missing report_key in payload'}

        # 1. Read JSON report from S3
        resp = s3.get_object(Bucket=REPORT_BUCKET, Key=report_key)
        rawdata = json.loads(resp['Body'].read().decode('utf-8'))
        rawdata['lang'] = lang

        # 2. Render PDF bytes
        pdf_bytes = report.Product_PDF(rawdata)

        # 3. Store PDF to S3
        s3.put_object(
            Bucket=REPORT_BUCKET,
            Key=output_key,
            Body=pdf_bytes,
            ContentType='application/pdf',
            ContentDisposition=f'attachment; filename="{filename}"'
        )

        # 4. Generate presigned download URL (valid for 1 hour)
        url = s3.generate_presigned_url(
            'get_object',
            Params={'Bucket': REPORT_BUCKET, 'Key': output_key},
            ExpiresIn=3600
        )

        return {
            'ok': True,
            'url': url,
            'key': output_key,
            'bytes': len(pdf_bytes),
            'expires_in': 3600
        }
    except Exception as e:
        return {'ok': False, 'error': str(e)}
