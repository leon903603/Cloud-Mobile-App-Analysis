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

        print(f"[StaticPDFLambda] Reading report from s3://{REPORT_BUCKET}/{report_key}")
        resp = s3.get_object(Bucket=REPORT_BUCKET, Key=report_key)
        rawdata = json.loads(resp['Body'].read().decode('utf-8'))

        if lang:
            while isinstance(rawdata, str):
            rawdata = json.loads(rawdata)
        rawdata['lang'] = lang
        elif 'lang' not in rawdata:
            rawdata['lang'] = 'zh-TW'

        print(f"[StaticPDFLambda] Rendering static PDF (lang={rawdata['lang']})")
        pdf_bytes = report.Product_PDF(rawdata)
        print(f"[StaticPDFLambda] Rendered PDF size: {len(pdf_bytes)} bytes")

        print(f"[StaticPDFLambda] Uploading PDF to s3://{REPORT_BUCKET}/{output_key}")
        s3.put_object(
            Bucket=REPORT_BUCKET,
            Key=output_key,
            Body=pdf_bytes,
            ContentType='application/pdf',
            ContentDisposition=f'attachment; filename="{filename}"'
        )

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
        import traceback
        traceback.print_exc()
        return {'ok': False, 'error': str(e)}
