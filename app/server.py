from flask import Flask, request, jsonify, send_from_directory, make_response
from flask_cors import CORS
import json
import report
from waitress import serve

app = Flask(__name__)
CORS(app, resorces={r'/*': {
        "origins": '*',
        "Access-Control-Allow-Credentials": True,
        "supports_credentials": True
    }},
    supports_credentials = True,
    expose_headers = "*"
)

@app.route('/api/report', methods = ['GET', 'POST'])
def send_report():
    dataraw = request.get_json()

    print(dataraw)

    # 檢查 request 中是否帶 "system" key
    if ('system' not in dataraw):
        return jsonify({"msg": "no system data in request body"}), 400

    # 檢查 request 中是否帶 "rule" key
    if ('rule' not in dataraw):
        return jsonify({"msg": "no rule in request body"}), 400

    # 檢查 request 中是否帶 "result" key
    if ('result' not in dataraw):
        return jsonify({"msg": "no result in request body"}), 400

    if ('lang' not in dataraw):
        dataraw['lang'] = 'en'

    report_pdf = report.Product_PDF(dataraw)

    res = make_response(report_pdf)
    res.headers.set('Content-Disposition', 'attachment', filename='report.pdf')
    res.headers.set('Content-Type', 'application/pdf')
    return res

if __name__=="__main__":
    serve(app, host='0.0.0.0', port=15148, threads=8)