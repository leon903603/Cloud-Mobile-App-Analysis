from reportlab.pdfgen import canvas
from reportlab.platypus import (SimpleDocTemplate, Paragraph, PageBreak, CondPageBreak, Image, Spacer, Table, TableStyle)
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.pagesizes import LETTER, A4
from reportlab.graphics.shapes import Line, LineShape, Drawing
from reportlab.lib.colors import Color
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from io import BytesIO
import json
import os
from copy import deepcopy
import i18n
from xml.sax.saxutils import escape as _xml_escape

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_DIR = os.path.join(BASE_DIR, 'font')
TRANSLATIONS_DIR = os.path.join(BASE_DIR, 'translations')

i18n.set('fallback', 'en')
i18n.set('file_format', 'json')
if TRANSLATIONS_DIR not in i18n.load_path:
    i18n.load_path.append(TRANSLATIONS_DIR)

class PDFPSReporte:

    def __init__(self, path, lang, system, rules, result):
        self.system = system
        self.rules = rules
        self.lang = lang
        self.appInfo = deepcopy(result)
        self.urlList = self.appInfo.pop('url_list', [])
        self.masterReport = self.appInfo.pop('mast_report', {})
        self.appInfo.pop('execution', None)
        self.startupChecks = self.appInfo.pop('startupChecks', {})
        self.appInfo.pop('evaluationSummary', None)
        self.appInfo.pop('dynamicEvaluationSummary', None)
        self.vulnerabilities = self.appInfo.pop('vulnerabilities', [])
        self.summary = self.appInfo.pop('summary', {})

        i18n.set('locale', lang)

        self.elements = []

        # colors - Azul turkeza 367AB3
        self.colorOhkaGreen0 = Color((45.0/255), (166.0/255), (153.0/255), 1)
        self.colorOhkaGreen1 = Color((182.0/255), (227.0/255), (166.0/255), 1)
        self.colorOhkaGreen2 = Color((140.0/255), (222.0/255), (192.0/255), 1)
        #self.colorOhkaGreen2 = Color((140.0/255), (222.0/255), (192.0/255), 1)
        self.colorOhkaBlue0 = Color((54.0/255), (122.0/255), (179.0/255), 1)
        self.colorOhkaBlue1 = Color((122.0/255), (180.0/255), (225.0/255), 1)
        self.colorOhkaGreenLineas = Color((50.0/255), (140.0/255), (140.0/255), 1)

        self.styleSheet = getSampleStyleSheet()
        self.stylePDFTitle = ParagraphStyle('stylePDFTitle', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=24, alignment=TA_CENTER, borderWidth=3, textColor=self.colorOhkaGreen0)
        self.styleTableHeader = ParagraphStyle('styleTableHeader', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=12, alignment=TA_LEFT, borderWidth=3, textColor=self.colorOhkaBlue0)
        self.styleCellLeft = ParagraphStyle('styleCellLeft', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=10, alignment=TA_LEFT)
        self.styleCellCenter = ParagraphStyle('styleCellCenter', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=10, alignment=TA_CENTER)
        self.styleCellRight = ParagraphStyle('styleCellRight', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=10, alignment=TA_RIGHT)
        
        try:
            pdfmetrics.registerFont(TTFont('SourceHanSansTC', os.path.join(FONT_DIR, 'SourceHanSansTC-Regular.ttf')))
            pdfmetrics.registerFont(TTFont('SourceHanSansTC-Bold', os.path.join(FONT_DIR, 'SourceHanSansTC-Bold.ttf')))
            pdfmetrics.registerFontFamily('SourceHanSansTC', normal='SourceHanSansTC', bold='SourceHanSansTC-Bold')
        except Exception:
            pass  # Already registered

        self.Header()
        self.AppInfo()
        self.StartupChecks()
        self.VulnerabilitiesReport()
        self.MasterReport()
        self.URLList()

        # Build

        # self.styleSheet
        self.doc = SimpleDocTemplate(path, pagesize=A4)
        self.doc.build(self.elements)

    def Header(self):
        text = i18n.t('label.audit_report', system = self.system)
        paragraphReportHeader = Paragraph(text, self.stylePDFTitle)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 20)
        self.elements.append(spacer)

        d = Drawing(500, 1)
        line = Line(-15, 0, 483, 0)
        line.strokeColor = self.colorOhkaGreenLineas
        line.strokeWidth = 2
        d.add(line)
        self.elements.append(d)

        spacer = Spacer(10, 1)
        self.elements.append(spacer)

        d = Drawing(500, 1)
        line = Line(-15, 0, 483, 0)
        line.strokeColor = self.colorOhkaGreenLineas
        line.strokeWidth = 0.5
        d.add(line)
        self.elements.append(d)

        spacer = Spacer(10, 10)
        self.elements.append(spacer)
    
    def StartupChecks(self):
        if not isinstance(self.startupChecks, dict) or not self.startupChecks:
            return
        chinese = self.lang.lower().startswith('zh')
        title = '前置檢查' if chinese else 'Pre-checks'
        self.elements.append(Paragraph(title, self.styleTableHeader))
        self.elements.append(Spacer(1, 15))
        labels = {
            'PASSED': ('通過', 'Passed', '#23824e'),
            'FAILED': ('未通過', 'Not passed', '#ad3030'),
            'NOT_EVALUATED': ('未評估', 'Not evaluated', '#666666'),
            'ERROR': ('檢測錯誤', 'Assessment error', '#ad6c00'),
        }
        for key, check in self.startupChecks.items():
            if not isinstance(check, dict):
                continue
            status = labels.get(check.get('status'), labels['ERROR'])
            label = status[0] if chinese else status[1]
            # Older startupChecks have no ruleId; Root still uses its existing rule metadata.
            rule_id = check.get('ruleId') or ('AD-Lab029' if key == 'rootDetection' else None)
            rule = self.rules.get(rule_id, {})
            title = check.get('title') or rule.get('title') or key
            result_cell = '<b>{}</b>'.format(_esc(title))

            mas = check.get('mas') or rule.get('mas', '')
            if mas:
                result_cell += '<br/><br/><b>{}</b><br/>'.format(i18n.t('label.mas_title'))
                for mas_id in mas.split('|'):
                    mas_title = i18n.t('mas.%s' % mas_id)
                    if mas_title and mas_title != ('mas.%s' % mas_id):
                        result_cell += '{} - {}<br/>'.format(_esc(mas_id), _esc(mas_title))
                    else:
                        result_cell += '{}<br/>'.format(_esc(mas_id))

            masvs = check.get('owasp_masvs') or rule.get('owasp_masvs', '') or rule.get('real_mstg', '')
            if masvs:
                result_cell += '<br/><br/><b>OWASP MASVS: </b><br/>{}'.format(
                    '<br/>'.join(_esc(item) for item in masvs.split('|')))

            owasp_mobile = check.get('owasp_mobile') or rule.get('owasp_mobile', '')
            if owasp_mobile:
                result_cell += '<br/><br/><b>{}</b><br/>{}'.format(
                    i18n.t('label.owasp_mobile_title'),
                    '<br/>'.join(_esc(item) for item in owasp_mobile.split('|')))

            description = check.get('description') or rule.get('desc', '')
            if description:
                result_cell += '<br/><br/><b>{}</b><br/>{}'.format(
                    i18n.t('label.description_title'), _esc(description[:1200]))

            if check.get('summary'):
                result_cell += '<br/><br/><b>{}</b><br/>{}'.format(
                    i18n.t('label.detail_info_title'), _esc(check['summary']))

            rows = [
                [Paragraph('<b>{}</b>'.format(i18n.t('label.table_result_title')), self.styleCellCenter),
                 Paragraph('<b>{}</b>'.format(i18n.t('label.table_rule_title')), self.styleCellLeft)],
                [Paragraph('<font color="{}">{}</font>'.format(status[2], label), self.styleCellCenter),
                 Paragraph(result_cell, self.styleCellLeft)],
            ]
            table = Table(rows, colWidths=[90, 400])
            table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('VALIGN', (0, 1), (0, 1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 0.5, self.colorOhkaGreenLineas),
                ('LINEABOVE', (0, 1), (-1, 1), 0.5, self.colorOhkaGreenLineas),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            self.elements.append(table)
            self.elements.append(Spacer(1, 15))

    def AppInfo(self):
        text = i18n.t('label.app_information')
        paragraphReportHeader = Paragraph(text, self.styleTableHeader)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 15)
        self.elements.append(spacer)
        """
        Create the line items
        """
        
        tStyle = TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ("ALIGN", (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'SourceHanSansTC'),
            ('LINEBELOW', (0, 0), (-1, -1), 1, self.colorOhkaBlue1)
         ])

        tableData = []
        for key in list(self.appInfo.keys()):
            val = self.appInfo[key]
            if isinstance(val, (dict, list)):
                continue
            tableData.append([
                Paragraph(f"<b>{_esc(i18n.t('label.' + key.lower()))}</b>", self.styleCellLeft),
                Paragraph(_esc(str(val)), self.styleCellLeft)
            ])

        if tableData:
            table = Table(tableData, colWidths=[120, 380])
            table.setStyle(tStyle)
            self.elements.append(table)
            self.elements.append(Spacer(10, 20))

    def VulnerabilitiesReport(self):
        if not self.vulnerabilities:
            return
        chinese = self.lang.lower().startswith('zh')
        title = '弱點掃描清單' if chinese else 'Vulnerability Assessment Findings'
        self.elements.append(Paragraph(title, self.styleTableHeader))
        self.elements.append(Spacer(1, 15))

        for v in self.vulnerabilities:
            if not isinstance(v, dict):
                continue
            title_text = v.get('title', 'Unknown Finding')
            sev = str(v.get('severity', 'low')).upper()
            color = '#ad3030' if sev in ('HIGH', 'CRITICAL') else ('#ad6c00' if sev == 'MEDIUM' else '#23824e')
            cwe = v.get('cwe', '')
            owasp = v.get('owasp', '')
            desc = v.get('description', '')

            desc_cell = f"<b>{_esc(title_text)}</b>"
            if cwe or owasp:
                desc_cell += f"<br/><font color='#666666'><b>CWE:</b> {_esc(cwe)} | <b>OWASP:</b> {_esc(owasp)}</font>"
            if desc:
                desc_cell += f"<br/><br/>{_esc(desc)}"

            rows = [
                [Paragraph('<b>Severity</b>', self.styleCellCenter), Paragraph('<b>Vulnerability Details</b>', self.styleCellLeft)],
                [Paragraph(f'<font color="{color}"><b>{sev}</b></font>', self.styleCellCenter), Paragraph(desc_cell, self.styleCellLeft)]
            ]
            table = Table(rows, colWidths=[90, 400])
            table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('VALIGN', (0, 1), (0, 1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 0.5, self.colorOhkaGreenLineas),
                ('LINEABOVE', (0, 1), (-1, 1), 0.5, self.colorOhkaGreenLineas),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            self.elements.append(table)
            self.elements.append(Spacer(1, 12))
        

    def MasterReport(self):
        if not self.masterReport:
            return
        separate_root = isinstance(self.startupChecks, dict) and 'rootDetection' in self.startupChecks
        if separate_root:
            self.elements.append(CondPageBreak(240))
        text = ('動態檢測' if self.lang.lower().startswith('zh') else 'Dynamic checks') if separate_root else i18n.t('label.scan_report')
        paragraphReportHeader = Paragraph(text, self.styleTableHeader)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 15)
        self.elements.append(spacer)
        """
        Create the line items
        """
        
        d = []
        textData = [i18n.t('label.table_result_title'), i18n.t('label.table_rule_title')]

        alignStyle = [self.styleCellCenter,
                      self.styleCellLeft,
                      self.styleCellLeft]
        
        fontSize = 12
        # centered = ParagraphStyle(name="centered", alignment=TA_CENTER)
        for (index, text) in enumerate(textData):
            ptext = "<b>%s</b>" % (text)
            titlesTable = Paragraph(ptext, alignStyle[index])
            d.append(titlesTable)
        
        data = [d]
        formattedLineData = []

        summary = {state: 0 for state in ('DETECTED', 'NOT_DETECTED', 'NOT_EVALUATED', 'ERROR')}
        for key, item in self.masterReport.items():
            if key in self.rules:
                summary[_evaluation_status(item)] += 1
        if separate_root and 'AD-Lab029' not in self.masterReport and 'rootDetection' in self.startupChecks:
            root_st = self.startupChecks['rootDetection'].get('status', 'NOT_EVALUATED')
            if root_st == 'PASSED':
                summary['NOT_DETECTED'] += 1
            elif root_st == 'FAILED':
                summary['DETECTED'] += 1
            elif root_st == 'NOT_EVALUATED':
                summary['NOT_EVALUATED'] += 1
            else:
                summary['ERROR'] += 1
        self.elements.append(Paragraph('Passed: {} | Detected: {} | Not evaluated: {} | Error: {}'.format(
            summary['NOT_DETECTED'], summary['DETECTED'], summary['NOT_EVALUATED'], summary['ERROR']), self.styleCellLeft))
        order = sorted(self.rules.keys())
        for rule in order:
            content = self.rules[rule]

            if rule == 'AD-Lab029' and separate_root and rule not in self.masterReport:
                root_check = self.startupChecks.get('rootDetection', {})
                root_status = root_check.get('status', 'NOT_EVALUATED')
                if root_status == 'PASSED':
                    lab_id_cell = f"<font color='green'>{i18n.t('label.rule_passed')}</font>"
                elif root_status == 'FAILED':
                    lab_id_cell = f"<font color='red'>{i18n.t('label.rule_detected')}</font>"
                elif root_status == 'NOT_EVALUATED':
                    lab_id_cell = f"<font color='gray'>{i18n.t('label.not_evaluated')}</font>"
                else:
                    lab_id_cell = "<font color='orange'>ERROR</font>"

                result_cell = "<b>{rule_id} - {rule_title}</b>".format(
                    rule_id = _esc(rule),
                    rule_title = _esc(content.get('title', ''))
                )
                if content.get('mas'):
                    result_cell += f"<br/><br/><b>{i18n.t('label.mas_title')}</b><br/>"
                    for mas_id in content['mas'].split('|'):
                        mas_title = i18n.t('mas.%s' % mas_id)
                        if mas_title and mas_title != ('mas.%s' % mas_id):
                            result_cell += f"{mas_id} - {mas_title}<br/>"
                        else:
                            result_cell += f"{mas_id}<br/>"

                mstg_val = content.get('real_mstg') or content.get('owasp_masvs', '')
                if mstg_val:
                    result_cell += f"<br/><br/><b>OWASP MASVS: </b><br/>"
                    result_cell += "<br/> ".join(_esc(item) for item in mstg_val.split('|'))

                if content.get('owasp_mobile'):
                    result_cell += f"<br/><br/><b>{i18n.t('label.owasp_mobile_title')}</b><br/>"
                    result_cell += "<br/> ".join(_esc(item) for item in content['owasp_mobile'].split('|'))

                if content.get('desc'):
                    result_cell += "<br/><br/><b>{description_title}</b><br/>{desc}".format(
                        description_title = i18n.t('label.description_title'),
                        desc = _esc(content.get('desc', '')[:1200])
                    )

                notice = "（已於前置檢查章節完成獨立評估，詳請參閱首頁前置檢查報告）" if self.lang.lower().startswith('zh') else "(Evaluated in Pre-checks section, see cover page)"
                result_cell += f"<br/><br/><b>{i18n.t('label.detail_info_title')}</b><br/>· <font color='#666666'><i>{notice}</i></font><br/>"

                data.append([
                    Paragraph(lab_id_cell, self.styleCellCenter),
                    Paragraph(result_cell, self.styleCellLeft)
                ])
                continue

            if (rule not in self.masterReport):
                # mas_report 裡面不含這個 lab_id，將跳過這個規則
                continue

            # print("   rule =>", rule)
            # print("content =>", content)
            
            lineData = [rule]
            lineData.append(content['title'])
            mstg_val = content.get('real_mstg') or content.get('owasp_masvs', '')
            lineData.append(mstg_val)

            # lab_id_cell
            lab_id_cell = "{label_passed}".format(
                label_passed = i18n.t('label.rule_passed')
            )

            evaluation = _evaluation_status(self.masterReport[rule])
            if evaluation == 'NOT_EVALUATED':
                label = i18n.t('label.not_evaluated')
                lab_id_cell = "<font color='gray'>{}</font>".format(label)
            elif evaluation == 'ERROR':
                lab_id_cell = "<font color='orange'>ERROR</font>"
            elif evaluation == 'DETECTED':
                lab_id_cell = "<font color='red'>{label_detected}</font>".format(
                    label_detected = i18n.t('label.rule_detected')
                )

            result_cell = "<b>{rule_id} - {rule_title}</b>".format(
                rule_id = _esc(rule),
                rule_title = _esc(content.get('title', ''))
            )

            if (content['mas']):
                result_cell += """
                <br/><br/>
                <b>{mas_title}</b><br/>
                """.format(
                    mas_title = i18n.t('label.mas_title')
                )

                for mas_id in content['mas'].split('|'):
                    mas_title = i18n.t('mas.%s' % mas_id)
                    if mas_title and mas_title != ('mas.%s' % mas_id):
                        result_cell += "{mas_id} - {mas_title}<br/>".format(mas_id=mas_id, mas_title=mas_title)
                    else:
                        result_cell += "{mas_id}<br/>".format(mas_id=mas_id)

            if mstg_val:
                result_cell += """
                <br/><br/>
                <b>OWASP MASVS: </b><br/>
                {mstg_result}
                """.format(
                    mstg_result = "<br/> ".join(mstg_val.split('|'))
                )

            if (content['owasp_mobile']):
                result_cell += """
                <br/><br/>
                <b>{owasp_mobile_title}</b><br/>
                {owasp_mobile}
                """.format(
                    owasp_mobile_title = i18n.t('label.owasp_mobile_title'),
                    owasp_mobile = "<br/> ".join(content['owasp_mobile'].split('|'))
                )

            if (content['desc']):
                result_cell += """
                <br/><br/>
                <b>{description_title}</b><br/>
                    {desc}
                """.format(
                    description_title = i18n.t('label.description_title'),
                        desc = _esc(content.get('desc', '')[:1200])
                )

            try:
                temp_result = ""
                # 避免空的 data: []
                if (self.masterReport[rule].get('data')):
                    temp_result += """
                    <br/><br/>
                    <b>{description_title}</b><br/>
                    """.format(
                        description_title = i18n.t('label.detail_info_title')
                    )
                    
                    # 暫時先限字數，似乎套件跨頁會故障
                    for detail_item in self.masterReport[rule]['data'][:1]:
                        try:
                            # 靜態分析的 data[i]["description"] 是整段 lab 說明
                            # (maldroid_main.py 會把 rule[lab]["desc"] 指派成 data[0]["description"]),
                            # 直接印會讓同一段敘述在 Description 與 Detail 各出現一次。
                            # 動態分析的 description 則是每筆發現的個別說明，必須保留。
                            # 兩者用「是否與 rule 的 desc 完全相同」區分。
                            _item_desc = detail_item.get('description', '')
                            if _item_desc and _item_desc != content.get('desc', ''):
                                temp_result += """· {details}<br/>{description}<br/><br/>""".format(
                                        details = _esc(detail_item.get('details', '')[:800]),
                                        description = _esc(_item_desc[:800]),
                                )
                            else:
                                temp_result += """· {details}<br/><br/>""".format(
                                        details = _esc(detail_item.get('details', '')[:800]),
                                )
                        except:
                            print("data structure does not include 'details' or 'description' key")
                result_cell += temp_result
            except:
                print("lab report does not contain 'data' or no matched rule with", rule)

            formattedLineData = [
                Paragraph(lab_id_cell, self.styleCellCenter),
                Paragraph(result_cell, self.styleCellLeft),
            ]

            data.append(formattedLineData)
            formattedLineData = []
        
        table = Table(data, colWidths=[90, 400])
        tStyle = TableStyle([ 
                ('VALIGN',(0, 0),(-1, -1), 'MIDDLE'),
                ('BOX',(0, 0), (-1, -1), 1, self.colorOhkaGreenLineas),
                ('LINEABOVE', (0, 0), (-1, -1), 1, self.colorOhkaGreenLineas)
        ])
        table.setStyle(tStyle)
        self.elements.append(table)

        spacer = Spacer(10, 50)
        self.elements.append(spacer)
        

    def URLList(self):
        text = i18n.t('label.url_list')
        paragraphReportHeader = Paragraph(text, self.styleTableHeader)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 15)
        self.elements.append(spacer)
        """
        Create the line items
        """

        tStyle = TableStyle([
                ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                ('BOX',(0, 0), (-1, -1), 1, self.colorOhkaBlue1),
                ('LINEABOVE', (0, 0), (-1, -1), 1, self.colorOhkaBlue1)
            ])

        table_data = []

        if (self.urlList):
            for url in self.urlList:
                table_data.append([Paragraph(_esc(url), self.styleCellLeft)])
        else:
            table_data.append([Paragraph(i18n.t('label.empty_url_list_hint'), self.styleCellLeft)])

        table = Table(table_data, colWidths=[490])
        tStyle = TableStyle([ 
                ('VALIGN',(0, 0),(-1, -1), 'MIDDLE'),
                ('BOX',(0, 0), (-1, -1), 1, self.colorOhkaGreenLineas),
                ('LINEABOVE', (0, 0), (-1, -1), 1, self.colorOhkaGreenLineas)
        ])
        table.setStyle(tStyle)
        self.elements.append(table)


def _evaluation_status(item):
    status = item.get('evaluationStatus')
    if status in ('DETECTED', 'NOT_DETECTED', 'NOT_EVALUATED', 'ERROR'):
        return status
    if 'evaluationStatus' in item:
        return 'ERROR'
    # Older reports have no evaluationStatus; null must never become Passed.
    if item.get('isDetected') is True:
        return 'DETECTED'
    if item.get('isDetected') is False:
        return 'NOT_DETECTED'
    return 'NOT_EVALUATED'


def _esc(text):
    # ReportLab's Paragraph supports a limited HTML-like syntax.
    # Dynamic analysis findings may contain attacker-controlled strings (e.g. fuzz payloads)
    # that must be escaped to avoid breaking PDF generation.
    return _xml_escape(str(text), {'"': '&quot;', "'": '&#39;'})
        
def Product_PDF(rawdata):
    if isinstance(rawdata, dict) and 'result' in rawdata:
        lang = rawdata.get('lang', 'en')
        system = rawdata.get('system', 'android')
        rule = rawdata.get('rule', {})
        result = rawdata['result']
    else:
        lang = 'en'
        system = 'android'
        rule = {}
        result = rawdata

    buffer = BytesIO()
    PDFPSReporte(buffer, lang, system, rule, result)
    pdf = buffer.getvalue()
    return pdf
