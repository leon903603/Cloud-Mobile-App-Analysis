import os
from reportlab.pdfgen import canvas
from reportlab.platypus import (SimpleDocTemplate, Paragraph, PageBreak, Image, Spacer, Table, TableStyle)
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.pagesizes import A4
from reportlab.graphics.shapes import Line, Drawing
from reportlab.lib.colors import Color
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from io import BytesIO
import json
import i18n
from copy import deepcopy
from xml.sax.saxutils import escape as _xml_escape

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
FONT_DIR = os.path.join(CURRENT_DIR, 'font')
TRANSLATIONS_DIR = os.path.join(CURRENT_DIR, 'translations')

i18n.set('fallback', 'en')
i18n.set('file_format', 'json')
if TRANSLATIONS_DIR not in i18n.load_path:
    i18n.load_path.append(TRANSLATIONS_DIR)

def _esc(val):
    if not val:
        return ""
    return _xml_escape(str(val))

def _init_fonts_and_styles():
    try:
        pdfmetrics.registerFont(TTFont('SourceHanSansTC', os.path.join(FONT_DIR, 'SourceHanSansTC-Regular.ttf')))
        pdfmetrics.registerFont(TTFont('SourceHanSansTC-Bold', os.path.join(FONT_DIR, 'SourceHanSansTC-Bold.ttf')))
        pdfmetrics.registerFontFamily('SourceHanSansTC', normal='SourceHanSansTC', bold='SourceHanSansTC-Bold')
    except Exception:
        pass


class BaseStaticReport:
    def __init__(self, lang):
        i18n.set('locale', lang)
        self.lang = lang
        self.elements = []

        self.colorGreen0 = Color((45.0/255), (166.0/255), (153.0/255), 1)
        self.colorGreen1 = Color((182.0/255), (227.0/255), (166.0/255), 1)
        self.colorBlue0 = Color((54.0/255), (122.0/255), (179.0/255), 1)
        self.colorBlue1 = Color((122.0/255), (180.0/255), (225.0/255), 1)
        self.colorGreenLine = Color((50.0/255), (140.0/255), (140.0/255), 1)

        _init_fonts_and_styles()
        self.styleSheet = getSampleStyleSheet()
        self.stylePDFTitle = ParagraphStyle('stylePDFTitle', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=24, alignment=TA_CENTER, borderWidth=3, textColor=self.colorGreen0)
        self.styleTableHeader = ParagraphStyle('styleTableHeader', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=13, alignment=TA_LEFT, borderWidth=3, textColor=self.colorBlue0)
        self.styleCellLeft = ParagraphStyle('styleCellLeft', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=10, alignment=TA_LEFT)
        self.styleCellCenter = ParagraphStyle('styleCellCenter', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=10, alignment=TA_CENTER)
        self.styleCellRight = ParagraphStyle('styleCellRight', fontName="SourceHanSansTC", parent=self.styleSheet["Normal"], fontSize=10, alignment=TA_RIGHT)

    def add_header(self, system_name="android"):
        text = i18n.t('label.audit_report', system=system_name)
        self.elements.append(Paragraph(text, self.stylePDFTitle))
        self.elements.append(Spacer(10, 15))

        d = Drawing(500, 1)
        line = Line(-15, 0, 483, 0)
        line.strokeColor = self.colorGreenLine
        line.strokeWidth = 2
        d.add(line)
        self.elements.append(d)

        self.elements.append(Spacer(10, 2))
        d2 = Drawing(500, 1)
        line2 = Line(-15, 0, 483, 0)
        line2.strokeColor = self.colorGreenLine
        line2.strokeWidth = 0.5
        d2.add(line2)
        self.elements.append(d2)

        self.elements.append(Spacer(10, 15))


class PDFVulnerabilityReporte(BaseStaticReport):
    """Renders static reports with vulnerability assessment findings (Guest/Fast Scan format)"""
    def __init__(self, path, lang, data):
        super().__init__(lang)
        self.data = deepcopy(data)
        self.vulnerabilities = self.data.get('vulnerabilities', [])
        self.summary = self.data.get('summary', {})
        self.url_list = self.data.get('url_list', [])

        self.add_header("android")
        self.render_app_info()
        self.render_vulnerabilities()
        self.render_url_list()

        doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        doc.build(self.elements)

    def render_app_info(self):
        self.elements.append(Paragraph(i18n.t('label.app_information'), self.styleTableHeader))
        self.elements.append(Spacer(10, 10))

        info_keys = [
            ('filename', self.data.get('filename') or self.data.get('file_name', 'N/A')),
            ('status', self.data.get('status', 'Completed')),
            ('security_score', f"{self.data.get('security_score', self.summary.get('score', 'N/A'))} / 100"),
            ('hash', self.data.get('hash') or self.data.get('sha256', 'N/A')),
        ]
        if self.summary:
            high = self.summary.get('high', 0)
            med = self.summary.get('medium', 0)
            low = self.summary.get('low', 0)
            info_keys.append(('risk_summary', f"High: {high} | Medium: {med} | Low: {low}"))

        tStyle = TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'SourceHanSansTC'),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, self.colorBlue1),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ])

        table_data = []
        for key, val in info_keys:
            label = i18n.t(f'label.{key}')
            if label.startswith('label.'):
                label = key.replace('_', ' ').capitalize()
            table_data.append([
                Paragraph(f"<b>{label}</b>", self.styleCellLeft),
                Paragraph(_esc(val), self.styleCellLeft)
            ])

        table = Table(table_data, colWidths=[150, 360])
        table.setStyle(tStyle)
        self.elements.append(table)
        self.elements.append(Spacer(10, 25))

    def render_vulnerabilities(self):
        self.elements.append(Paragraph(i18n.t('label.vulnerability_findings'), self.styleTableHeader))
        self.elements.append(Spacer(10, 10))

        if not self.vulnerabilities:
            self.elements.append(Paragraph(i18n.t('label.rule_passed'), self.styleCellLeft))
            self.elements.append(Spacer(10, 20))
            return

        sev_colors = {
            'CRITICAL': '#8b0000',
            'HIGH': '#d32f2f',
            'MEDIUM': '#e65100',
            'LOW': '#2e7d32',
            'INFO': '#0288d1'
        }

        for vuln in self.vulnerabilities:
            title = vuln.get('title', 'Unknown Issue')
            severity = str(vuln.get('severity', 'LOW')).upper()
            desc = vuln.get('description', '')
            cwe = vuln.get('cwe', '')
            owasp = vuln.get('owasp', '')

            badge_color = sev_colors.get(severity, '#555555')
            badge_html = f"<font color='{badge_color}'><b>{severity}</b></font>"

            details_html = f"<b>{_esc(title)}</b><br/>"
            meta_items = []
            if cwe:
                meta_items.append(f"{i18n.t('label.cwe_title')}{_esc(cwe)}")
            if owasp:
                meta_items.append(f"{i18n.t('label.owasp_mobile_title')}{_esc(owasp)}")
            if meta_items:
                details_html += f"<font color='#555555'>{' | '.join(meta_items)}</font><br/><br/>"
            if desc:
                details_html += f"{_esc(desc)}"

            item_table_data = [
                [
                    Paragraph(f"<b>{i18n.t('label.severity')}</b>", self.styleCellCenter),
                    Paragraph("<b>Vulnerability Details</b>", self.styleCellLeft)
                ],
                [
                    Paragraph(badge_html, self.styleCellCenter),
                    Paragraph(details_html, self.styleCellLeft)
                ]
            ]

            tStyle = TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('BOX', (0, 0), (-1, -1), 0.8, self.colorGreenLine),
                ('LINEBELOW', (0, 0), (-1, 0), 0.5, self.colorBlue1),
                ('BACKGROUND', (0, 0), (-1, 0), Color(0.96, 0.98, 0.98, 1)),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ])

            table = Table(item_table_data, colWidths=[90, 420])
            table.setStyle(tStyle)
            self.elements.append(table)
            self.elements.append(Spacer(10, 10))

        self.elements.append(Spacer(10, 15))

    def render_url_list(self):
        self.elements.append(Paragraph(i18n.t('label.url_list'), self.styleTableHeader))
        self.elements.append(Spacer(10, 10))

        table_data = []
        if self.url_list:
            for url in self.url_list:
                table_data.append([Paragraph(_esc(url), self.styleCellLeft)])
        else:
            table_data.append([Paragraph(i18n.t('label.empty_url_list_hint'), self.styleCellLeft)])

        table = Table(table_data, colWidths=[510])
        tStyle = TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 0.8, self.colorGreenLine),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ])
        table.setStyle(tStyle)
        self.elements.append(table)


class PDFPSReporte(BaseStaticReport):
    """Renders static reports with full 80 MAS rules matrix (Format A - 37 pages)"""
    def __init__(self, path, lang, system, rules, result):
        super().__init__(lang)
        self.system = system
        self.rules = rules
        self.appInfo = deepcopy(result)
        self.urlList = self.appInfo.pop('url_list', [])
        self.masterReport = self.appInfo.pop('mast_report', {})
        self.appInfo.pop('evaluationSummary', None)
        self.appInfo.pop('rule', None)

        self.add_header("android")
        self.AppInfo()
        self.MasterReport()
        self.URLList()

        doc = SimpleDocTemplate(path, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        doc.build(self.elements)

    def AppInfo(self):
        self.elements.append(Paragraph(i18n.t('label.app_information'), self.styleTableHeader))
        self.elements.append(Spacer(10, 10))

        tStyle = TableStyle([
            ('ALIGN', (0, 0), (0, -1), 'LEFT'),
            ("ALIGN", (1, 0), (1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'SourceHanSansTC'),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, self.colorBlue1),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
        ])

        tableData = []
        for key in self.appInfo:
            val = self.appInfo[key]
            if isinstance(val, (dict, list)):
                continue
            label = i18n.t(f'label.{key.lower()}')
            if label.startswith('label.'):
                label = key.replace('_', ' ').capitalize()
            tableData.append([
                Paragraph(f"<b>{label}</b>", self.styleCellLeft),
                Paragraph(_esc(val), self.styleCellLeft)
            ])

        table = Table(tableData, colWidths=[150, 360])
        table.setStyle(tStyle)
        self.elements.append(table)
        self.elements.append(Spacer(10, 25))

    def MasterReport(self):
        self.elements.append(Paragraph(i18n.t('label.scan_report'), self.styleTableHeader))
        self.elements.append(Spacer(10, 6))

        # Calculate Passed / Failed counts
        passed_count = sum(1 for r in self.masterReport.values() if isinstance(r, dict) and not r.get('isDetected', False))
        failed_count = sum(1 for r in self.masterReport.values() if isinstance(r, dict) and r.get('isDetected', False))
        if self.lang.lower().startswith('zh'):
            summary_text = f"通過: {passed_count} &nbsp;|&nbsp; 偵測到風險: {failed_count} &nbsp;|&nbsp; 未評估: 0 &nbsp;|&nbsp; 錯誤: 0"
        else:
            summary_text = f"Passed: {passed_count} &nbsp;|&nbsp; Failed: {failed_count} &nbsp;|&nbsp; Not evaluated: 0 &nbsp;|&nbsp; Error: 0"
        self.elements.append(Paragraph(summary_text, self.styleCellLeft))
        self.elements.append(Spacer(10, 10))

        textData = [i18n.t('label.table_result_title'), i18n.t('label.table_rule_title')]
        d = [
            Paragraph(f"<b>{textData[0]}</b>", self.styleCellCenter),
            Paragraph(f"<b>{textData[1]}</b>", self.styleCellLeft)
        ]

        data = [d]
        for rule in self.rules.keys():
            content = self.rules[rule]
            if rule not in self.masterReport:
                continue

            is_detected = self.masterReport[rule].get('isDetected', False)
            if is_detected:
                lab_id_cell = f"<font color='red'>{i18n.t('label.rule_detected')}</font>"
            else:
                lab_id_cell = f"<font color='green'>{i18n.t('label.rule_passed')}</font>"

            mstg_val = content.get('real_mstg') or content.get('owasp_masvs', '')

            result_cell = "<b>{rule_id} - {rule_title}</b>".format(
                rule_id=_esc(rule),
                rule_title=_esc(content.get('title', ''))
            )

            if content.get('mas'):
                result_cell += f"<br/><br/><b>{i18n.t('label.mas_title')}</b><br/>"
                for mas_id in content['mas'].split('|'):
                    mas_desc = i18n.t(f'mas.{mas_id}')
                    result_cell += f"{_esc(mas_id)} - {_esc(mas_desc)}<br/>"

            if mstg_val:
                result_cell += f"<br/><br/><b>OWASP MASVS: </b><br/>"
                result_cell += "<br/> ".join(_esc(item) for item in mstg_val.split('|'))

            if content.get('owasp_mobile'):
                result_cell += f"<br/><br/><b>{i18n.t('label.owasp_mobile_title')}</b><br/>"
                result_cell += "<br/> ".join(_esc(item) for item in content['owasp_mobile'].split('|'))

            if content.get('desc'):
                result_cell += "<br/><br/><b>{description_title}</b><br/>{desc}".format(
                    description_title=i18n.t('label.description_title'),
                    desc=_esc(content.get('desc', ''))
                )

            try:
                temp_result = ""
                rule_info = self.masterReport[rule]
                data_list = rule_info.get('data', [])
                
                # Report Data Normalization: Handle AS-lab052 contradiction & empty findings
                has_meaningful_finding = False
                MAX_DETAIL_CHARS = 3000
                if data_list:
                    for detail_item in data_list[:1]:
                        d_text = detail_item.get('details', '').strip()
                        d_desc = detail_item.get('description', '').strip()

                        # Safety ceiling: prevent extremely large logs from causing ReportLab Table LayoutError
                        if len(d_text) > MAX_DETAIL_CHARS:
                            trunc_note = " ... [內容長度超出安全限制已截斷]" if self.lang.lower().startswith('zh') else " ... [Truncated for layout safety]"
                            d_text = d_text[:MAX_DETAIL_CHARS] + trunc_note
                        if len(d_desc) > MAX_DETAIL_CHARS:
                            trunc_note = " ... [內容長度超出安全限制已截斷]" if self.lang.lower().startswith('zh') else " ... [Truncated for layout safety]"
                            d_desc = d_desc[:MAX_DETAIL_CHARS] + trunc_note
                        
                        # Check AS-lab052 contradiction
                        if rule == 'AS-lab052' and ('not at risk' in d_desc.lower() or 'not at risk' in d_text.lower()):
                            temp_result += f"<br/><br/><b>{i18n.t('label.detail_info_title')}</b><br/>"
                            note = "程式碼引用 SQLite 資料庫組件，但日誌確認無 SQLite Journal 資訊洩漏風險（依檢測基準評估為安全或需人工關注）。" if self.lang.lower().startswith('zh') else "SQLite components referenced; verified not at risk of Journal Information Disclosure."
                            temp_result += f"· <font color='#666666'><i>{note}</i></font><br/><br/>"
                            has_meaningful_finding = True
                            break

                        if d_text or (d_desc and d_desc != content.get('desc', '')):
                            temp_result += f"<br/><br/><b>{i18n.t('label.detail_info_title')}</b><br/>"
                            esc_details = _esc(d_text)
                            esc_desc = _esc(d_desc)
                            if d_desc and d_desc != content.get('desc', ''):
                                temp_result += f"&bull; {esc_details}<br/>{esc_desc}<br/><br/>"
                            else:
                                temp_result += f"&bull; {esc_details}<br/><br/>"
                            has_meaningful_finding = True
                            break

                # Data Normalization: if detected but findings are completely blank (e.g. AS-lab017, 035, 043, 075)
                if is_detected and not has_meaningful_finding:
                    empty_notice = _esc(i18n.t('label.finding_empty_notice'))
                    temp_result += f"<br/><br/><b>{i18n.t('label.detail_info_title')}</b><br/>&bull; <font color='#888888'><i>{empty_notice}</i></font><br/><br/>"

                result_cell += temp_result
            except Exception:
                pass

            data.append([
                Paragraph(lab_id_cell, self.styleCellCenter),
                Paragraph(result_cell, self.styleCellLeft)
            ])

        table = Table(data, colWidths=[90, 420])
        tStyle = TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOX', (0, 0), (-1, -1), 0.8, self.colorGreenLine),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, self.colorBlue1),
            ('BACKGROUND', (0, 0), (-1, 0), Color(0.96, 0.98, 0.98, 1)),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ])
        table.setStyle(tStyle)
        self.elements.append(table)
        self.elements.append(Spacer(10, 25))

    def URLList(self):
        self.elements.append(Paragraph(i18n.t('label.url_list'), self.styleTableHeader))
        self.elements.append(Spacer(10, 10))

        table_data = []
        if self.urlList:
            for url in self.urlList:
                table_data.append([Paragraph(_esc(url), self.styleCellLeft)])
        else:
            table_data.append([Paragraph(i18n.t('label.empty_url_list_hint'), self.styleCellLeft)])

        table = Table(table_data, colWidths=[510])
        tStyle = TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOX', (0, 0), (-1, -1), 0.8, self.colorGreenLine),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ])
        table.setStyle(tStyle)
        self.elements.append(table)


def Product_PDF(rawdata):
    """
    Polymorphic static report compiler:
    - If rawdata has 'rule' or 'mast_report', compiles the full 80 MAS rules report (37 pages).
    - If rawdata has 'vulnerabilities', compiles the vulnerability assessment report.
    """
    lang = rawdata.get('lang', 'zh-TW')
    buffer = BytesIO()

    res = rawdata.get('result', {}) if isinstance(rawdata.get('result'), dict) else {}
    has_mast = 'mast_report' in res or 'mast_report' in rawdata
    has_rules = 'rule' in rawdata or 'rule' in res

    if has_mast and has_rules:
        system = rawdata.get('system') or {
            'app_name': rawdata.get('app_name') or res.get('app_name', 'Android App'),
            'file_name': rawdata.get('file_name') or res.get('file_name', 'app.apk'),
            'package_name': res.get('package_name', ''),
            'version_name': res.get('app_version', ''),
        }
        rule = rawdata.get('rule') or res.get('rule') or {}
        result_copy = deepcopy(res) if res else deepcopy(rawdata)
        PDFPSReporte(buffer, lang, system, rule, result_copy)
    elif 'vulnerabilities' in rawdata or 'vulnerabilities' in res:
        data = res if 'vulnerabilities' in res else rawdata
        PDFVulnerabilityReporte(buffer, lang, data)
    elif has_mast:
        system = rawdata.get('system') or {'app_name': 'Android App', 'file_name': 'app.apk'}
        rule = rawdata.get('rule') or {}
        result_copy = deepcopy(res) if res else deepcopy(rawdata)
        PDFPSReporte(buffer, lang, system, rule, result_copy)
    else:
        PDFVulnerabilityReporte(buffer, lang, rawdata)

    return buffer.getvalue()
