from reportlab.pdfgen import canvas
from reportlab.platypus import (SimpleDocTemplate, Paragraph, PageBreak, Image, Spacer, Table, TableStyle)
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER, TA_JUSTIFY
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.pagesizes import LETTER, A4
from reportlab.graphics.shapes import Line, LineShape, Drawing
from reportlab.lib.colors import Color
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from io import BytesIO
import json
import i18n

i18n.set('fallback', 'en')
i18n.set('file_format', 'json')
i18n.load_path.append('./translations')

class PDFPSReporte:

    def __init__(self, path, lang, system, rules, result):
        self.system = system
        self.rules = rules
        self.urlList = result.pop('url_list')
        self.masterReport = result.pop('mast_report')
        self.appInfo = result

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
        
        pdfmetrics.registerFont(TTFont('SourceHanSansTC', './font/SourceHanSansTC-Regular.ttf'))
        pdfmetrics.registerFont(TTFont('SourceHanSansTC-Bold', './font/SourceHanSansTC-Bold.ttf'))

        pdfmetrics.registerFontFamily('SourceHanSansTC', normal='SourceHanSansTC', bold='SourceHanSansTC-Bold')

        self.Header()
        self.AppInfo()
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
        for key in self.appInfo:
            tableData.append([i18n.t('label.'+key.lower()), self.appInfo[key]])

        table = Table(tableData, colWidths=[120, 380])
        table.setStyle(tStyle)
        self.elements.append(table)

        spacer = Spacer(10, 50)
        self.elements.append(spacer)
        

    def MasterReport(self):
        text = i18n.t('label.scan_report')
        paragraphReportHeader = Paragraph(text, self.styleTableHeader)
        self.elements.append(paragraphReportHeader)

        spacer = Spacer(10, 15)
        self.elements.append(spacer)
        """
        Create the line items
        """
        
        d = []
        textData = ["Result", "Rule"]

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

        for rule in self.rules.keys():
            content = self.rules[rule]

            if (rule not in self.masterReport):
                # mas_report 裡面不含這個 lab_id，將跳過這個規則
                continue

            # print("   rule =>", rule)
            # print("content =>", content)
            
            lineData = [rule]
            lineData.append(content['title'])
            lineData.append(content['real_mstg'])

            # lab_id_cell
            lab_id_cell = "{label_passed}".format(
                label_passed = i18n.t('label.rule_passed')
            )

            if (self.masterReport[rule]['isDetected']):
                lab_id_cell = "<font color='red'>{label_failed}</font>".format(
                    label_failed = i18n.t('label.rule_failed')
                )

            result_cell = "<b>{rule_id} - {rule_title}</b>".format(
                rule_id = rule,
                rule_title = content['title']
            )

            if (content['mas']):
                result_cell += """
                <br/><br/>
                <b>{mas_title}</b><br/>
                """.format(
                    mas_title = i18n.t('label.mas_title')
                )

                for mas_id in content['mas'].split('|'):
                    result_cell += "{mas_id} - {mas_title}<br/>".format(
                        mas_id = mas_id,
                        mas_title = i18n.t('mas.%s' % mas_id)
                    )

            if (content['real_mstg']):
                result_cell += """
                <br/><br/>
                <b>{mstg_title}</b><br/>
                {mstg_result}
                """.format(
                    mstg_title = i18n.t('label.mstg_title'),
                    mstg_result = "<br/> ".join(content['real_mstg'].split('|'))
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
                    desc = content['desc']
                )

            try:
                temp_result = ""
                # 避免空的 data: []
                if (self.masterReport[rule]['data']):
                    temp_result += """
                    <br/><br/>
                    <b>{description_title}</b><br/>
                    """.format(
                        description_title = i18n.t('label.detail_info_title')
                    )
                    
                    # 暫時先限字數，似乎套件跨頁會故障
                    for detail_item in self.masterReport[rule]['data'][:1]:
                        try:
                            temp_result += """· {details}<br/>{description}<br/><br/>""".format(
                                details = detail_item['details'],
                                description = str(detail_item['description']),
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
                table_data.append([Paragraph(url, self.styleCellLeft)])
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
        
def Product_PDF(rawdata):
    lang = rawdata['lang']
    system = rawdata['system']
    rule = rawdata['rule']
    result = rawdata['result']

    buffer = BytesIO()
    
    PDFPSReporte(buffer, lang, system, rule, result)

    pdf = buffer.getvalue()
    return pdf