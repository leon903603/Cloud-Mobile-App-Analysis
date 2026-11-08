import os
import sys
import unittest
import json
from io import BytesIO

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_LAMBDA_DIR = os.path.join(BASE_DIR, "..", "static_lambda")
sys.path.insert(0, STATIC_LAMBDA_DIR)

import report
import i18n


def build_static_reporter(lang, rules, mast_report):
    system_mock = {
        'app_name': 'TestApp',
        'file_name': 'test.apk',
        'package_name': 'com.test.app',
        'version_name': '1.0'
    }
    result_mock = {
        'md5': '6949cb68fad0b9a38ef08332435f3d5a',
        'mast_report': mast_report
    }
    
    class MockStaticReporter(report.PDFPSReporte):
        def __init__(self, path, lang, system, rules, result):
            from copy import deepcopy
            super(report.PDFPSReporte, self).__init__(lang)
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
            self.saved_elements = list(self.elements)

    return MockStaticReporter(BytesIO(), lang, system_mock, rules, result_mock)


def build_dynamic_reporter(lang, rules, mast_report):
    import importlib.util
    dyn_path = os.path.join(BASE_DIR, "..", "dynamic_lambda", "report.py")
    spec = importlib.util.spec_from_file_location("dyn_report_module", dyn_path)
    dyn_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dyn_mod)

    system_mock = 'android'
    result_mock = {
        'md5': '6949cb68fad0b9a38ef08332435f3d5a',
        'mast_report': mast_report
    }

    class MockDynReporter(dyn_mod.PDFPSReporte):
        def __init__(self, path, lang, system, rules, result):
            self.system = system
            self.rules = rules
            self.appInfo = dict(result)
            self.masterReport = self.appInfo.pop('mast_report', {})
            self.startupChecks = {}
            super(MockDynReporter, self).__init__(path, lang, system, rules, result)

        def Header(self):
            super().Header()
            self.saved_header_elements = list(self.elements)

        def MasterReport(self):
            super().MasterReport()
            self.saved_elements = list(self.elements)

    reporter = MockDynReporter(BytesIO(), lang, system_mock, rules, result_mock)
    return reporter


class TestPDFReportRendering(unittest.TestCase):
    def setUp(self):
        self.static_rules_mock = {
            'AS-lab001': {
                'title': 'Cleartext Traffic Check',
                'desc': 'A' * 1300 + ' already mitigated by OS, but should be cleaned up. Extra text to ensure length exceeds 1500 chars.',
                'mas': '4.1.2.4.1',
                'owasp_mobile': 'M3'
            },
            'AS-lab017': {
                'title': 'Debug Mode Checking',
                'desc': 'Debug mode check description',
                'mas': '4.1.5.5.9',
            },
            'AS-lab052': {
                'title': 'SQLite Database Vulnerability Check',
                'desc': 'Database check description',
                'mas': '4.1.5.1.1',
            }
        }
        self.static_mast_report_mock = {
            'AS-lab001': {
                'isDetected': False,
                'data': []
            },
            'AS-lab017': {
                'isDetected': True,
                'data': []  # Empty finding
            },
            'AS-lab052': {
                'isDetected': True,
                'data': [{
                    'details': 'SQLite open',
                    'description': 'This app is using SQLite but is not at risk of Journal Information Disclosure.'
                }]
            }
        }

    def test_description_no_truncation(self):
        """Verify that descriptions longer than 1200 characters are NOT cut off."""
        reporter = build_static_reporter('en', self.static_rules_mock, self.static_mast_report_mock)
        tbl = reporter.saved_elements[14]
        
        found_as001 = False
        for row in tbl._cellvalues:
            rule_cell = row[1]
            if 'AS-lab001' in rule_cell.text:
                found_as001 = True
                self.assertIn('cleaned up', rule_cell.text, "Description was truncated before 'cleaned up'!")
        self.assertTrue(found_as001, "AS-lab001 table row not found!")

    def test_summary_text_bilingual_and_non_breaking(self):
        """Verify summary text has &nbsp;|&nbsp; and supports Chinese and English."""
        # Test English
        reporter_en = build_static_reporter('en', self.static_rules_mock, self.static_mast_report_mock)
        summary_en = getattr(reporter_en.saved_elements[12], 'text', '')
        self.assertIn('&nbsp;|&nbsp;', summary_en, "English summary should use non-breaking spaces around separator!")
        self.assertIn('Passed: 1', summary_en)
        self.assertIn('Failed: 2', summary_en)

        # Test Chinese
        reporter_zh = build_static_reporter('zh-TW', self.static_rules_mock, self.static_mast_report_mock)
        summary_zh = getattr(reporter_zh.saved_elements[12], 'text', '')
        self.assertIn('&nbsp;|&nbsp;', summary_zh, "Chinese summary should use non-breaking spaces around separator!")
        self.assertIn('通過: 1', summary_zh)
        self.assertIn('偵測到風險: 2', summary_zh)

    def test_as_lab052_contradiction_normalized(self):
        """Verify AS-lab052 contradiction generates an explanatory notice."""
        reporter = build_static_reporter('zh-TW', self.static_rules_mock, self.static_mast_report_mock)
        tbl = reporter.saved_elements[14]
        found_note = False
        for row in tbl._cellvalues:
            rule_cell = row[1]
            if 'AS-lab052' in rule_cell.text:
                self.assertIn('無 SQLite Journal 資訊洩漏風險', rule_cell.text)
                found_note = True
        self.assertTrue(found_note, "AS-lab052 normalization note was not rendered!")

    def test_empty_findings_render_notice_instead_of_dot(self):
        """Verify AS-lab017 (empty finding) renders empty finding notice instead of just a lone dot."""
        reporter = build_static_reporter('en', self.static_rules_mock, self.static_mast_report_mock)
        tbl = reporter.saved_elements[14]
        found_notice = False
        for row in tbl._cellvalues:
            rule_cell = row[1]
            if 'AS-lab017' in rule_cell.text:
                self.assertIn('manual review recommended', rule_cell.text)
                found_notice = True
        self.assertTrue(found_notice, "Empty finding notice was not rendered for AS-lab017!")

    def test_dynamic_summary_text_bilingual_and_non_breaking(self):
        """Verify dynamic report summary text has &nbsp;|&nbsp; and bilingual support."""
        dyn_rules_mock = {
            'AD-Lab001': {
                'title': 'Root Check',
                'desc': 'Check root',
                'mas': '4.1.2.6.1',
                'owasp_mobile': 'M1'
            }
        }
        dyn_mast_report_mock = {
            'AD-Lab001': {
                'status': 'PASSED'
            }
        }
        rep_en = build_dynamic_reporter('en', dyn_rules_mock, dyn_mast_report_mock)
        found_dyn_summary_en = False
        for el in rep_en.saved_elements:
            text = getattr(el, 'text', '')
            if 'Passed:' in text:
                found_dyn_summary_en = True
                self.assertIn('&nbsp;|&nbsp;', text)
                self.assertIn('Detected: 0', text)
        self.assertTrue(found_dyn_summary_en, "Dynamic English summary missing!")

        rep_zh = build_dynamic_reporter('zh-TW', dyn_rules_mock, dyn_mast_report_mock)
        found_dyn_summary_zh = False
        for el in rep_zh.saved_elements:
            text = getattr(el, 'text', '')
            if '通過:' in text:
                found_dyn_summary_zh = True
                self.assertIn('&nbsp;|&nbsp;', text)
                self.assertIn('偵測到風險: 0', text)
        self.assertTrue(found_dyn_summary_zh, "Dynamic Chinese summary missing!")

    def test_english_report_suppresses_cjk_descriptions(self):
        """AC-01: Verify English report suppresses CJK descriptions from static analysis engine."""
        import re
        rules_mock = {
            'AS-lab001': {
                'title': 'Cleartext Traffic Enabled',
                'desc': 'The application enables cleartext HTTP traffic.',
                'mas': '4.1.2.6.1',
                'owasp_mobile': 'M3'
            }
        }
        # 模擬靜態引擎吐出的中文 description 與英文 details
        mast_report_mock = {
            'AS-lab001': {
                'status': 'FAILED',
                'isDetected': True,
                'data': [
                    {
                        'details': 'android:usesCleartextTraffic="true"',
                        'description': '偵測到 App 可能透過 cleartext (HTTP) 進行網路傳輸，存在中間人攻擊風險。'
                    }
                ]
            }
        }
        reporter = build_static_reporter('en', rules_mock, mast_report_mock)
        tbl = reporter.saved_elements[14]
        rule_cell_text = tbl._cellvalues[1][1].text

        # 斷言技術 details 被保留，但 CJK 中文說明完全被過濾
        self.assertIn('android:usesCleartextTraffic="true"', rule_cell_text)
        self.assertNotIn('偵測到 App 可能透過', rule_cell_text)
        cjk_matches = re.findall(r'[\u4e00-\u9fff]', rule_cell_text)
        self.assertEqual(len(cjk_matches), 0, f"Found unexpected CJK characters in English report: {cjk_matches}")

    def test_chinese_report_preserves_cjk_descriptions(self):
        """AC-03: Verify Chinese report (zh-TW and zh) preserves CJK descriptions."""
        rules_mock = {
            'AS-lab001': {
                'title': '允許明文網路傳輸',
                'desc': '應用程式允許未加密的明文傳輸。',
                'mas': '4.1.2.6.1',
                'owasp_mobile': 'M3'
            }
        }
        mast_report_mock = {
            'AS-lab001': {
                'status': 'FAILED',
                'data': [
                    {
                        'details': 'android:usesCleartextTraffic="true"',
                        'description': '偵測到 App 可能透過 cleartext (HTTP) 進行網路傳輸，存在中間人攻擊風險。'
                    }
                ]
            }
        }
        # 測試 zh-TW
        rep_zh_tw = build_static_reporter('zh-TW', rules_mock, mast_report_mock)
        tbl_tw = rep_zh_tw.saved_elements[14]
        cell_text_tw = tbl_tw._cellvalues[1][1].text
        self.assertIn('偵測到 App 可能透過', cell_text_tw)

        # 測試 zh
        rep_zh = build_static_reporter('zh', rules_mock, mast_report_mock)
        tbl_zh = rep_zh.saved_elements[14]
        cell_text_zh = tbl_zh._cellvalues[1][1].text
        self.assertIn('偵測到 App 可能透過', cell_text_zh)

    def test_empty_details_with_cjk_desc_does_not_render_lone_dot(self):
        """AC-04: When details is empty and description is CJK, English report must not render lone dot."""
        rules_mock = {
            'AS-lab017': {
                'title': 'Debuggable Flag Enabled',
                'desc': 'Application is marked as debuggable.',
                'mas': '4.1.2.6.1',
                'owasp_mobile': 'M1'
            }
        }
        mast_report_mock = {
            'AS-lab017': {
                'status': 'FAILED',
                'isDetected': True,
                'data': [
                    {
                        'details': '',
                        'description': '應用程式在 AndroidManifest.xml 中設定了 android:debuggable="true"'
                    }
                ]
            }
        }
        reporter = build_static_reporter('en', rules_mock, mast_report_mock)
        tbl = reporter.saved_elements[14]
        rule_cell_text = tbl._cellvalues[1][1].text

        # 斷言觸發了空 finding 提示，且絕不包含孤立黑點 &bull; <br/>
        self.assertIn('manual review recommended', rule_cell_text)
        self.assertNotIn('&bull; <br/>', rule_cell_text)
        self.assertNotIn('&bull; <br/><br/>', rule_cell_text)


if __name__ == '__main__':
    unittest.main()
