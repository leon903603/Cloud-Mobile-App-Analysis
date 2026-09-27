import unittest
import os
import json
from unittest.mock import patch, MagicMock

import sys

# 若本機環境未安裝 celery，注入 mock 模組以利本機測試 Flask 鑑權
try:
    import celery
except ImportError:
    mock_celery_mod = MagicMock()
    sys.modules["celery"] = mock_celery_mod
    sys.modules["celery_app"] = MagicMock()
    mock_tasks = MagicMock()
    sys.modules["tasks"] = mock_tasks

# 載入受測模組前先設定環境變數
os.environ["STATIC_API_KEY"] = "test-secret-key-12345"
os.environ["PORT"] = "5001"

import wrapper

class TestWrapperAuth(unittest.TestCase):
    def setUp(self):
        wrapper.app.config["TESTING"] = True
        self.client = wrapper.app.test_client()
        self.valid_key = "test-secret-key-12345"
        self.invalid_key = "wrong-key-hacker"

    def test_health_check_public(self):
        """Phase 4 驗證：/health 與 /api/v1/health 端點無須 Key，正常探測"""
        for endpoint in ["/health", "/api/v1/health"]:
            res = self.client.get(endpoint)
            self.assertEqual(res.status_code, 200)
            data = res.get_json()
            self.assertEqual(data.get("status"), "ok")
            self.assertEqual(data.get("port"), 5001)

    def test_missing_api_key_rejected(self):
        """Phase 4 驗證（憲法五）：未帶 X-API-Key 標頭，強制 401 拒絕"""
        res_post = self.client.post("/analyze_apk", json={"hash": "abc", "key": "apk.apk"})
        self.assertEqual(res_post.status_code, 401)
        self.assertIn("Invalid or missing API key", res_post.get_json().get("error", ""))

        res_status = self.client.get("/status/job-123")
        self.assertEqual(res_status.status_code, 401)

    def test_invalid_api_key_rejected(self):
        """Phase 4 驗證（憲法五）：偽造或錯誤的 X-API-Key，強制 401 拒絕"""
        headers = {"X-API-Key": self.invalid_key}
        res_post = self.client.post("/analyze_apk", headers=headers, json={"hash": "abc", "key": "apk.apk"})
        self.assertEqual(res_post.status_code, 401)
        self.assertIn("Invalid or missing API key", res_post.get_json().get("error", ""))

        res_v1 = self.client.post("/api/v1/analyze_apk", headers=headers, json={"hash": "abc", "key": "apk.apk"})
        self.assertEqual(res_v1.status_code, 401)

    @patch("wrapper.analyze_apk.delay")
    @patch("wrapper.get_s3_client")
    def test_valid_api_key_authorized(self, mock_s3_client, mock_delay):
        """Phase 4 驗證（憲法五）：攜帶正確 X-API-Key 正常放行通過鑑權"""
        mock_task = MagicMock()
        mock_task.id = "job-mock-test-id"
        mock_delay.return_value = mock_task

        headers = {"X-API-Key": self.valid_key}
        
        # 測試缺少參數應返回 400（表示已通過 401 鑑權層）
        res_empty = self.client.post("/analyze_apk", headers=headers, json={})
        self.assertEqual(res_empty.status_code, 400)

        # 測試正常派發任務
        mock_s3 = MagicMock()
        mock_s3_client.return_value = mock_s3
        res_ok = self.client.post("/api/v1/analyze_apk", headers=headers, json={
            "key": "uploads/user1/test.apk",
            "hash": "d2d2d2d2d2d2d2d2d2",
            "filename": "test.apk"
        })
        self.assertEqual(res_ok.status_code, 202)
        self.assertEqual(res_ok.get_json().get("job_id"), "job-mock-test-id")

    def test_server_unconfigured_key_fail_closed(self):
        """Phase 4 驗證（憲法五）：當伺服器未設定 STATIC_API_KEY 時，應遵循 Fail-Closed 原則一律拒絕"""
        original_key = wrapper.STATIC_API_KEY
        try:
            wrapper.STATIC_API_KEY = ""
            headers = {"X-API-Key": self.valid_key}
            res = self.client.post("/analyze_apk", headers=headers, json={})
            self.assertEqual(res.status_code, 401)
            self.assertIn("Server API key is not configured", res.get_json().get("error", ""))
        finally:
            wrapper.STATIC_API_KEY = original_key


if __name__ == "__main__":
    unittest.main()
