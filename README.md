# CMAA 集中式 PDF 報告生成微服務 (Centralized PDF Generator)

本服務為 **CMAA (Cloud Mobile App Analysis)** 平台的集中式 PDF 報告編譯核心微服務，專門負責將檢測數據（JSON）渲染為符合台灣行動應用程式基本資安規範 (MAS) 與國際 OWASP MASVS 標準的正式 PDF 檢測報告。

---

## 📌 模組定位與職責

- **全平台共用**：無論是 **靜態分析 (CMAA-Astatic)**、**動態沙盒分析 (Dynamic System)** 還是 **爬蟲自動化分析**，皆統一將檢測 JSON 丟給本服務產出 PDF。
- **解耦設計**：檢測端無需安裝 ReportLab、PDF 編譯器或各類中英文字型，所有樣板、視覺排版、多國語系 (i18n) 條例對照皆由本服務統一封裝與維護。

---

## 🚀 快速啟動 (Docker)

本專案自帶 `Dockerfile` 與 `docker-compose.yml`，預設運行於 **Port 15148**：

```bash
# 構建並在背景啟動容器
docker compose up -d --build

# 查看服務日誌
docker compose logs -f

# 重啟服務 (若有更新 translations 語系檔)
docker compose restart
```

---

## 🔌 API 對接規格

### 1. 生成檢測報告
- **Method**: `POST`
- **Endpoint**: `/api/report`
- **Header**: `Content-Type: application/json`
- **Response**: `application/pdf`（二進位 PDF 檔案流）

### 2. Request Payload 結構範例
```json
{
  "lang": "en",  // "en" (英文) 或 "zh-TW" (繁體中文)
  "system": {
    "app_name": "MySampleApp",
    "file_name": "app-release.apk",
    "package_name": "com.example.app",
    "version_name": "1.0.0",
    "scan_date": "2026-09-19"
  },
  "rule": {
    "AS-lab001": {
      "title": "Debug Mode Check",
      "mas": "4.1.5.5.9",
      "real_mstg": "MSTG-RESILIENCE-2",
      "owasp_mobile": "M8",
      "level": "HIGH",
      "cve": "N/A",
      "desc": "Check if debug mode is enabled in AndroidManifest.xml"
    },
    "AS-lab082": {
      "title": "Emulator Detection Check",
      "mas": "4.1.5.5.7",
      "real_mstg": "MSTG-RESILIENCE-1",
      "owasp_mobile": "M8",
      "level": "MEDIUM",
      "cve": "N/A",
      "desc": "Check if emulator detection mechanism is implemented"
    }
  },
  "result": {
    "url_list": [],
    "mast_report": {
      "AS-lab001": {
        "isDetected": false,
        "data": []
      },
      "AS-lab082": {
        "isDetected": true,
        "data": [
          {
            "details": "Emulator indicators found in bytecode",
            "description": "Found string: /dev/socket/qemud"
          }
        ]
      }
    }
  }
}
```

---

## 🌐 條文與語系維護 (i18n)

所有 MAS 檢測基準條例與多國語言定義均集中於 `app/translations/`：
- **繁體中文**: `app/translations/mas.zh-TW.json`
- **英文**: `app/translations/mas.en.json`
- **通用標籤**: `app/translations/label.*.json`

### 維護規範：
1. **條例對照碼**：請使用標準條例號碼（如 `4.1.5.5.7`、`4.1.5.5.8`、`4.1.5.5.9` 等）。
2. **雙語對稱**：若在 `mas.zh-TW.json` 新增了條例，請務必在 `mas.en.json` 同步補上對應的英文，避免產生報告時 fallback 顯示原始鍵值 `mas.x.x.x.x`。
3. **熱生效**：修改 `app/translations/` 下的 JSON 檔後，執行 `docker restart <container_name>` 即可載入生效。
