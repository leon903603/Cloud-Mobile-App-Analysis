# 📱 Mobile-APP-Crawler & CMAA 雲地混合全域系統備忘錄 (Project Architecture Cheat Sheet)

> **最新更新時間**：2026-09-17  
> **用途**：記錄三大實體/雲端主機配置、職責分工、Tailscale 內網穿透、Docker 微服務與資料庫連線，開新對話或交接時「一秒還原全部架構」！

---

## 🗺️ 全域系統架構圖 (Hybrid Cloud & Dual-Node Isolation)

```
                       【客戶 / 外部使用者】
                                │
                                ▼ (HTTPS 瀏覽器訪問)
       ┌──────────────────────────────────────────────────────────┐
       │ ☁️ 主機一：AWS 雲端 EC2 (t3.small, Sydney)               │
       │    • CMAA-Int (React 前端 + Express 後端, Docker)        │
       │    • 負責：會員登入、點數餘額 (Firebase)、金流、S3 存儲    │
       └──────────────────────────┬───────────────────────────────┘
                                  │
                                  ▼ (透過 Tailscale 100.117.29.74:5001 加密穿透)
       ┌──────────────────────────────────────────────────────────┐
       │ 🖥️ 主機二：實驗室舊伺服器 (192.168.50.53, ubuntu-2004)    │
       │                                                          │
       │  [線上生產環境 (Production)]                              │
       │    • 目錄：/home/islab/CMAA-Astatic-New                  │
       │    • 對外端口：Port 5001 (Wrapper API), 8010 (Androguard) │
       │    • 核心容器：wrapper(5001), backend(8010), worker,     │
       │                app-pdf-generator(15148)                  │
       │    • 規則引擎：完整 80 條 MAST 規則 (含 lab_042 加殼檢測) │
       │    • 實測驗證：2026-09-17 實跑 Celery 產出 36 頁 PDF 報告│
       │                                                          │
       │  [靜態組獨立開發環境 (Dev / Changable)]                  │
       │    • 目錄：/home/islab/CMAA-Astatic-New-changable        │
       │    • 對外端口：Port 5002 (Wrapper API), 8011 (Backend)   │
       │    • 特性：掛載 ./:/app 支援熱重載，專屬 -dev 容器與線上隔離 │
       │    • 規則引擎：完整同步 80 條規則 (含 lab_042/057/058)   │
       │    • 附有 STATIC_DEVELOPER_GUIDE.md 開發指引             │
       │                                                          │
       │  [動態分析系統 (Dynamic Analysis)]                       │
       │    • 本地模擬器：AndroidDynamicSystem (Port 8080)        │
       │    • 雲端真實沙箱：AWS Sydney c6g.metal (24x Redroid ARM)│
       └──────────────────────────────────────────────────────────┘

       ──────────────────────── 實體硬體隔離 ────────────────────────

       ┌──────────────────────────────────────────────────────────┐
       │ 🚀 主機三：實驗室 5860 怪物主機 (192.168.50.120, Precision)│
       │    • 專屬承擔「背景爬蟲批次抓取與巨量任務檢測長跑」       │
       │    • PostgreSQL 16 (Port 5433, 存儲 121 萬筆 APP 與記帳)│
       │    • 9 個 Tor 代理池 (輪替 IP，抗 Google Play 封鎖)       │
       │    • 狀態：維持現狀穩定運作（供行銷推廣/免費報告，與線上隔離） │
       └──────────────────────────────────────────────────────────┘
```

---

## 📋 程式碼倉庫與最新改動紀錄 (Changelog & Commits)

- **核心倉庫**：`leon903603/Cloud-Mobile-App-Analysis`
- **主要分支**：`android-static`
- **本地路徑**：`D:\APP平台\android-static` (或 `D:\APP(android)\CMAA-Astatic`)
- **最新 Commit**：`46e36a0`（修復 `~)^` 檔名亂碼與強制校正台灣時區）
- **近期重大 Commits**：
  - `46e36a0`：修復 `androguard_server.py` 與 `maldroid_main.py` 的 Base64 檔名亂碼 `~)^`，強制設定 `Asia/Taipei` (UTC+8) 時間戳。
  - `43bedff`：全面整併學長姐 47 條規則至 `androguard_server.py`，補回加殼檢測 `lab_042` 與敏感識別碼 `lab_057`/`lab_058`。
  - `ba57e69`：優化 Dockerfile 建置快取層（獨立複製 requirements.txt）。
  - `553ea44`：固定 PDF 與分析報告為英文標準輸出。
  - `2653be4`：恢復 `Reports/{sha256}_static.json` 產出與 `/get_json` 多層 Fallback。

---

## 🔍 重大技術突破與問題根因分析 (2026-09-17 專案關鍵修復)

### 1. `lab_042` (加殼檢測/Packer Detection) 遺失真相與雙環境修復
- **現象回顧**：靜態組在 53 主機測試 `CMAA-Astatic-New-changable` (Port 8011) 與線上 `CMAA-Astatic-New` (Port 8010) 時，發現 `lab_042` 消失，發送請求回傳 HTTP 404。
- **根因分析**：
  1. 先前同步學長姐進度時，僅 cherry-pick 了 commit `e63df66`。該 commit 僅修改了 `androguard_server.py` 中的 `lab081`（輸入驗證）與 `lab063`（防誤判）。
  2. 但 `maldroid_main.py` 已經全面擴充至 80 條規則，並在分析流程中調用了 `/lab_042`（加殼檢測）、`/lab_057`（IMEI/IMSI 存取）、`/lab_058`（MAC 地址存取）。
  3. 舊版 `androguard_server.py` 根本沒有註冊這三個 API 端點，導致底層靜態分析時直接拋出 404 Not Found。
- **解決方案與落地**：
  - 將學長姐完整 47 條 Androguard 規則全數整併進 `androguard_server.py`，並同時保留微服務架構必備的 4 個核心端點（`/load_apk`、`/run_maldroid`、`/get_json`、`/androguard/lab16`）。
  - 同步覆蓋至 53 主機上的兩個環境：
    - **線上生產端 (Production)**：`/home/islab/CMAA-Astatic-New` (Port 8010)
    - **靜態開發端 (Changable)**：`/home/islab/CMAA-Astatic-New-changable` (Port 8011)
  - 兩端容器均重啟驗證，端點皆正常回傳 HTTP 200 與分析結果（`jiagu: true/false`）。

---

### 2. `~)^` 檔名亂碼根因徹底治本
- **現象回顧**：產出的靜態分析報告與 PDF 中，APK 檔案名稱經常被顯示為奇怪的亂碼字串 `~)^`。
- **根因追查**：
  1. `androguard_server.py` 在調用 `maldroid_main.py` 的命令列參數中，寫死了：
     `cmd = ["python2", ..., "-n", "file", ...]`
  2. 而 `maldroid_main.py` 接收到 `-n` 參數後，執行了 Base64 解碼：
     `base64.b64decode('file')`
  3. 字串 `'file'` 在 Base64 解碼後的原始二進位位元組剛好是 `b'\x7e)\xf8'`，在 ASCII / Latin-1 解碼下正是 **`~)^`**！
  4. 先前系統僅在 Celery Worker 的記憶體中做暫時性覆寫，只要走靜態底層原生調用或直連測試，檔名就會變回 `~)^`。
- **根本解決**：
  - 在 `androguard_server.py` 發動命令時，將真實檔名做 Base64 編碼傳入：`base64.b64encode(os.path.basename(apk_path).encode('utf-8')).decode('ascii')`。
  - 在 `maldroid_main.py` 加上保險檢查：若解碼出的檔名為 `~)^` 或包含不可讀控制字元，自動 Fallback 回傳真實 APK 檔案名稱。

---

### 3. 掃描時間時區偏差校正 (Asia/Taipei UTC+8)
- **現象回顧**：報告中的 `Scan time` 顯示時間比台灣實際時間慢 8 小時（例如下午 16:34 產出的報告顯示為 08:34）。
- **根因分析**：Docker 容器內部預設時區為 UTC+0 (`Etc/UTC`)，未掛載主機時區配置，導致 Python `datetime.now()` 抓取為 UTC 時間。
- **解決方案**：
  - 在 `docker-compose.yml` 中掛載主機時區 `/etc/localtime:/etc/localtime:ro`。
  - 在 `maldroid_main.py` 加入時間戳容錯補償機制：若檢測到環境為 UTC (`time.timezone == 0`)，自動補償 +8 小時轉為 `Asia/Taipei` 標準時間格式。

---

### 4. 報告目錄辨析：`Reports/` vs `reports/` 與雲端生命週期
在 53 主機上有兩個名稱相近但職責截然不同的目錄：
1. **`Reports/` (大寫 R，微服務核心目錄)**：
   - 位於 `/home/islab/CMAA-Astatic-New/Reports`。
   - 由 `maldroid_main.py` 直接寫入，存放以 APK SHA-256 為名稱的靜態分析結果：
     - `{sha256}_static.json`（英文標準版，供 PDF Generator 與前端使用）
     - `{sha256}_static_zh.json`（中文備查版）
   - **設計目的**：使用 SHA-256 檔名確保多租戶高併發掃描時，絕對不會互相覆蓋報告。
2. **`reports/` (小寫 r，本機除錯目錄)**：
   - 位於 `/home/islab/CMAA-Astatic-New/reports`。
   - 供地端開發人員除錯與驗證產生之 PDF 檔案（例如 `production_scan_report.pdf`、`app-debug_report.pdf`）。
3. **線上正式運作之 S3 雲端生命週期**：
   - 線上真實使用者透過 Web 上傳檢測時，Celery Worker 在生成 PDF 後，會**直接將二進位流上傳至 AWS S3**：
     `s3://cmaa-s3-islab-sydney/reports/{userId}/{fileId}/static.pdf`
   - 地端不會無限期堆積舊 PDF，兼具資料隱私與硬碟容量維護。

---

### 5. 動態分析 (Dynamic Analysis) 與帳密登入檢測機制
- **雲端沙箱環境**：
  - 規格：AWS Sydney EC2 `c6g.metal` ARM64 裸機實體機（Instance ID: `i-037917cfa6d87177f`）。
  - 具備 64 個 vCPU、128GB RAM，底層直載 KVM 核心模組，已完成 24 個 Redroid (Android 11) 容器叢集配置。
  - **成本控制**：目前處於 **STOPPED (已停止)** 狀態，每小時節省 $4.096 美金，需要大規模動態測試時可隨時由 AWS CLI 一鍵啟動。
- **帳號密碼登入檢測策略**：
  1. **使用者有提供帳號密碼**：
     - 前端輸入時加密儲存，派發動態分析任務時透過 `setpa` 參數將憑證傳送給沙箱內之 `CmdServer.py`。
     - 沙箱透過 UI Automator / Frida 識別登入畫面的 EditText 元件，自動鍵入帳密並觸發登入按鈕，進入登入後畫面深度檢測 API 流量與敏感行為。
  2. **使用者未提供帳號密碼 / 輸入「無」**：
     - 許多工具類、公開資訊類 APP 原生無須登入。
     - 沙箱自動進入**訪客探索模式 (`action: auto`)**：
       - 若遇彈窗、權限授權框，自動點擊「允許」或「略過」。
       - 若遇到登入頁面，自動嘗試點擊「以訪客身分繼續」、「略過 (Skip)」、「稍後再說」。
       - 自動遍歷公開 Activity、點擊主要按鈕，記錄所有非授權狀態下的網路連線、明文傳輸與 SDK 行為。
  3. **需簡訊/OTP 雙因素驗證**：
     - 自動化爬蟲沙箱無法自動獲取外在簡訊，若遇到此類強驗證頁面，系統標記為「需人工代測/進階專人服務」，或僅對登入前行為進行動態評估。

---

## ☁️ 主機一：AWS 雲端環境 (SaaS 門面大腦)

- **執行個體**：`i-03d897a7c64334194` (`t3.small`)，地區：亞太雪梨 `ap-southeast-2`
- **內網 IP (AWS 內部)**：`172.31.40.72`
- **Tailscale IP**：`100.87.155.98`
- **SSH 帳號**：`ubuntu`
- **專案目錄**：
  - `~/CMAA-Int`：主平台（React + Node.js Express + SQLite），由 Docker Compose 運行
  - `~/CMAA-Astatic`：備案靜態分析源碼
  - `~/CMAA-Pdf`：PDF 渲染原始碼
- **核心設定檔**：`~/CMAA-Int/.env`
  - `S3_BUCKET=cmaa-s3-islab-sydney`
  - `ANDROID_STATIC_API=http://100.117.29.74:5001/analyze_apk`（透過 Tailscale 直通主機二 53 線上生產節點）
- **外部雲端相依**：
  - **Firebase**：負責 Authentication (信箱登入) 與 Firestore (點數扣款 `users/{uid}`)
  - **AWS S3**：`cmaa-s3-islab-sydney` 存儲 APK/IPA 與產出的 PDF 報告

---

## 🖥️ 主機二：實驗室舊主機 (線上 Web 專屬檢測節點 & 靜態組開發節點)

- **內網 IP**：`192.168.50.53` (主機名 `ubuntu-2004`)
- **Tailscale IP**：`100.117.29.74`
- **SSH 帳號 / 密碼**：`islab` / `4296842968`
- **角色定位**：**專屬支援 AWS EC2 線上客戶的即時靜態與動態分析，並提供靜態組熱生效開發環境**

### 1. 線上生產環境 (Production)
- **工作目錄**：`/home/islab/CMAA-Astatic-New` (Git branch: `android-static`, 最新 commit `46e36a0`)
- **對外端口**：Port `5001`（Queue Wrapper API，由雪梨 EC2 透過 Tailscale 連入）
- **運行容器** (`docker-compose.yml`, Network: `app-sso-network`)：
  - `android-static-wrapper` (Port `5001`)：對外 RESTful API (`POST /analyze_apk`)
  - `android-static-backend` (Port `8010`)：Androguard 反編譯與 MalDroid 80 條靜態特徵引擎 (含 `lab_042`、`lab_057`、`lab_058`)
  - `cmaa-astatic-new_celery-worker_1`：Celery 排程背景任務
  - `android-static-redis`：Redis 任務快取
  - `app-pdf-generator` (Port `15148`)：預先生成 PDF 報告模組
- **實測驗證紀錄**：
  - 任務 ID：`6d45e8dc-3a78-4265-afe3-a9e44f6686c5` (2026-09-17 16:34:04)
  - 產出檔案：`production_scan_report.pdf` (共 36 頁，包含完整 80 條規則清單與漏洞細節)
  - 驗證點：檔名確認為真實名稱 `app-debug.apk`（無 `~)^`），時區為台灣時間 `2026-09-17 16:34:04`，`lab_042` 判定為 `True`（加殼偵測成功）。

### 2. 靜態組獨立開發環境 (Dev / Changable)
- **工作目錄**：`/home/islab/CMAA-Astatic-New-changable`
- **對外端口**：Port `5002`（API 端點）、Port `8011`（Androguard 後端）
- **環境特性**：
  - **代碼即時熱生效**：掛載 `./:/app`，修改 Python 腳本或 JSON 規則**無需 re-build Docker 映像檔**，重啟服務即可生效。
  - **完全環境隔離**：已配置專屬 `-dev` 容器，與線上 5001/8010 完全隔離，避免開發調試影響線上服務。
  - **引擎版本一致**：`androguard_server.py` 同步整合 47 條規則，`lab_042` 端點經實測確認回傳 HTTP 200。
- **開發指引**：已在該目錄放置 `STATIC_DEVELOPER_GUIDE.md` 供靜態組工程師參考開發。

### 3. 動態分析系統 (Dynamic Sandbox)
- **主機 53 本地服務**：`AndroidDynamicSystem` (Port `8080`) + 本地模擬器 `emulator-5554`
- **AWS 雲端實體機**：`c6g.metal` (24x Redroid ARM64，依需求動態開機使用)

---

## 🚀 主機三：實驗室 5860 怪物主機 (爬蟲與大數據批量長跑)

- **主機型號**：Dell Precision 5860 Tower
- **內網 IP**：`192.168.50.120`
- **SSH 帳號 / 密碼**：`islab` / `islab42968`
- **專案路徑**：`/home/islab/Projects/Mobile-APP-Crawler-Leon` (Git: `origin/leon-repo`)
- **Python 虛擬環境**：`source venv/bin/activate`
- **運作中的微服務**：
  - **PostgreSQL 16**：`localhost:5433` (帳密 `crawler`/`crawlerpass`, DB `appcrawler`)，**已登記 1,211,081 筆 APP**
  - **Tor 代理池**：9 個獨立 Tor 容器，自動更換出口 IP 爬取 Google Play
  - **獨立檢測與 PDF 模組**：`5001` Wrapper + `8010` Backend + `8080` PDF Generator
  - **防重複保護**：已實裝 `is_scan_completed`，已檢測之 APP 零延遲略過，不重複下載。
- **維運策略**：維持現狀未動，專職進行 Google Play 批次抓取與行銷用報表長跑。

---

## 💻 本地端（Windows 開發工作區目錄結構：D:\APP平台）

本地端現已將所有會用到的子系統完整配置到位，方便在本地 IDE 高效修改代碼、版本比對與測試：

1. **`android-static/`（靜態分析微服務引擎）**：
   - 倉庫：`leon903603/Cloud-Mobile-App-Analysis`，分支：`android-static`
   - 內容：80 條 MAST 規則、Androguard 47 條規則、`maldroid_main.py`、Celery Worker、Queue Wrapper。已全面修復 `lab_042`、`~)^` 檔名亂碼與台灣時區（已與 GitHub 和主機 53 雙向同步最新 `a40eb3a`）。
2. **`android-detection-system/`（動態分析系統核心）**：
   - 倉庫：`CoreXing/android_detection_system`，分支：`Dymanic_maintain`
   - 內容：Frida 注入腳本、APIMonitor-beta、`CmdServer.py`、自動化探測、UI Automator、`run_eval.py`、TestLoader、ws_scrcpy。
   - 執行架構：本地編輯代碼，透過 ADB / SSH Tunnel 連線至主機 53 (Port 8080) 或 AWS Sydney `c6g.metal` Redroid (Port 5565) 執行測試。
3. **`Cloud-Mobile-App-Analysis/`（CMAA 雲端主平台門面）**：
   - 倉庫：`leon903603/Cloud-Mobile-App-Analysis`，分支：`main`
   - 內容：React 前端 + Express 後端 + Firebase Auth / Firestore 點數金流。
4. **`Mobile-APP-Crawler/`（大數據爬蟲與批次檢測）**：
   - 倉庫：`leon903603/Mobile-APP-Crawler`，分支：`leon-repo`
   - 內容：Google Play 爬蟲、PostgreSQL 介接、Tor 代理池管理。
5. **`pdf-generator/`（PDF 報告產生器）**：
   - 倉庫：`leon903603/Cloud-Mobile-App-Analysis`，分支：`pdf-generator`
   - 內容：ReportLab 報告渲染引擎。

---

## 🛠️ 常用驗證與健康檢查指令

### 1. 檢查主機 53 線上端點與開發端點
```bash
# 測試生產環境加殼偵測端點 (8010)
curl -X POST http://localhost:8010/lab_042

# 測試開發環境加殼偵測端點 (8011)
curl -X POST http://localhost:8011/lab_042

# 測試線上 Wrapper API 健康度 (5001)
curl http://localhost:5001/
```

### 2. 觸發真實 APK 靜態掃描與 PDF 生成測試 (以主機 53 為例)
```bash
curl -X POST http://localhost:5001/analyze_apk \
  -F "file=@/home/islab/CMAA-Astatic-New/test_apks/app-debug.apk"
```

### 3. 查看 Celery 任務日誌
```bash
docker logs -f cmaa-astatic-new_celery-worker_1 --tail 50
```
