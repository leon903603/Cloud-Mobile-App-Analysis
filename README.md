# CMAA Android Static Analysis Engine (`android-static`)

## 快速維運與部署工具 (`ops/`)

- 🔍 **雲地差異比對 Agent**:
  ```powershell
  python ops/compare_aws_static.py
  ```
- 📋 **靜態規則與語法驗證器**:
  ```powershell
  python ops/validate_rules.py
  ```
- 🚀 **一鍵發布 SOP 腳本**:
  ```powershell
  .\ops\deploy_static.ps1
  ```
- ⚠️ **一鍵緊急回退腳本**:
  ```powershell
  .\ops\rollback_static.ps1
  ```

完整操作說明與架構設計請參考：[`../docs/SOP_ANDROID_STATIC_DEPLOYMENT.md`](../docs/SOP_ANDROID_STATIC_DEPLOYMENT.md)。
