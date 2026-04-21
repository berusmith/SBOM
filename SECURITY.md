# Security Policy

## 支援版本

| 版本 | 安全性支援 |
|------|-----------|
| 1.5.x (最新) | 支援 |
| 1.0.x | 僅嚴重漏洞 |
| < 1.0 | 不支援 |

## 回報安全漏洞

**請勿透過 GitHub Issues 公開回報安全漏洞。**

請以電子郵件寄送至：**pdbl8951@gmail.com**

郵件請包含：
- 漏洞描述與影響範圍
- 重現步驟（含 HTTP request/response 若適用）
- 建議修補方式（選填）
- 是否已有 PoC exploit（請勿附上完整攻擊工具）

收到後將在 **3 個工作天內**確認收件，**14 天內**提供初步評估結果。

## 已知安全設計決策

| 項目 | 設計 | 說明 |
|------|------|------|
| 認證 | JWT Bearer Token | 8 小時有效期，無 refresh token |
| 密碼儲存 | bcrypt hash | 不儲存明文 |
| CORS | 僅允許設定的 origin | 預設 localhost:3000 |
| 資料庫 | SQLite 本地檔案 | 生產環境建議限制檔案系統權限 |
| API 存取 | 所有端點需 JWT | `/login` 與 `/health` 除外 |
| SECRET_KEY | 環境變數注入 | 預設值 `change-me-in-production` 不適用於正式環境 |

## 生產環境安全清單

- [ ] 修改 `SECRET_KEY` 為隨機強金鑰（`openssl rand -hex 32`）
- [ ] 修改 `ADMIN_PASSWORD` 為強密碼
- [ ] HTTPS/TLS 終止於 Nginx（參考 `deploy/nginx-sbom.conf`）
- [ ] 限制 `sbom.db` 檔案系統讀寫權限（`chmod 600`）
- [ ] 定期備份 `sbom.db` 與 `uploads/`
- [ ] 設定防火牆，port 9100 不對外暴露（僅 Nginx → backend）
