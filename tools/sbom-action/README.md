# SBOM Policy Gate GitHub Action

自動在 GitHub Actions 流程中檢查 SBOM 的 Policy Gate 狀態。

## 使用方式

### 基本範例

```yaml
name: SBOM Check

on:
  pull_request:

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: SBOM Policy Gate Check
        uses: ./tools/sbom-action
        with:
          sbom-file: sbom.json
          release-id: my-release-id
          api-token: ${{ secrets.SBOM_API_TOKEN }}
```

## 輸入

| 輸入 | 必需 | 預設值 | 說明 |
|------|------|--------|------|
| `sbom-file` | ✓ | - | SBOM 檔案路徑 |
| `release-id` | ✓ | - | SBOM 系統中的版本 ID |
| `api-token` | ✓ | - | SBOM API 令牌 |
| `api-url` | ✗ | `http://localhost:9100` | SBOM API 伺服器網址 |
| `fail-on-gate` | ✗ | `true` | 若 Policy Gate 檢查失敗則使 workflow 失敗 |
| `product-id` | ✗ | - | 產品 ID（用於差異比較） |

## 功能

- 上傳 SBOM 檔案到指定版本
- 執行 Policy Gate 檢查
- 在 PR 上留下檢查結果 comment
- 若檢查失敗可選擇 workflow 失敗或繼續

## 環境變數

不需要設定額外的環境變數。所有配置透過 Action 的 inputs 參數提供。

## 設定 Secrets

在 GitHub repository 的 Settings > Secrets and variables > Actions 中設定：

- `SBOM_API_TOKEN` - SBOM API 令牌
- `SBOM_RELEASE_ID` - 預設的版本 ID（可選）

## 範例 Workflow

```yaml
name: SBOM Check

on:
  pull_request:
    paths:
      - 'sbom.json'

jobs:
  sbom-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: SBOM Policy Gate Check
        uses: ./tools/sbom-action
        with:
          sbom-file: sbom.json
          release-id: 'my-app-v1'
          api-token: ${{ secrets.SBOM_API_TOKEN }}
          api-url: 'https://sbom.example.com'
          fail-on-gate: 'true'
```

## 輸出

- **PR Comment**: 在 pull request 上自動留下檢查結果
- **Workflow Status**: 若 `fail-on-gate` 為 true，檢查失敗時 workflow 失敗

## 許可證

MIT
