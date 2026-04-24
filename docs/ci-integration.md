# SBOM CI/CD 整合指南

本文檔說明如何將 SBOM 掃描整合到您的 CI/CD 流程中。

## 快速開始

### 1. 建立 API Token

首先，您需要建立一個長期的 API Token 用於 CI/CD 流程。

#### 透過 Web UI 建立

1. 登入 SBOM 系統
2. 進入 **Settings** > **API Tokens**
3. 點擊 **新增 Token**
4. 輸入描述（例如：`GitHub Actions`）
5. 選擇 scope：
   - `read` - 只讀操作
   - `write` - 讀寫操作（上傳 SBOM、更新狀態）
   - `admin` - 全部權限
6. 複製並保存 token（通常以 `sbom_` 開頭）

### 2. 安裝 CLI

#### NPM / Node.js
```bash
npm install -g sbom-cli
```

#### Python (pip)
```bash
pip install sbom-cli

# 或者 editable install
pip install -e /path/to/tools/sbom-cli
```

#### 直接執行
```bash
python /path/to/sbom-cli/sbom.py <command>
```

### 3. 配置環境變數

在您的 CI/CD 系統中設定以下環境變數：

```bash
export SBOM_API_TOKEN=sbom_xxxxxxxxxxxxxxxx
export SBOM_API_URL=http://sbom.example.com
```

## CLI 命令

### upload - 上傳 SBOM

```bash
sbom upload <sbom.json> --release <release-id>
```

**參數：**
- `<sbom.json>` - SBOM 檔案路徑
- `--release` - 版本 ID

**範例：**
```bash
sbom upload sbom.json --release app-v1.2.0
```

### gate - 檢查 Policy Gate

```bash
sbom gate --release <release-id>
```

**返回值：**
- 0 - 檢查通過
- 1 - 檢查失敗

**範例：**
```bash
sbom gate --release app-v1.2.0
if [ $? -eq 0 ]; then
  echo "Policy Gate 已通過！"
else
  echo "Policy Gate 失敗，請修復問題"
  exit 1
fi
```

### diff - 比較版本

```bash
sbom diff --v1 <release-id-1> --v2 <release-id-2> [--product <product-id>]
```

**參數：**
- `--v1` - 第一個版本 ID
- `--v2` - 第二個版本 ID
- `--product` - 產品 ID（可選）

**範例：**
```bash
sbom diff --v1 app-v1.0.0 --v2 app-v1.1.0 --product my-app
```

## 集成示例

### GitHub Actions

最簡單的整合方式，使用官方 GitHub Action：

```yaml
name: SBOM Check

on:
  pull_request:
    paths:
      - 'sbom.json'

jobs:
  sbom:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: SBOM Policy Gate Check
        uses: ./tools/sbom-action
        with:
          sbom-file: sbom.json
          release-id: ${{ github.event.pull_request.title }}
          api-token: ${{ secrets.SBOM_API_TOKEN }}
          fail-on-gate: 'true'

      - name: Comment on PR
        if: always()
        uses: actions/github-script@v6
        with:
          script: |
            github.rest.issues.createComment({
              issue_number: context.issue.number,
              owner: context.repo.owner,
              repo: context.repo.repo,
              body: '✅ SBOM 檢查已完成'
            });
```

### GitLab CI

```yaml
sbom_check:
  stage: test
  image: python:3.11
  script:
    - pip install sbom-cli
    - sbom upload sbom.json --release $CI_COMMIT_TAG
    - sbom gate --release $CI_COMMIT_TAG
  only:
    - tags
  environment:
    name: production
  variables:
    SBOM_API_TOKEN: $SBOM_API_TOKEN
    SBOM_API_URL: https://sbom.example.com
```

### Jenkins

```groovy
pipeline {
  agent any

  stages {
    stage('SBOM Check') {
      environment {
        SBOM_API_TOKEN = credentials('sbom-api-token')
        SBOM_API_URL = 'https://sbom.example.com'
      }
      steps {
        sh '''
          pip install sbom-cli
          sbom upload sbom.json --release ${BUILD_TAG}
          sbom gate --release ${BUILD_TAG}
        '''
      }
    }
  }

  post {
    always {
      publishHTML([
        reportDir: '.',
        reportFiles: 'sbom-report.html',
        reportName: 'SBOM Report'
      ])
    }
  }
}
```

### GitLab CI (使用 Docker)

```yaml
sbom_check:
  stage: test
  image: sbom:latest
  script:
    - sbom upload sbom.json --release $CI_COMMIT_SHA
    - sbom gate --release $CI_COMMIT_SHA || exit 1
  variables:
    SBOM_API_TOKEN: $SBOM_API_TOKEN
    SBOM_API_URL: https://sbom.example.com
  artifacts:
    reports:
      dotenv: sbom_results.env
    when: always
```

## Best Practices

### 1. 安全地管理 API Token

- **永遠不要**在代碼中硬編碼 token
- 使用 CI/CD 系統的 secrets 管理功能
- 定期輪換 token
- 為不同的 CI/CD 流程使用不同的 token（最小權限原則）

### 2. 版本命名

使用一致的版本命名方案：
```bash
# Git tag 作為版本 ID
sbom upload sbom.json --release $(git describe --tags)

# 或者使用 commit hash
sbom upload sbom.json --release $(git rev-parse --short HEAD)
```

### 3. 檢查通過條件

Policy Gate 檢查有以下 5 個條件，全部必須通過：

1. **SBOM 已上傳** - 版本必須有上傳的 SBOM
2. **無未處理 Critical 漏洞** - 不能有開放的 Critical 漏洞
3. **無 Block 等級 License** - 不能有被 block 的 License
4. **SBOM 品質 ≥ B 級** - SBOM 品質評分必須 ≥ B 級
5. **所有漏洞已完成分類** - 所有漏洞必須被標記為已分類

### 4. 處理失敗

Policy Gate 檢查失敗時，檢查失敗的漏洞詳情：

```bash
# 取得版本的詳細漏洞列表
curl -H "Authorization: Bearer $SBOM_API_TOKEN" \
  "https://sbom.example.com/api/releases/{release-id}/vulnerabilities"
```

### 5. 分析差異

在每次發佈前，比較新舊版本的組件和漏洞：

```bash
sbom diff --v1 app-v1.0.0 --v2 app-v1.1.0 --product my-app
```

## 常見問題

### Q: 如何更新 Policy Gate 的檢查規則？

A: Policy Gate 的規則由系統管理員在 Settings > Policies 中配置。

### Q: SBOM 上傳失敗了怎麼辦？

A: 檢查以下幾點：
1. SBOM 檔案格式是否正確（CycloneDX 或 SPDX）
2. 版本 ID 是否正確
3. API token 是否有效
4. API 伺服器是否可訪問

### Q: 如何在本地測試 CI/CD 配置？

A: 設定環境變數並在本地執行命令：
```bash
export SBOM_API_TOKEN=sbom_xxxx
export SBOM_API_URL=http://localhost:9100
python sbom.py gate --release test-release
```

### Q: 能否在不連接到服務器的情況下進行本地驗證？

A: 目前不支持，但計劃在未來的版本中添加本地驗證功能。

## 相關文檔

- [API 參考](api-reference.md)
- [CLI 使用指南](../tools/sbom-cli/README.md)
- [GitHub Action 使用](../tools/sbom-action/README.md)

---

## 直接掃描 Container Image（不需先產 SBOM）

如果你的 CI pipeline 是從 image tag 開始，可以跳過 SBOM 產生步驟，直接讓平台呼叫 Trivy 掃描：

```bash
# 取得 token
TOKEN=$(curl -sX POST $SBOM_API_URL/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"sbom@2024"}' | jq -r .access_token)

# 掃描 Container Image，結果合併進指定 Release
curl -X POST $SBOM_API_URL/api/releases/$RELEASE_ID/scan-image \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"image": "myrepo/myapp:1.2.3"}'
```

回應範例：
```json
{ "image": "myrepo/myapp:1.2.3", "components_found": 87, "vulnerabilities_found": 12 }
```

### 前置條件

Trivy 必須安裝在後端伺服器上：
```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
# 初次拉 DB（約 500MB，離線環境請預先下載）
trivy image --download-db-only
```

若 Trivy 未安裝，API 回傳 HTTP 503 並附帶安裝指令提示。

---

## 掃描 IaC / Terraform / K8s YAML

```bash
# 壓縮你的 infra 目錄
zip -r infra.zip terraform/ k8s/ Dockerfile

# 上傳掃描
curl -X POST $SBOM_API_URL/api/releases/$RELEASE_ID/scan-iac \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@infra.zip"
```

回應會包含 `misconfigs` 陣列，每項含 `id`、`severity`、`title`、`resolution`。
