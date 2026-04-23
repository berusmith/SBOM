# SBOM CLI Tool

命令行工具用于在 CI/CD 流程中整合 SBOM 掃描。

## 安裝

```bash
pip install -e .
```

或直接執行：

```bash
python sbom.py <command> [options]
```

## 環境變數

- `SBOM_API_TOKEN` - API 認證令牌（必需）
- `SBOM_API_URL` - API 伺服器網址（預設：http://localhost:9100）

## 指令

### 上傳 SBOM

```bash
sbom upload <sbom.json> --release <release-id>
```

上傳 SBOM 檔案到指定的版本。

**參數：**
- `<sbom.json>` - SBOM 檔案路徑（JSON 格式）
- `--release` - 版本 ID

### 檢查 Policy Gate

```bash
sbom gate --release <release-id>
```

檢查版本是否通過 Policy Gate 檢查。若失敗返回非 0 exit code。

**參數：**
- `--release` - 版本 ID

### 比較版本

```bash
sbom diff --v1 <release-id-1> --v2 <release-id-2>
```

比較兩個版本的差異，包括新增/移除/修改的元件。

**參數：**
- `--v1` - 第一個版本 ID
- `--v2` - 第二個版本 ID

## 範例

```bash
# 設定環境變數
export SBOM_API_TOKEN=sbom_xxx_yyy
export SBOM_API_URL=http://localhost:9100

# 上傳 SBOM
sbom upload sbom.json --release abc123

# 檢查 gate
sbom gate --release abc123

# 比較版本
sbom diff --v1 abc123 --v2 def456
```

## 許可證

MIT
