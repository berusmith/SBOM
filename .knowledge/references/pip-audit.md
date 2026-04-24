# Reference: `pip-audit`

**用途** | 掃描 Python 相依套件的已知 CVE。官方維護(PyCQA 生態)。

**用法** |
```bash
python -m pip install pip-audit
python -m pip_audit -r backend/requirements.txt --format columns
```
輸出欄位:Name / Version / Vulnerability ID / Fix Versions。

**選項** |
- `--format json`:機器可讀
- `--fix`:自動產生修正 requirements(會改檔!)
- `--ignore-vuln ID`:忽略特定 CVE
- `--skip-editable`:跳過 editable install

**注意** | pip-audit 依 OSV.dev + PyPI advisory。新 CVE 有時延遲數天才出現;上線前務必再跑一次。

**本專案怎麼用** | 每次改 `requirements.txt` 後手動跑一次;CI 可自動化(見下):
```yaml
# .github/workflows/security.yml
- run: pip install pip-audit
- run: pip-audit -r backend/requirements.txt
```

**連結** | https://github.com/pypa/pip-audit

**日期** | 2026-04-24
