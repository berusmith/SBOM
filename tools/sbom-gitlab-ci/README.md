# SBOM Platform — GitLab CI Integration

GitLab CI/CD pipeline template for SBOM upload and Policy Gate checking.

## Setup

### 1. Set CI/CD Variables

Go to **Settings → CI/CD → Variables** and add:

| Variable | Value | Protected | Masked |
|----------|-------|-----------|--------|
| `SBOM_API_TOKEN` | API token (write scope) from SBOM Platform → Tokens | ✅ | ✅ |
| `SBOM_RELEASE_ID` | Release ID from SBOM Platform | — | — |
| `SBOM_API_URL` | `https://your-sbom-server` | — | — |

### 2. Include in Your Pipeline

**Option A — Copy template directly:**
```bash
cp .gitlab-ci.yml your-project/
```

**Option B — Include from this repo:**
```yaml
include:
  - project: 'your-group/sbom-gitlab-ci'
    ref: main
    file: '.gitlab-ci.yml'

stages:
  - build
  - test
  - sbom    # add this stage to your pipeline
```

### 3. Customize

```yaml
variables:
  SBOM_FILE: "path/to/your/sbom.json"   # default: sbom.json
  FAIL_ON_GATE: "true"                   # "false" = warn only, don't fail pipeline
```

## What It Does

| Job | Stage | Description |
|-----|-------|-------------|
| `sbom-upload` | sbom | Uploads SBOM JSON to the platform, triggers vulnerability scan |
| `sbom-gate` | sbom | Checks Policy Gate (6 checks); fails pipeline if gate fails |

## Pipeline Output

```
==================================================
  SBOM Policy Gate: PASS
  Checks passed: 6/6
==================================================
  ✅  No Critical CVEs: 0 unresolved critical severity
  ✅  No KEV Entries: No actively exploited CVEs
  ✅  High CVE Limit: 2 unresolved high severity (limit 5)
  ✅  VEX Assessment Rate: 87% assessed
  ✅  Patch Rate: 73% patched
  ✅  SBOM Signature: Signature present and valid
==================================================
```

## Generating SBOM in GitLab CI

Use [Microsoft SBOM Tool](https://github.com/microsoft/sbom-tool) or [Syft](https://github.com/anchore/syft) before the sbom stage:

```yaml
generate-sbom:
  stage: build
  image: ubuntu:22.04
  script:
    - curl -Lo syft https://github.com/anchore/syft/releases/latest/download/syft_linux_amd64
    - chmod +x syft && ./syft . -o cyclonedx-json > sbom.json
  artifacts:
    paths: [sbom.json]
```
