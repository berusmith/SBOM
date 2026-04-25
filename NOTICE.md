# Third-Party Notices — SBOM Platform

This product includes the open-source components listed below. The product
itself is not derivative of any of them in the legal copyright sense; this
file exists to satisfy attribution and source-availability obligations of the
respective licenses.

If you are a downstream user of this product and need the source code of any
component listed below, follow the **Source** link for that component. If a
component lists an LGPL/MPL/EPL license, you have the right to obtain its
source from that link and to substitute your own modified build of that
component in this product.

Last reviewed: **2026-04-25** (versions match `backend/requirements.txt` and
`frontend/package.json` as of that date).

---

## 1. Backend — Python packages (runtime dependencies)

All packages installed via `pip install -r backend/requirements.txt`.

### 1.1 Permissive (MIT / BSD / Apache 2.0 / HPND)

No source-disclosure obligation. Attribution only.

| Package | Version | License | Source |
|---------|---------|---------|--------|
| fastapi | 0.120.4 | MIT | https://github.com/fastapi/fastapi |
| starlette | 0.49.2 | BSD-3-Clause | https://github.com/encode/starlette |
| uvicorn[standard] | 0.30.6 | BSD-3-Clause | https://github.com/encode/uvicorn |
| sqlalchemy | 2.0.35 | MIT | https://github.com/sqlalchemy/sqlalchemy |
| pydantic | 2.9.2 | MIT | https://github.com/pydantic/pydantic |
| pydantic-settings | 2.5.2 | MIT | https://github.com/pydantic/pydantic-settings |
| python-multipart | 0.0.26 | Apache-2.0 | https://github.com/Kludex/python-multipart |
| httpx | 0.27.2 | BSD-3-Clause | https://github.com/encode/httpx |
| python-jose[cryptography] | 3.5.0 | MIT (jose) + Apache-2.0/BSD (cryptography) | https://github.com/mpdavis/python-jose / https://github.com/pyca/cryptography |
| passlib[bcrypt] | 1.7.4 | BSD-2-Clause | https://foss.heptapod.net/python-libs/passlib |
| bcrypt | 4.3.0 | Apache-2.0 | https://github.com/pyca/bcrypt |
| requests | 2.33.0 | Apache-2.0 | https://github.com/psf/requests |
| pillow | 12.2.0 | HPND (BSD-like) | https://github.com/python-pillow/Pillow |
| aiofiles | 23.2.1 | Apache-2.0 | https://github.com/Tinche/aiofiles |

### 1.2 Weak copyleft — LGPL-3.0

These libraries are used via Python dynamic import (`import psycopg2`,
`from fpdf import FPDF`). LGPL-3.0 §4 "combined work" provisions are
satisfied by:

1. listing the library here with version and source URL,
2. not modifying the library's source as shipped from PyPI,
3. allowing the user to substitute their own build of the library into
   their `venv/` (Python's import mechanism does this naturally — no
   restriction is imposed by this product).

**No part of the SBOM Platform's own source code becomes subject to LGPL.**

| Package | Version | License | Source |
|---------|---------|---------|--------|
| **fpdf2** | 2.8.7 | LGPL-3.0-or-later | https://github.com/py-pdf/fpdf2 |
| **psycopg2-binary** | 2.9.9 | LGPL-3.0-or-later **with OpenSSL Exception** | https://github.com/psycopg/psycopg2 |

To obtain the LGPL source of these libraries:

```bash
pip download --no-deps --no-binary :all: fpdf2==2.8.7 psycopg2==2.9.9
```

---

## 2. Frontend — npm packages (runtime + build)

All MIT / ISC. Bundled into `frontend/dist/` by `npm run build`.

| Package | License | Source |
|---------|---------|--------|
| react / react-dom | MIT | https://github.com/facebook/react |
| react-router-dom | MIT | https://github.com/remix-run/react-router |
| react-i18next | MIT | https://github.com/i18next/react-i18next |
| i18next | MIT | https://github.com/i18next/i18next |
| axios | MIT | https://github.com/axios/axios |
| lucide-react | ISC | https://github.com/lucide-icons/lucide |
| vite | MIT | https://github.com/vitejs/vite |
| @vitejs/plugin-react | MIT | https://github.com/vitejs/vite-plugin-react |
| tailwindcss | MIT | https://github.com/tailwindlabs/tailwindcss |
| postcss | MIT | https://github.com/postcss/postcss |
| autoprefixer | MIT | https://github.com/postcss/autoprefixer |

---

## 3. External tools — invoked as separate processes (NOT bundled)

These tools are **not redistributed** by the SBOM Platform. The platform
invokes them via `subprocess.run(...)` if the operator has installed them
locally. Installation instructions are provided as documentation only
(`deploy/setup-macos.sh` may help install upon explicit opt-in via
environment flags such as `INSTALL_TRIVY=1`); no binary is shipped in any
release artifact of this product.

This arms-length / subprocess invocation pattern is the established
convention for combining proprietary software with GPL CLI tools without
extending the GPL across the process boundary.

| Tool | License | Source | Used for |
|------|---------|--------|----------|
| Trivy | Apache-2.0 | https://github.com/aquasecurity/trivy | Container image SBOM, IaC misconfig scan (server invokes via subprocess) |
| Syft | Apache-2.0 | https://github.com/anchore/syft | Source-archive and binary SBOM generation (server invokes via subprocess) |
| **EMBA** | **GPL-3.0** | https://github.com/e-m-b-a/emba | Firmware unpack + component identification |
| nginx | BSD-2-Clause | https://nginx.org/ | Reverse proxy in production |
| PostgreSQL | PostgreSQL License (BSD-style) | https://www.postgresql.org/ | Optional database backend |
| SQLite | Public Domain | https://www.sqlite.org/ | Default database backend |
| Python | PSF License | https://www.python.org/ | Runtime |
| Homebrew (macOS) | BSD-2-Clause | https://github.com/Homebrew/brew | macOS package manager |

> **EMBA / GPL-3.0 specifically:** The SBOM Platform never includes EMBA
> binaries, EMBA source code, or any derivative of EMBA in its release
> artifacts. `firmware_service.py` calls `emba` via `subprocess.run`. If
> the operator chooses to install EMBA, that installation is governed by
> EMBA's own GPL-3.0 license and is the operator's responsibility. The
> SBOM Platform's own source remains under its own license.

---

## 4. External data sources (no software linkage)

These services are queried over HTTPS for vulnerability and advisory data.
The SBOM Platform stores derived results in its own database; bulk
redistribution of these data sets is not performed.

| Service | Data license | Operator | URL |
|---------|--------------|----------|-----|
| OSV.dev | Apache-2.0 (data) | Google + community | https://osv.dev |
| NVD (National Vulnerability Database) | Public domain (US Government work) | NIST | https://nvd.nist.gov |
| CISA Known Exploited Vulnerabilities (KEV) | Public domain (US Government work) | CISA | https://www.cisa.gov/known-exploited-vulnerabilities-catalog |
| EPSS (Exploit Prediction Scoring System) | CC0 / public domain (since 2023) | FIRST.org | https://www.first.org/epss/ |
| GitHub Security Advisories (GHSA) | GitHub TOS — free for any use including commercial; rate-limited per token tier | GitHub | https://github.com/advisories |

---

## 5. CycloneDX & SPDX specifications

The SBOM Platform produces and consumes documents conformant to:

- **CycloneDX** — OWASP-stewarded standard. Spec at https://cyclonedx.org/specification/overview/. Spec text is licensed Apache-2.0.
- **SPDX** — Linux Foundation standard. Spec at https://spdx.dev/specifications/. Spec text is licensed CC-BY-3.0.

Use of these specifications imposes no copyleft obligation on this product.

---

## 6. License files

The full text of each license referenced above is available at the
respective project's source repository. License full-text bundles are
also reproduced at:

- MIT: https://opensource.org/licenses/MIT
- BSD-3-Clause: https://opensource.org/licenses/BSD-3-Clause
- BSD-2-Clause: https://opensource.org/licenses/BSD-2-Clause
- Apache-2.0: https://www.apache.org/licenses/LICENSE-2.0
- LGPL-3.0: https://www.gnu.org/licenses/lgpl-3.0.html
- GPL-3.0: https://www.gnu.org/licenses/gpl-3.0.html
- HPND: https://opensource.org/licenses/HPND
- ISC: https://opensource.org/licenses/ISC

---

## 7. Compliance summary for downstream users

If you are evaluating SBOM Platform for inclusion in your own product or
service, the obligations you inherit from the dependencies above are:

1. **Reproduce this NOTICE.md** (or an equivalent attribution notice) in
   your documentation, About page, or end-user agreement.
2. **Do not strip** the license headers from `fpdf2` or `psycopg2-binary`
   when packaging.
3. **Do not bundle EMBA** in your distribution unless you also accept
   GPL-3.0 obligations on the EMBA portion (those obligations do not
   extend to SBOM Platform itself, but they do govern any EMBA artifact
   you ship).
4. **Document any modifications** you make to fpdf2 or psycopg2-binary,
   if any, and provide a way for downstream users to obtain those
   modifications (typically a link to your fork's GitHub).

For commercial licensing questions about SBOM Platform itself, contact
the project maintainer.
