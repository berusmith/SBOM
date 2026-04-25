---
name: WDAC blocks third-party signed binaries
description: 這台 Windows 開啟 WDAC 強制模式,EnterpriseDB / 其他非微軟簽章的 .exe 一律被擋,無法跑 Postgres / 其他下載工具。
type: pitfall
---

# WDAC blocks third-party signed binaries on this Windows host

**徵兆:** 從可信來源(EnterpriseDB、PostgreSQL.org 官方 ZIP 等)下載並解壓的 `.exe` 跑起來報:

```
Program 'postgres.exe' failed to run: An Application Control policy has blocked this file
```

或在 PowerShell 看:

```
postgres.exe 已被 Device Guard 阻擋執行
```

**根因:** 這台機器啟用了 **WDAC(Windows Defender Application Control)強制模式**。檢查:

```powershell
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard `
  | Select CodeIntegrityPolicyEnforcementStatus, UsermodeCodeIntegrityPolicyEnforcementStatus
```

兩個值若都是 **2**(= Enforced),代表強制模式啟用。只有政策白名單上的發行者(主要是 Microsoft + 少數 OEM/IT 加的)才能跑。

**`Unblock-File` 解不了** — 那只移除 NTFS Mark-of-the-Web,WDAC 是更上層的政策,需要改 CI policy XML(管理員權限 + 重啟)。

## 受影響的工具

- **EnterpriseDB Postgres binaries**(`postgres.exe`、`initdb.exe`、`pg_ctl.exe`等)— 確認被擋
- 大概率受影響:任何下載的 .exe / .dll 來自非 Microsoft / 非 Adobe / 非典型企業白名單 publisher
- **不受影響**:Python、Node.js、Git、winget 自身(這些都已在 WDAC 政策白名單內)

## 替代方案

需要本機跑 Postgres 驗證時:

1. **改用 Mac / Linux 機器** — 本專案的 Mac Mini 是天然替代(macOS 沒這層強制)
2. **跑在 WSL 中** — Linux 的二進位不受 Windows WDAC 管轄(若 WSL 已啟用)
3. **Skip 本機驗證** — 程式碼層做完跨 DB 抽象後,把驗證留到 Mac Mini 部署時做(風險低,因為主要的 SQLite 特化已抽乾淨)
4. **要管理員改政策** — 把 EDB 的簽章 cert 加進 WDAC supplemental policy + reboot;運維工程才有的權限

## 跟此專案的關係

2026-04-25 嘗試在這台 Windows 跑 portable Postgres 16.13 驗證 cross-DB code,卡在 WDAC,只完成 SQLite-side 驗證(54/54 tests + days_between() 編譯確認)。Postgres 端驗證延後到 Mac Mini 部署時做。

## 怎麼快速判斷

跑任何下載的 .exe 前,先試一次:

```bash
"<path>/some_binary.exe" --version
```

若報「Application Control policy has blocked」就是 WDAC 擋,**不要再嘗試 Unblock-File / 改 ACL / 加 Defender 例外** — 那些都解不了,直接走替代方案 1-3。
