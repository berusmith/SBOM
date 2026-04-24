# Pitfall: PowerShell 執行 `npm.ps1` 被 ExecutionPolicy 擋住

**錯誤訊息** |
```
npm.ps1 cannot be loaded because running scripts is disabled on this system.
For more information, see about_Execution_Policies ...
FullyQualifiedErrorId : UnauthorizedAccess
```

**原因** | Windows PowerShell 預設 ExecutionPolicy 是 `Restricted`,拒絕執行 `.ps1`。Node.js MSI 安裝同時放了 `npm.ps1` 和 `npm.cmd`;PowerShell 優先找 `npm.ps1`,就被擋。

**解法(不改 ExecutionPolicy)** |
- 直接指定:`& "C:\Program Files\nodejs\npm.cmd" install`
- 或在 Git Bash / WSL 裡執行,它會找 `npm.cmd`
- 或改呼叫 `node` + 明確 cli:`node "C:\Program Files\nodejs\node_modules\npm\bin\npm-cli.js" install`

**若想一次解決** | 用系統管理員 PowerShell 執行:
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```
(但這改變安全策略,讓本機所有 `.ps1` 可執行 — 若不是共用機器可接受,共用機器要小心。)

**預防** | Bash / cmd / Git Bash 不受影響,優先用這些執行 npm。

**日期** | 2026-04-24
