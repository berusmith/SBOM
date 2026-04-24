# Pitfall: `npm install` 子程序找不到 `node`

**錯誤訊息** |
```
npm error code 1
npm error path ...\node_modules\esbuild
npm error command failed
npm error command C:\Windows\system32\cmd.exe /d /s /c node install.js
'node' 不是內部或外部命令、可執行的程式或批次檔。
```

**原因** | 透過 winget 或 MSI 裝完 Node.js 後,已開啟的 shell 仍用舊 PATH(不會自動刷新)。`npm` 執行時走 cmd.exe 呼叫 `node install.js`,cmd.exe 繼承父 shell 的 PATH,而父 shell 沒有 node,因此失敗。esbuild / sucrase 等有 postinstall 的套件會掛掉。

**判斷** | 安裝看似成功但 `node_modules` 裡某些套件的 `.bin` 不全,或 log 看到 `'node' ... is not recognized`。

**解法** |
1. 重開 shell,讓 PATH 從 registry 重新載入
2. 或在現有 shell `export PATH="/c/Program Files/nodejs:$PATH"`(Bash)
3. 或 `$env:Path = [Environment]::GetEnvironmentVariable('Path','Machine') + ';' + [Environment]::GetEnvironmentVariable('Path','User')`(PowerShell)
4. 乾淨重裝:`rm -rf node_modules package-lock.json && npm install`

**預防** | winget 裝完 Node.js 後永遠重開 shell 再跑 `npm install`。

**相關坑** | [Windows python.exe 捷徑](windows-msstore-python-alias.md)

**日期** | 2026-04-24
