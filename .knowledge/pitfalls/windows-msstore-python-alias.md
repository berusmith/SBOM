# Pitfall: Windows `python.exe` is a Microsoft Store Alias

**錯誤訊息** |
```
Python was not found; run without arguments to install from the Microsoft Store,
or disable this shortcut from Settings > Apps > Advanced app settings > App execution aliases.
```

**原因** | Windows 10/11 預設在 `C:\Users\<user>\AppData\Local\Microsoft\WindowsApps\python.exe` 放一個 0-byte 轉址捷徑,指向 MS Store。執行它會直接彈 Store 頁面,而不是真的 Python。

**判斷** | `(Get-Command python).Source` 如果指向 `WindowsApps\python.exe`,就是捷徑。

**解法** |
1. 用 winget 裝正式 Python:`winget install Python.Python.3.12 --scope user`
2. 安裝後的路徑是 `C:\Users\<user>\AppData\Local\Programs\Python\Python312\python.exe`
3. 用絕對路徑呼叫,或重開 shell 讓 PATH 刷新

**預防** |
- Bash 內 `export PATH="/c/Users/peter/AppData/Local/Programs/Python/Python312:$PATH"` 讓 `python` 優先找到真的 Python
- 或乾脆在腳本裡都用絕對路徑

**相關坑** | [npm install child-process PATH 問題](npm-install-child-path.md)

**日期** | 2026-04-24
