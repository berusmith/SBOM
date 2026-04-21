# Oracle Cloud 防火牆設定（必做）

Oracle Cloud 有兩層防火牆，兩層都要開。

## 第一層：VCN Security List（雲端控制台）

1. 登入 Oracle Cloud Console
2. 左上 ≡ → Networking → Virtual Cloud Networks
3. 點你的 VCN → Security Lists → Default Security List
4. Add Ingress Rules：

| Source CIDR | Protocol | Port | 說明 |
|-------------|----------|------|------|
| 0.0.0.0/0  | TCP      | 80   | HTTP |
| 0.0.0.0/0  | TCP      | 443  | HTTPS（未來用） |

## 第二層：伺服器 iptables（setup.sh 已自動處理）

Ubuntu 用 ufw，Oracle Linux 用 firewalld，setup.sh 會自動偵測並開放。

若自動設定失敗，手動執行：
```bash
# Ubuntu
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Oracle Linux
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --reload
```

## 部署步驟

```bash
# 在 D:\projects\SBOM\sbom-platform 目錄下執行
bash deploy/first-deploy.sh
```

## 日後更新

```bash
bash deploy/deploy.sh
```

## 常用維運指令

```bash
# SSH 連線
ssh -i ../../ssh-key-2026-04-21.key ubuntu@161.33.130.101

# 查看後端日誌
journalctl -u sbom-backend -f

# 重啟後端
sudo systemctl restart sbom-backend

# 查看記憶體使用
free -h

# 查看磁碟使用
df -h
```
