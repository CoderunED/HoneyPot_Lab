# AWS Security Group Configuration

## Inbound Rules

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 22 | TCP | 0.0.0.0/0 | Cowrie honeypot (fake SSH) |
| 23 | TCP | 0.0.0.0/0 | Cowrie honeypot (fake Telnet) |
| 2222 | TCP | Your IP only | Real SSH admin access |

## Important Notes

- **Port 22** is redirected to Cowrie (running on 2222 internally)
- **Port 2222** is your real SSH access — restrict to your IP only
- Never expose your real SSH port to 0.0.0.0/0
- Use IAM roles for EC2 — no hardcoded AWS credentials

## iptables Redirect Command

```bash
# Redirect incoming port 22 to Cowrie on port 2222
sudo iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222

# Redirect incoming port 23 to Cowrie on port 2223
sudo iptables -t nat -A PREROUTING -p tcp --dport 23 -j REDIRECT --to-port 2223
```
