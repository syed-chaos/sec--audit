# 🛡️ SEC AUDIT — System Security Auditor

```
  _____ __   __ _____  _____  
 / ____|\\ \\ / /| | __ ||  __ \\ 
| (___   \\ V /  | | __ || |  | |
 \\___ \\   > <  | | __ || |  | |
 ____) | / .     | |__  ||__| |
|_____/ /_/      | |____||_____/ 

  ____  _   _    _    ___  ____  
 / ___|| | | |  / \\  / _ \\/ ___| 
| |    | |_| | / _ \\| | | \\___ \\ 
| |___ |  _  |/ ___ \\ |_| |___) |
 \\____||_| |_/_/   \\_\\___/|____/ 
```

> **Made by SYED._.CHAOS**  
> ⚠️ Use only on systems you own or have explicit permission to audit.

---

## 📌 What is this?

**SEC AUDIT** is a Python-based security auditing tool for **Kali Linux** and other Debian-based systems.  
It scans your own PC across 10 security categories and gives you a **score out of 100**, a grade, and a detailed list of **weak points with fix commands**.

---

## 🔍 What it checks

| # | Category | Max Score |
|---|----------|-----------|
| 1 | 🔥 Firewall Status | 10 |
| 2 | 🌐 Open / Risky Ports | 10 |
| 3 | 🔐 SSH Configuration | 15 |
| 4 | 👤 User Accounts | 10 |
| 5 | 📁 File Permissions (SUID/World-Writable) | 10 |
| 6 | 🔄 Pending System Updates | 15 |
| 7 | ⚙️ Running Services | 10 |
| 8 | 💽 Disk Encryption | 10 |
| 9 | 📋 Logging & Auditing | 10 |
| 10 | 🧠 Kernel Hardening (sysctl) | 10 |

---

## 💻 Requirements

| Requirement | Details |
|-------------|---------|
| OS | Kali Linux / Debian / Ubuntu |
| Python | 3.6 or higher |
| Privileges | Run as root (sudo) for full scan |
| Library | `pyfiglet` (for big banner) |

---

## 📦 Installation

**Step 1 — Clone the repository:**
```bash
git clone https://github.com/syed-chaos/sec-audit.git
cd sec-audit
```

**Step 2 — Install required library:**
```bash
pip install pyfiglet --break-system-packages
```

**Step 3 — Give execute permission:**
```bash
chmod +x security_auditor.py
```

---

## 🚀 Usage

```bash
sudo python3 security_auditor.py
```

> ⚠️ Always run with `sudo` for deeper and more accurate scan results.

---

## 📊 Sample Output

```
Overall Score:  [████████████████░░░░░░░░]  65/100
Grade:          C — Fair

Category Breakdown:
Firewall              7/10    ███████████████░░░░░  70%
Open Ports           10/10    ████████████████████  100%
SSH Security          5/15    ████░░░░░░░░░░░░░░░░  33%
...

⚠ Weak Points & Recommendations:
1. [Firewall]
   → UFW is not active — enable with: sudo ufw enable

2. [SSH Security]
   → Set 'PermitRootLogin no' in /etc/ssh/sshd_config
```

---

## 🔧 How to Fix Issues

### Fix Firewall
```bash
sudo ufw enable
```

### Fix SSH
```bash
sudo nano /etc/ssh/sshd_config
# Set: PermitRootLogin no
# Set: PasswordAuthentication no
# Set: Port 2222
sudo systemctl restart ssh
```

### Fix Kernel Hardening
```bash
sudo nano /etc/sysctl.conf
# Add:
# net.ipv4.ip_forward=0
# net.ipv4.conf.all.accept_redirects=0
# net.ipv4.tcp_syncookies=1
# kernel.randomize_va_space=2
# net.ipv4.conf.all.rp_filter=1
sudo sysctl -p
```

### Fix System Updates
```bash
sudo apt update && sudo apt upgrade -y
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes** and **authorized security auditing only**.  
Only run this tool on systems **you own** or have **explicit written permission** to test.  
The author is **not responsible** for any misuse or damage caused by this tool.

---

## 👤 Author

**SYED._.CHAOS**  
- GitHub: [@syed-chaos](https://github.com/syed-chaos)

---

## 📄 License

This project is licensed under the **MIT License** — free to use, modify, and distribute with credit.

```
MIT License
Copyright (c) 2025 SYED._.CHAOS
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software.
```
