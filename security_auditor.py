#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║         SYSTEM SECURITY AUDITOR  v1.0               ║
║         For Kali Linux / Debian-based systems        ║
║         Use only on systems you own or have          ║
║         explicit permission to audit.                ║
╚══════════════════════════════════════════════════════╝
"""

import os
import subprocess
import socket
import platform
import pwd
import grp
import stat
import re
import sys
from datetime import datetime

# ─── COLORS ────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"
WHITE  = "\033[97m"
MAGENTA= "\033[95m"

def banner():
    print(f"""
{CYAN}{BOLD}
 ███████╗███████╗ ██████╗    █████╗ ██╗   ██╗██████╗ ██╗████████╗
 ██╔════╝██╔════╝██╔════╝   ██╔══██╗██║   ██║██╔══██╗██║╚══██╔══╝
 ███████╗█████╗  ██║        ███████║██║   ██║██║  ██║██║   ██║   
 ╚════██║██╔══╝  ██║        ██╔══██║██║   ██║██║  ██║██║   ██║   
 ███████║███████╗╚██████╗   ██║  ██║╚██████╔╝██████╔╝██║   ██║   
 ╚══════╝╚══════╝ ╚═════╝   ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═╝   ╚═╝  
{RESET}
{WHITE}        System Security Auditor — Rates your PC out of 100{RESET}
{YELLOW}  ⚠  Use only on systems you own or have permission to scan ⚠{RESET}
""")

def run(cmd):
    """Run a shell command and return output."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        return result.stdout.strip()
    except Exception:
        return ""

def section(title):
    print(f"\n{CYAN}{BOLD}{'─'*55}")
    print(f"  🔍 {title}")
    print(f"{'─'*55}{RESET}")

def ok(msg):
    print(f"  {GREEN}[✔] {msg}{RESET}")

def warn(msg):
    print(f"  {YELLOW}[⚠] {msg}{RESET}")

def fail(msg):
    print(f"  {RED}[✘] {msg}{RESET}")

def info(msg):
    print(f"  {WHITE}[i] {msg}{RESET}")

# ─── CHECKS ─────────────────────────────────────────────

results = []   # (category, score_earned, max_score, issues[])

def add_result(category, earned, maximum, issues):
    results.append({
        "category": category,
        "earned": earned,
        "maximum": maximum,
        "issues": issues
    })

# 1. FIREWALL
def check_firewall():
    section("Firewall Status")
    issues = []
    score = 0

    ufw = run("ufw status 2>/dev/null")
    iptables = run("iptables -L -n 2>/dev/null | head -20")

    if "active" in ufw.lower():
        ok("UFW firewall is ACTIVE")
        score += 10
    elif iptables and "ACCEPT" in iptables:
        warn("UFW not found, but iptables rules detected")
        score += 5
        issues.append("UFW is not active — consider enabling it with: sudo ufw enable")
    else:
        fail("No active firewall detected!")
        issues.append("No firewall is running — run: sudo ufw enable")

    nftables = run("nft list ruleset 2>/dev/null | wc -l")
    if nftables and int(nftables) > 5:
        ok("nftables rules detected")
        score = min(score + 2, 10)

    add_result("Firewall", score, 10, issues)

# 2. OPEN PORTS
def check_open_ports():
    section("Open Ports & Services")
    issues = []
    score = 10

    risky_ports = {
        21: "FTP (unencrypted)",
        23: "Telnet (unencrypted)",
        25: "SMTP",
        110: "POP3",
        135: "RPC",
        139: "NetBIOS",
        445: "SMB",
        512: "rexec",
        513: "rlogin",
        514: "rsh",
        3389: "RDP",
        5900: "VNC",
    }

    open_ports_raw = run("ss -tuln 2>/dev/null || netstat -tuln 2>/dev/null")
    open_ports = []

    for line in open_ports_raw.splitlines():
        match = re.search(r':(\d{2,5})\s', line)
        if match:
            port = int(match.group(1))
            if port not in open_ports:
                open_ports.append(port)

    found_risky = []
    for port, service in risky_ports.items():
        if port in open_ports:
            fail(f"Risky port open: {port} ({service})")
            found_risky.append(port)
            score -= 2
            issues.append(f"Port {port} ({service}) is open — disable if not needed")

    if not found_risky:
        ok("No common risky ports detected")
    else:
        info(f"Total open ports found: {len(open_ports)}")

    if len(open_ports) > 15:
        warn(f"Many open ports: {len(open_ports)} — minimize attack surface")
        issues.append(f"{len(open_ports)} open ports detected — close unused ones")
        score -= 2

    score = max(score, 0)
    add_result("Open Ports", score, 10, issues)

# 3. SSH SECURITY
def check_ssh():
    section("SSH Configuration")
    issues = []
    score = 0
    max_score = 15

    ssh_config = ""
    for path in ["/etc/ssh/sshd_config", "/etc/ssh/ssh_config"]:
        if os.path.exists(path):
            with open(path, "r") as f:
                ssh_config = f.read()
            break

    if not ssh_config:
        warn("SSH config not found — SSH may not be installed")
        add_result("SSH Security", 10, max_score, ["SSH config not found"])
        return

    # Root login
    if re.search(r'^\s*PermitRootLogin\s+no', ssh_config, re.MULTILINE):
        ok("Root login via SSH is disabled")
        score += 5
    else:
        fail("Root login via SSH may be enabled!")
        issues.append("Set 'PermitRootLogin no' in /etc/ssh/sshd_config")

    # Password auth
    if re.search(r'^\s*PasswordAuthentication\s+no', ssh_config, re.MULTILINE):
        ok("SSH password authentication is disabled (key-only)")
        score += 5
    else:
        warn("SSH password authentication is enabled")
        issues.append("Consider disabling PasswordAuthentication and using SSH keys")
        score += 2

    # Protocol version
    if re.search(r'^\s*Protocol\s+1', ssh_config, re.MULTILINE):
        fail("SSH Protocol 1 is in use (insecure!)")
        issues.append("Disable SSH Protocol 1 — it is vulnerable")
    else:
        ok("SSH Protocol 1 not detected")
        score += 3

    # Port
    port_match = re.search(r'^\s*Port\s+(\d+)', ssh_config, re.MULTILINE)
    if port_match and port_match.group(1) != "22":
        ok(f"SSH running on non-default port {port_match.group(1)}")
        score += 2
    else:
        warn("SSH is on default port 22 — consider changing it")
        issues.append("Change SSH port from 22 to a non-standard port")

    add_result("SSH Security", min(score, max_score), max_score, issues)

# 4. USER ACCOUNTS
def check_users():
    section("User Accounts")
    issues = []
    score = 10

    # Check for users with empty passwords
    empty_pass = run("awk -F: '($2==\"\" || $2==\"!\") && $1!=\"nobody\"' /etc/shadow 2>/dev/null")
    if empty_pass:
        fail(f"Users with empty/locked passwords: {empty_pass}")
        issues.append("Some users have empty passwords — set strong passwords")
        score -= 3

    # UID 0 users (root privileges)
    uid0 = run("awk -F: '($3==0){print $1}' /etc/passwd")
    uid0_users = [u for u in uid0.splitlines() if u != "root"]
    if uid0_users:
        fail(f"Non-root users with UID 0: {', '.join(uid0_users)}")
        issues.append(f"Users with UID 0 (root-level access): {uid0_users}")
        score -= 4
    else:
        ok("No non-root users with UID 0")

    # Check /etc/passwd for suspicious shells
    passwd_lines = run("cat /etc/passwd")
    suspicious = []
    for line in passwd_lines.splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[6] in ["/bin/sh", "/bin/bash"] and parts[2] not in ["0"]:
            try:
                uid = int(parts[2])
                if uid >= 1000:
                    suspicious.append(parts[0])
            except:
                pass

    if suspicious:
        info(f"Human users with shell access: {', '.join(suspicious)}")
    else:
        ok("User account list looks clean")

    # Guest account
    guest = run("id guest 2>/dev/null")
    if guest:
        warn("Guest account exists")
        issues.append("Guest account found — disable if not needed")
        score -= 1

    score = max(score, 0)
    add_result("User Accounts", score, 10, issues)

# 5. FILE PERMISSIONS
def check_permissions():
    section("File Permissions (SUID/SGID/World-Writable)")
    issues = []
    score = 10

    # SUID files
    suid = run("find / -perm -4000 -type f 2>/dev/null | grep -v proc | head -30")
    suid_list = suid.splitlines() if suid else []
    known_safe_suid = ["/usr/bin/sudo", "/usr/bin/passwd", "/usr/bin/su",
                       "/usr/bin/newgrp", "/usr/bin/chsh", "/usr/bin/chfn",
                       "/usr/bin/gpasswd", "/bin/mount", "/bin/umount",
                       "/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign"]
    unusual_suid = [f for f in suid_list if f not in known_safe_suid]

    if unusual_suid:
        warn(f"Unusual SUID files found: {len(unusual_suid)}")
        for f in unusual_suid[:5]:
            fail(f"  SUID: {f}")
        issues.append(f"{len(unusual_suid)} unusual SUID files found — review them")
        score -= min(len(unusual_suid), 4)
    else:
        ok("No unusual SUID files found")

    # World-writable directories (excluding /tmp, /var/tmp)
    world_write = run("find / -xdev -type d -perm -o+w 2>/dev/null | grep -v '^/tmp' | grep -v '^/var/tmp' | grep -v proc | head -10")
    ww_list = [x for x in world_write.splitlines() if x]
    if ww_list:
        warn(f"World-writable directories: {len(ww_list)}")
        for d in ww_list[:3]:
            warn(f"  {d}")
        issues.append(f"{len(ww_list)} world-writable directories (excluding /tmp)")
        score -= min(len(ww_list), 3)
    else:
        ok("No unexpected world-writable directories")

    score = max(score, 0)
    add_result("File Permissions", score, 10, issues)

# 6. UPDATES
def check_updates():
    section("System Updates")
    issues = []
    score = 0

    updates = run("apt list --upgradable 2>/dev/null | grep -v Listing | wc -l")
    try:
        count = int(updates)
    except:
        count = -1

    if count == 0:
        ok("System is fully up to date!")
        score = 15
    elif count > 0 and count <= 10:
        warn(f"{count} package(s) need updating")
        issues.append(f"{count} updates pending — run: sudo apt upgrade")
        score = 10
    elif count > 10 and count <= 50:
        warn(f"{count} packages need updating")
        issues.append(f"{count} updates pending — system is out of date")
        score = 5
    elif count > 50:
        fail(f"{count} packages need updating — system is very out of date!")
        issues.append(f"Critical: {count} updates pending — run: sudo apt update && sudo apt upgrade")
        score = 0
    else:
        info("Could not check updates (apt not available or needs refresh)")
        score = 8

    add_result("System Updates", score, 15, issues)

# 7. SERVICES
def check_services():
    section("Running Services")
    issues = []
    score = 10

    risky_services = {
        "telnet": "Telnet (unencrypted remote access)",
        "rsh": "RSH (insecure remote shell)",
        "rlogin": "RLogin (insecure)",
        "vsftpd": "FTP server",
        "ftp": "FTP",
        "finger": "Finger daemon",
        "rpcbind": "RPC Bind",
    }

    active_services = run("systemctl list-units --type=service --state=running 2>/dev/null")

    found_risky = []
    for svc, desc in risky_services.items():
        if svc in active_services.lower():
            fail(f"Risky service running: {svc} ({desc})")
            found_risky.append(svc)
            score -= 2
            issues.append(f"Disable {svc}: sudo systemctl disable --now {svc}")

    if not found_risky:
        ok("No obviously risky services running")

    add_result("Running Services", max(score, 0), 10, issues)

# 8. DISK ENCRYPTION
def check_encryption():
    section("Disk Encryption")
    issues = []
    score = 0

    luks = run("lsblk -o name,type,fstype 2>/dev/null | grep -i crypt")
    dm_crypt = run("dmsetup ls --target crypt 2>/dev/null")

    if luks or dm_crypt:
        ok("LUKS/dm-crypt encryption detected on disk(s)")
        score = 10
    else:
        warn("No disk encryption detected")
        issues.append("Consider encrypting your disk with LUKS for data protection")
        score = 3

    add_result("Disk Encryption", score, 10, issues)

# 9. LOGS & AUDIT
def check_logs():
    section("Logging & Auditing")
    issues = []
    score = 0

    # syslog / rsyslog
    syslog = run("systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog 2>/dev/null")
    if "active" in syslog:
        ok("System logging (rsyslog) is active")
        score += 5
    else:
        warn("rsyslog/syslog not running")
        issues.append("Enable system logging: sudo systemctl enable --now rsyslog")

    # auditd
    auditd = run("systemctl is-active auditd 2>/dev/null")
    if "active" in auditd:
        ok("Audit daemon (auditd) is active")
        score += 5
    else:
        warn("auditd is not running")
        issues.append("Consider enabling auditd for detailed security auditing")

    add_result("Logging & Auditing", score, 10, issues)

# 10. KERNEL & SYSCTL HARDENING
def check_kernel():
    section("Kernel Hardening (sysctl)")
    issues = []
    score = 0
    max_score = 10

    checks = {
        "net.ipv4.ip_forward": ("0", "IP forwarding is disabled"),
        "net.ipv4.conf.all.accept_redirects": ("0", "ICMP redirects ignored"),
        "net.ipv4.tcp_syncookies": ("1", "SYN flood protection enabled"),
        "kernel.randomize_va_space": ("2", "ASLR fully enabled"),
        "net.ipv4.conf.all.rp_filter": ("1", "Reverse path filtering on"),
    }

    per_check = max_score // len(checks)

    for key, (expected, label) in checks.items():
        val = run(f"sysctl -n {key} 2>/dev/null").strip()
        if val == expected:
            ok(f"{label}")
            score += per_check
        else:
            warn(f"{label} — NOT set (current: {val or 'unknown'})")
            issues.append(f"Set {key}={expected} in /etc/sysctl.conf")

    add_result("Kernel Hardening", min(score, max_score), max_score, issues)

# ─── SCORE DISPLAY ───────────────────────────────────────

def display_report():
    total_earned = sum(r["earned"] for r in results)
    total_max    = sum(r["maximum"] for r in results)
    final_score  = round((total_earned / total_max) * 100) if total_max else 0

    # Grade
    if final_score >= 85:
        grade = f"{GREEN}A — Excellent{RESET}"
        bar_color = GREEN
    elif final_score >= 70:
        grade = f"{CYAN}B — Good{RESET}"
        bar_color = CYAN
    elif final_score >= 50:
        grade = f"{YELLOW}C — Fair{RESET}"
        bar_color = YELLOW
    elif final_score >= 30:
        grade = f"{MAGENTA}D — Poor{RESET}"
        bar_color = MAGENTA
    else:
        grade = f"{RED}F — Critical{RESET}"
        bar_color = RED

    bar_len = 40
    filled = int((final_score / 100) * bar_len)
    bar = bar_color + "█" * filled + RESET + "░" * (bar_len - filled)

    print(f"\n{BOLD}{CYAN}{'═'*55}")
    print(f"  📊  SECURITY AUDIT REPORT")
    print(f"{'═'*55}{RESET}")
    print(f"\n  {BOLD}Overall Score:{RESET}  [{bar}]  {BOLD}{bar_color}{final_score}/100{RESET}")
    print(f"  {BOLD}Grade:{RESET}          {grade}")
    print(f"  {BOLD}Scanned:{RESET}        {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  {BOLD}Hostname:{RESET}       {socket.gethostname()}")
    print(f"  {BOLD}OS:{RESET}             {platform.platform()}")

    print(f"\n{CYAN}{BOLD}  📋 Category Breakdown:{RESET}")
    print(f"  {'Category':<22} {'Score':>6}   {'Bar'}")
    print(f"  {'─'*22}  {'─'*6}   {'─'*20}")
    for r in results:
        pct = round((r["earned"] / r["maximum"]) * 100) if r["maximum"] else 0
        mini_fill = int((pct / 100) * 20)
        if pct >= 80:   mc = GREEN
        elif pct >= 50: mc = YELLOW
        else:           mc = RED
        mini_bar = mc + "█" * mini_fill + RESET + "░" * (20 - mini_fill)
        print(f"  {r['category']:<22} {r['earned']:>2}/{r['maximum']:<3}   {mini_bar} {pct}%")

    # Weak points
    all_issues = []
    for r in results:
        for issue in r["issues"]:
            all_issues.append((r["category"], issue))

    if all_issues:
        print(f"\n{RED}{BOLD}  ⚠  Weak Points & Recommendations:{RESET}")
        for i, (cat, issue) in enumerate(all_issues, 1):
            print(f"\n  {RED}{BOLD}{i}. [{cat}]{RESET}")
            print(f"     {YELLOW}→ {issue}{RESET}")
    else:
        print(f"\n  {GREEN}{BOLD}🎉 No major issues found! System is well-hardened.{RESET}")

    print(f"\n{CYAN}{'═'*55}{RESET}")
    print(f"  {WHITE}Tip: Run as root (sudo) for deeper scan access.{RESET}")
    print(f"{CYAN}{'═'*55}{RESET}\n")

# ─── MAIN ────────────────────────────────────────────────

def main():
    banner()
    print(f"  {WHITE}Starting security audit... this may take a minute.{RESET}\n")

    check_firewall()
    check_open_ports()
    check_ssh()
    check_users()
    check_permissions()
    check_updates()
    check_services()
    check_encryption()
    check_logs()
    check_kernel()

    display_report()

if __name__ == "__main__":
    main()
