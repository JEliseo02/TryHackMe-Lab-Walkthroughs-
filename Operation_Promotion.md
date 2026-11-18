# Operation Promotion — Penetration Test Report
 
**Engagement:** Solo assessment of RecruitCorp (Hadron Security promotion engagement)
**Assessor:** Jack
**Date:** 2026-11-17
**Target:** RecruitCorp public-facing careers portal (`recruitcorp`)
**Classification:** Confidential
 
> **Lab note:** This is a TryHackMe lab. Target and attacker IP addresses rotate between sessions; commands below show the IP active at the time of each step. Where one host is meant generically, it is the RecruitCorp server.
 
---
 
## 1. Executive Summary
 
RecruitCorp's host was assessed from the perspective of an unauthenticated external attacker. Full compromise (**root**) was achieved by chaining a weak admin login, an OS command injection in an internal maintenance endpoint, a leaked password hash in a web-readable config file, and an over-permissive `sudo` rule.
 
The attack path was:
 
> **Admin login bypass → OS command injection (shell as www-data) → leaked bcrypt hash in config → crack → SSH as jford → sudo `find` → root**
 
The root cause is a chain of small failures that individually look minor but together give complete compromise: an admin panel reachable with trivial credentials, user input passed unsanitised to a shell, a secret committed to a readable config file, and a low-privileged user granted passwordless `sudo` to a binary that can spawn a shell. Any single fix would have broken the chain.
 
### Severity Summary
 
| # | Finding | Severity |
|---|---------|----------|
| 1 | OS command injection in maintenance endpoint | Critical |
| 2 | Passwordless `sudo` on `find` → privilege escalation | Critical |
| 3 | Credential (bcrypt hash) leaked in web-readable config | High |
| 4 | Weak, pattern-based password (`spring2026!`) | High |
| 5 | Weak admin authentication / information disclosure | Medium |
 
---
 
## 2. Scope & Methodology
 
**In scope:** The RecruitCorp host (TCP 22, 80, 139, 445) and the web application served on it. Objectives: capture `user.txt` and `flag.txt`.

**Methodology:** Standard black-box progression — reconnaissance, enumeration, exploitation, post-exploitation, privilege escalation — aligned to PTES/OWASP. Findings are presented in discovery order; dead ends are documented in Section 6 because ruling them out was part of the engagement.
 
**Tooling:** `nmap`, `gobuster`, `curl`, `smbclient`, `nxc`, `sqlmap`, `sqlite3`, `nc`, `john`, GTFOBins.
 
---
 
## 3. Reconnaissance & Enumeration
 
### 3.1 Port scan
```bash
nmap -sC -sV -p- <target> -oN nmap-full.txt
```
 
| Port | Service |
|------|---------|
| 22/tcp | OpenSSH 9.6p1 (Ubuntu) |
| 80/tcp | Apache 2.4.58 — "RecruitCorp - Careers Portal" |
| 139/445 | Samba smbd 4.6.2 |
 
`robots.txt` disclosed a `Disallow: /admin/` entry.
 
### 3.2 Content discovery
```bash
gobuster dir -u http://<target> -w .../directory-list-2.3-medium.txt -x php,html,js,txt
```
Notable: `/admin/` (301), `/config` (**403**), `/index.php`, `/robots.txt`. The 403 on `/config` was noted as "exists but blocked" — relevant later.
 
### 3.3 SMB
```bash
smbclient -L //<target>/ -N
```
A `public` share was readable via null session but contained only a placeholder `README.txt`, and was not writable. SMB was not the entry vector.
 
---
 
## 4. Initial Access
 
### Finding 5 — Weak Admin Authentication (Medium)
 
The admin login at `/admin/` was bypassed with a classic auth-bypass string:
```
username: admin' OR 1=1-- -
password: anything
```
This granted an authenticated admin session (`PHPSESSID` cookie). Source review later confirmed the login query is built by string concatenation against a SQLite database:
```php
$query = "SELECT id, username FROM users WHERE username='$u' AND password='$p'";
```
 
The admin dashboard exposed a **User Lookup** (`/admin/users/lookup.php?id=`) and, via a user record (ID 7), disclosed a sensitive internal detail:
> `sysmaint` — "Service account for /admin/sysmaint-checks/ping.php. Do not disable."
 
**Remediation.** Use parameterised queries; enforce strong admin credentials and MFA; do not expose internal service-account notes in the UI.

