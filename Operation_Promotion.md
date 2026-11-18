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
