# Operation Promotion - TryHackMe Walkthrough

## Machine Information

| Category         | Value                      |
| ---------------- | -------------------------- |
| Platform         | TryHackMe                  |
| Room Name        | Operation Promotion        |
| Difficulty       | Easy                       |
| Operating System | Linux                      |
| Objective        | Obtain User and Root Flags |

---

# Scenario

You are up for promotion at Hadron Security. Your senior lead, Mara, has handed you a solo engagement against RecruitCorp, a small recruiting firm with a public-facing portal.

Your objective is to:

* Enumerate the target
* Gain initial access
* Escalate privileges
* Capture both flags

Target IP:

```text
10.49.137.12
```

---

# Reconnaissance

## Initial Nmap Scan

We begin with a full TCP port scan.

```bash
nmap -p- --min-rate 5000 -T4 10.49.137.12
```

### Results

```text
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

Interesting.

The target exposes:

* SSH
* HTTP
* SMB
