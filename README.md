<div align="center">
  <picture>
    <img width="400" height="400" alt="Holehe Screenshot" src="https://github.com/user-attachments/assets/f2d73208-e697-4e25-8543-940077e2a8ac" />
  </picture>
</div>

<p align="center">
  |
  <a href="https://t.me/tracetheleak_cybertechsecuriry">📚 <strong>CanalCyberx2</strong></a> |
  <a href="https://medium.com/@tracetheleak_securityOfficial">📊 <strong>Medium</strong></a> |
  <a href="https://t.me/tracetheleakofficial">🎮 <strong>Telegram</strong></a> |
  <a href="https://x.com/tracetheleak">🐦 <strong>X (Twitter)</strong></a> |
</p>

# Tool Spotlight – Holehe

**Holehe** It is an advanced OSINT tool to find out which online services are connected to an email address.  
Perfect for **security research, breach assessment and preemptive analysis**.

---

## Use Cases

- Check which accounts are exposed for an email
- Map possible attachment surfaces for penetration testing
- Prevent **credential stuffing attacks** and violations
- Support audits and red/blue team analysis

---

## Features

- Supports dozens of online services (Google, GitHub, Instagram, Twitter, and many more)
- Returns clean and readable results
- Easily integrated into automated OSINT workflows
- Open-source, upgradeable and customizable

---

## Quick Start

### Requirements
- Python 3.10+
- pip install:

```bash
python3 holehe_advanced.py -e target@example.com
```
## specify a custom services file 
```bash
python3 holehe_advanced.py -e target@example.com -s services.json
```
## output in json
```bash
python3 holehe_advanced.py -e target@example.com -o risultati_target.json
```
## use of proxies (brurp suite/owasp zap) 
```bash
python3 holehe_advanced.py -e target@example.com --proxy http://127.0.0.1:8080 --no-verify-ssl -v
```

