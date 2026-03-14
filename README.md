# 🛡️ CyberShield — SOC Analyst Threat Intelligence Dashboard

A comprehensive **Security Operations Center (SOC) Dashboard** built to demonstrate proficiency in threat hunting, OSINT analysis, incident response, and cyber defense — using only free APIs and tools.

![Dashboard Preview](https://img.shields.io/badge/Status-Live-brightgreen) ![Node.js](https://img.shields.io/badge/Node.js-22+-green) ![License](https://img.shields.io/badge/License-ISC-blue)

---

## 🔍 Features

| Module | Capabilities | APIs Used |
|---|---|---|
| **Threat Hunter** | IOC investigation (IP, domain, hash, URL) | VirusTotal v3, AbuseIPDB v2 |
| **OSINT Tools** | IP geolocation, URL scanning, bulk IOC analysis | ipinfo.io, URLhaus |
| **Incident Response** | Create, track, and manage security incidents | Local storage |
| **Cyber Defense** | CVE vulnerability search, MITRE ATT&CK browser | NIST NVD v2, MITRE ATT&CK |
| **Threat Intel Feed** | Live threat intelligence pulse monitoring | AlienVault OTX v2 |
| **Dashboard** | Aggregated stats, threat gauge, activity timeline | — |

## 🔒 Security Architecture

This project demonstrates **defense-in-depth** and **security-first design**:

- **Server-side API proxy** — API keys stored in `.env`, never exposed to the browser
- **Helmet.js** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **Rate limiting** — 100 req/min global, 20 req/min per API route
- **SSRF protection** — Private/internal IP ranges blocked at proxy layer
- **Input validation** — All user inputs validated server-side before forwarding
- **Request timeouts** — AbortController prevents hung connections
- **XSS protection** — All user-facing content escaped via `textContent`/`escapeHtml`
- **Audit logging** — Every API call logged with timestamp, IP, and action

```
Browser ──→ Express Proxy (server.js) ──→ External APIs
               ↑                              ↑
          Keys from .env              VirusTotal, AbuseIPDB,
          (never sent                 ipinfo.io, URLhaus,
           to client)                 NIST NVD, AlienVault OTX
```

## 🚀 Quick Start

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cybershield-soc-dashboard.git
cd cybershield-soc-dashboard

# Configure API keys
cp .env.example .env
# Edit .env and add your free API keys

# Install dependencies & start
npm install
npm start

# Note: If `npm start` fails on Windows due to PowerShell execution policies,
# you can either double-click the `start.bat` file or run:
# node server.js

# Open http://localhost:3000
```

## 🔑 Getting API Keys (All Free)

| Service | Sign Up | Free Tier |
|---|---|---|
| [VirusTotal](https://www.virustotal.com/gui/join-us) | Email registration | 500 lookups/day |
| [AbuseIPDB](https://www.abuseipdb.com/register) | Email registration | 1000 checks/day |
| [ipinfo.io](https://ipinfo.io/signup) | Email registration | 50,000 req/month |
| [AlienVault OTX](https://otx.alienvault.com/api) | Email registration | Unlimited |
| URLhaus | No key needed | Unlimited |
| NIST NVD | No key needed | Rate limited |

## 🛠️ Tech Stack

- **Frontend**: Vanilla HTML, CSS, JavaScript (no frameworks)
- **Backend**: Node.js + Express.js
- **Security**: Helmet, express-rate-limit, CORS, CSP
- **Design**: Dark cybersecurity theme with glassmorphism
- **Storage**: localStorage for incidents, search history, bookmarks

## 📁 Project Structure

```
soc-dashboard/
├── server.js           # Hardened Express proxy server
├── .env.example        # API key template
├── render.yaml         # Render.com deployment config
├── index.html          # SPA shell
├── css/index.css       # Dark cyber theme
└── js/
    ├── app.js          # Core: navigation, utilities
    ├── dashboard.js    # Stats & activity timeline
    ├── threat-hunter.js # VT + AbuseIPDB analysis
    ├── osint.js        # GeoIP, URLhaus, bulk scanner
    ├── incident.js     # Incident CRUD tracker
    ├── cyber-defense.js # CVE + MITRE ATT&CK
    └── threat-feed.js  # AlienVault OTX feed
```

## 🌐 Deploy to Render (Free)

1. Push this repo to GitHub
2. Go to [render.com](https://render.com) → New → Web Service
3. Connect your GitHub repo
4. Render auto-detects `render.yaml`
5. Add your API keys in Environment Variables
6. Deploy!

## 📜 License

ISC

---

> Built as a portfolio project to demonstrate SOC analyst proficiency in threat intelligence, OSINT, and incident response.
