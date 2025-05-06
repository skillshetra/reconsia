<div align="center">
  <img src="https://via.placeholder.com/1000x200.png?text=Reconsia" alt="Reconsia Banner" />
  <h1>🔎 Reconsia</h1>
  <p><strong>Recon made simple.</strong><br/>Domain insights, subdomain mapping, HTTP fingerprinting & archived web history — all in one sleek API.</p>
  <br/>
  <img src="https://img.shields.io/badge/status-active-brightgreen?style=flat-square" />
  <img src="https://img.shields.io/badge/build-passing-blue?style=flat-square" />
  <img src="https://img.shields.io/badge/license-MIT-lightgrey?style=flat-square" />
  <img src="https://img.shields.io/badge/made%20with-node.js-green?style=flat-square" />
</div>

---

## ✨ Overview

**Reconsia** is a lightweight yet powerful open-source reconnaissance API built with Node.js. It gathers detailed information about domains, subdomains, and their infrastructure in real time using a combination of WHOIS, certificate transparency logs, DNS, HTTP headers, and web archival data.

Think of it as your personal passive recon toolkit — programmatic, fast, and ready for integration into security pipelines, dashboards, or browser extensions.

---

## ⚙️ Features at a Glance

| Capability                     | Description                                                                 |
|-------------------------------|-----------------------------------------------------------------------------|
| 🧾 WHOIS Lookup                | Get registrar data, creation/expiry dates, name servers, abuse contacts     |
| 🌍 Subdomain Enumeration       | Discovers subdomains via `crt.sh` certificate logs                          |
| 📡 HTTP Metadata              | Retrieves title, content type, IP, server header, status code               |
| 🕰️ Web Archive Integration    | Extracts historical snapshots via the Wayback Machine                       |
| 💡 Minimal API Interface       | One endpoint, zero friction — `/` with a single `q` parameter               |

---

## 📦 Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/skillshetra/reconsia.git
cd reconsia
npm install