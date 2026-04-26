# 🛡️ Sentinel-X
**Next-Generation Agentic DevSecOps & Vulnerability Reconnaissance Platform**

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)](https://sentinel-x-api.onrender.com)
[![Version](https://img.shields.io/badge/Version-2.0-blue?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Live-success?style=for-the-badge)](#)

> **Live Platform:** https://sentinel-x-swale.netlify.app/

---

## ⚡ Overview
Sentinel-X is an autonomous, agentic exploit engine designed to harden critical infrastructure. It seamlessly bridges the gap between offensive security testing and defensive remediation. By deploying targeted Python payloads from a centralized Node.js Command and Control (C2) server, Sentinel-X detects vulnerabilities in real-time and instantly generates production-ready remediation code.

It is equipped with **CypherVault**, an integrated AI Copilot powered by Google Gemini, designed to assist operators with real-time threat analysis and DevSecOps workflows.

---

## 🏗️ System Architecture
Sentinel-X utilizes a distributed cloud microservice architecture to ensure separation of concerns and high availability.

* **The Edge (Frontend):** Vanilla HTML/CSS/JS with a custom-built Terminal UI, deployed serverlessly via **Netlify**.
* **The C2 Server (Backend):** A custom **Node.js / Express** engine acting as the central nervous system, hosted on **Render**.
* **The Exploit Engine:** A subprocessized **Python 3** agent deployed dynamically by the C2 server for aggressive target reconnaissance.
* **The Vault (Database):** **Supabase (PostgreSQL)** handles persistent, secure telemetry and scan logging.
* **The Brain (AI):** **Google Gemini 2.5 Flash** integrated directly into the C2 core for intelligent copilot interactions.

---

## 🚀 Core Features
- **[+] Agentic Scanning:** Execute targeted reconnaissance directly from a web-based terminal emulator.
- **[+] Zero-Day Remediation:** Automatically generate secure, patch-ready code for identified vulnerabilities.
- **[+] CypherVault AI Copilot:** Context-aware AI assistant capable of deep educational security breakdowns.
- **[+] Tuned Security Shields:** Custom WAF middleware and strict CSP/CORS policies to prevent unauthorized path traversal and origin spoofing.
- **[+] Real-Time Telemetry:** Findings are instantly synced to a central PostgreSQL database for audit logging.

---

## 💻 Local Deployment
If you have been granted access to run this repository locally, follow these steps:

**1. Clone the Repository:**
```bash
git clone https://github.com/Swarup-Ingale/sentinel-x-core.git
cd sentinel-x-core/backend
```

**2. Install Engine Dependencies:**
```bash
npm install
pip install -r ../agent/requirements.txt
```

**3. Configure Environment:**
Create a .env file in the backend directory with the following keys:
```bash
SUPABASE_URL=your_supabase_url
SUPABASE_KEY=your_supabase_anon_key
GEMINI_API_KEY=your_gemini_api_key
PORT=8080
```

**4. Ignite the C2 Server:**
```bash
node server.js
```
The frontend can then be served locally via Live Server or by directly opening index.html.

---

# ⚖️ Legal & Copyright
© 2026 Sentinel-X Development Team. All Rights Reserved.

This repository and its contents are strictly proprietary. No license is granted for the reproduction, modification, distribution, or commercial use of this code.

This code is published publicly on GitHub solely for portfolio viewing and hackathon evaluation purposes. You may not copy, fork, adapt, or use any part of this software, its architecture, or its user interface for any personal or commercial projects without explicit, written permission from the creators.

---
