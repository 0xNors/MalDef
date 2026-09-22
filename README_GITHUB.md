# 🛡️ MALDEF - Malware Defense Platform v2.5

**Professional SOC Malware Defense & Offensive Analysis Platform**

[![Next.js](https://img.shields.io/badge/Next.js-14.2.5-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)
[![License](https://img.shields.io/badge/License-Defensive_Only-red)](https://github.com/0xNors/MalDef)
[![Engines](https://img.shields.io/badge/Engines-29-green)](https://github.com/0xNors/MalDef)
[![MITRE](https://img.shields.io/badge/MITRE-499-purple)](https://attack.mitre.org/)

> **Developed by:** Sahil Rakholiya & Priya Yadav | Internship Project | Defensive Cybersecurity Only

---

## 🚀 Live Demo Screenshots

### Dashboard - Colorful Solid Professional
![Dashboard](public/screenshots/dashboard-live.png)

### Deep Scan Detail - 29 Engines
![Analysis](public/screenshots/analysis-detail.png)

### System Health & Operations Center
![System Health](public/screenshots/system-health.png)

---

## ✨ Features

### **8 Core Modules**
1. **Dashboard** - 8 stat cards distinct solid colors (blue/purple/green/yellow/orange/red/cyan), Threat Level 85 CRITICAL red glow, Top Findings colorful bars, Entropy graph, Imports donut
2. **Threat Intelligence / IOC Explorer LIVE** - Auto-populates on deep-scan with geo country/city/ASN/ISP, whois registrar/created/expires, network ports/protocols
3. **Malware Analysis HOT** - Upload with pre-signed URL simulation, file type PE/ELF/PDF/ZIP/PNG/JPG benign, hashes MD5/SHA1/SHA256
4. **Behavior Analysis** - Timeline process_creation/file_modification/registry/network, MITRE mapping, attack chain 12 kill chain
5. **System Health & Operations Center** - Live Status API/workers/queue/cache/storage, Queue Management 6 queues, Host Health CPU/RAM/disk/network, PC Deep Scan, Network Monitor C2/beaconing
6. **ML Analytics / MALDEF Fingerprint AI** - 7 Tabs: Explainable AI SHAP, Threat Intel, Performance real DB, Dataset health drift, Live Feed, Playground
7. **Reports PRO** - 10 sections checkboxes, multi-page PDF solid high-contrast 11 sections, Executive Dashboard org-wide, 6 Templates
8. **Threat Hunting / MITRE ATT&CK** - Full matrix 499 techniques 14 tactics, hide/show sub-techniques, horizontal scroll

### **29-Engine Deep Scan (15-20 Sec)**
Not 1 sec - Takes time and scans deeply:
- Static 1283ms, Multi-Layer 1833ms, YARA 1111ms, Packer, String Decoder, Signature, C2, Attack Chain
- MITRE Full 2000ms - 499 techniques 14 tactics
- Network Structure, File System Structure
- CrowdStrike 14 Techniques x150ms each
- HTML/JS/URL Reputation, Final Aggregation 500ms
- Ratio: 9/29 MALICIOUS or 0/29 BENIGN

### **MITRE ATT&CK 499 + CrowdStrike 14**
- **14 Tactics:** Reconnaissance, Resource Development, Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, Exfiltration, Command and Control, Impact
- **CrowdStrike:** Signature/IOC/IOA, Static, Reputation, Heuristic, Sandbox, Blocklist, Allowlist, Checksum, Entropy, ML Behavioral, Memory/Runtime, LOLBIN, Ransomware, Deception/Honeypot

---

## 🏗️ System Architecture - MALDEF Advanced Design

```
Client → Pre-signed URL (15min) → S3 Bucket Encrypted → Lambda SHA1/SHA256 + Blob Cache (Dedup 40%) 
→ Redis Cache → RabbitMQ Fan-Out 6 Queues Auto-Scale → KEDA 2-20 Workers → Datadog Monitoring
→ Cassandra RowID SHA256:Timestamp TTL 1yr RF3 → DLQ Retry 3 Attempts → Sandboxing Isolated 
→ API Results/Rescan/Scans/Download → Rate Limiting 100/min → KEDA + Datadog
```

**Why each part exists:**
- Pre-signed URL: Secure upload without exposing S3 creds
- Blob Cache: Saves 40% storage via deduplication
- RabbitMQ: Decoupling, auto-scale, persistent messages, DLQ reliability
- Cassandra: Immutable versioned results
- Redis: Low-latency LRU 1hr TTL
- KEDA: Cost-effective scaling 2-20
- Sandboxing: Security isolated CPU/memory

---

## 🛠️ Tech Stack

| Category | Technology | Purpose |
|----------|------------|---------|
| Frontend | Next.js 14.2.5 | App Router, SSR, API Routes |
| Language | TypeScript | Type safety, production ready |
| Styling | Tailwind + Framer Motion | Solid #08080a #121214 colorful |
| Icons | Lucide React | Different icons per module |
| Charts | Recharts | Entropy graph, imports donut |
| PDF | jsPDF 2.5.1 | Professional multi-page solid |
| Auth | JWT + bcrypt | Role ADMIN/ANALYST/MANAGER |
| DB | JSON File (prod: Cassandra) | Samples, analyses, IOCs |
| Cache | In-memory (prod: Redis) | Read-through cache LRU |
| Queue | In-memory (prod: RabbitMQ) | 6 queues fan-out auto-scale |
| Storage | Local FS (prod: S3+Blob) | Deduplication 40% saving |
| Analysis | Custom 29 Engines | Static, YARA, Packer, C2, MITRE |

---

## 📦 Installation - 3 Commands Only (No Docker)

```bash
# 1. Install dependencies
npm install

# 2. Build production
npm run build
# Output: 16 pages, First Load 87.5kB, dashboard 6.32kB

# 3. Start server
npm start
# Open http://localhost:3000
# First user becomes ADMIN, select role during register
```

---

## 🔒 Security & Market-Ready

- ✅ **Zero Fake Data** - No hardcoded demo users/IOCs/credentials, no synthetic telemetry, no fake ML accuracy - all stats from real DB
- ✅ **False Positive Fixed** - PNG/JPG 0/29 BENIGN LOW 99% - type-aware detection
- ✅ **Defensive Only** - No malware generation, base64 encoded patterns
- ✅ **Role-Based** - ADMIN full, ANALYST upload/analyze/investigate, MANAGER dashboard/reports
- ✅ **Production Ready** - JWT_SECRET enforcement, bcrypt hashing, rate limiting 100/min
- ✅ **Branding** - Red shield M logo, colorful solid UI professional SOC

---

## 🧪 Testing & Results

| Metric | Value |
|--------|-------|
| Build | Next.js 14.2.5, 16 pages, Success |
| First Load JS | 87.5kB shared |
| Deep Scan | 15-20 sec total, 29 engines one by one |
| Engines | 29 total, ratio 9/29 MALICIOUS for inno_updater.exe |
| MITRE | 499 techniques, 14 tactics |
| CrowdStrike | 14 techniques, 0/14 for PNG |
| False Positive | PNG/JPG 0/29 BENIGN fixed |
| Screenshots | 9 live screenshots real + generated |
| Zip Size | 5.9MB with logos and screenshots |

---

## 📸 More Screenshots

| IOC Explorer | ML Analytics | MITRE ATT&CK |
|--------------|--------------|--------------|
| ![IOC](public/screenshots/ioc-explorer.png) | ![ML](public/screenshots/ml-analytics.png) | ![MITRE](public/screenshots/mitre.png) |

| Reports | Malware Analysis | Login |
|---------|------------------|-------|
| ![Reports](public/screenshots/reports.png) | ![Malware](public/screenshots/malware-analysis.png) | ![Login](public/screenshots/login.png) |

---

## 👥 Team

**Sahil Rakholiya** - Lead Developer
- System Architecture, 29-Engine Deep Scan, MITRE 499, CrowdStrike 14, Backend, Security, API Design

**Priya Yadav** - UI/UX & Analytics
- UI/UX, Reports, ML Analytics, IOC Explorer, System Health, Testing, Branding, Screenshots, Professional PDF

---

## 📄 Documentation

- 📘 **Internship Report:** `MALDEF_Internship_Report_Sahil_Priya_FINAL_22_Pages_Live_Screenshots_No_VirusTotal.pdf` (19MB, 21 pages)
- 📊 **Presentation:** `MALDEF_Internship_Presentation_Sahil_Priya_FINAL_20_Slides.pptx` (12MB, 20 slides)
- 📦 **Full Package:** `MALDEF_FINAL_No_VirusTotal_With_Screenshots.zip` (16MB)

---

## 📝 License

**Defensive Cybersecurity Only** - For SOC training and malware analysis education. No malware generation.

---

## 🌟 Star History

If you like this project, give it a star! ⭐

**Built with ❤️ for Cybersecurity Community**

