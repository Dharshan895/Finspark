# SentinelIQ - Insider Threat Detection Dashboard

SentinelIQ is a real-time insider threat detection prototype designed for privileged access monitoring in banking. It features an automated synthetic log generator, a user behavior profile cache (UEBA), an Isolation Forest anomaly detection engine, real-time WebSocket events, an auto-locking defensive mechanism (SOAR), and an encrypted audit log. 

It also includes a validation module (`validate.py`) which evaluates the model against the real Carnegie Mellon University (CMU) CERT insider threat dataset.

---

## Technical Stack
- **Backend**: FastAPI, scikit-learn (IsolationForest), pandas, cryptography, websockets
- **Frontend**: React (Vite-based), Recharts, Lucide-React, Vanilla CSS (Modern dark banking theme)
- **Containerization**: Docker Compose

---

## Quick Start (How to Run)

### Prerequisites
- Install **Docker** and **Docker Compose** on your system.

### Steps to Run
From the root directory of the project, run:

```bash
docker-compose up --build
```

- **React Dashboard**: Open your browser at `http://localhost:5173`
- **FastAPI Backend (Swagger API Docs)**: Accessible at `http://localhost:8000/docs`

---

## Model Labeled Validation (Slide Metrics)
To verify the model against the real CMU CERT dataset (logon.csv and device.csv), run:

```bash
python backend/validate.py
```

### Accuracy Metrics
- **Recall (Detection Rate)**: **58.33%** (This represents the **theoretical maximum recall** using logon hour & USB connections. It successfully flags 100% of the active malicious exfiltration events).
- **Total Sessions Analyzed**: 334,600 user-day sessions.

---

## Suggested Hackathon Demo Flow
1. **Open the Dashboard**: Go to `http://localhost:5173`. You will see the operations feed streaming active banking events (green/amber status).
2. **Trigger an Attack**: Click the **"Attack 1: Contractor Export (2 AM)"** button. 
3. **Observe Alert & SOAR Lockdown**: 
   - A critical threat alert (red badge, risk > 75) will appear in the scrolling feed.
   - The top **SOAR alert banner** will instantly flash, noting the user account has been disabled.
   - The user's status in the scoreboard will update to **Locked/Disabled** (red dot).
4. **Drill Down to AI Analysis**: Click on the flagged red event in the scrolling feed. The **Investigation Panel** will load, detailing the MITRE ATT&CK techniques mapped (e.g. `T1048`, `T1078`) and a plain-English explainability analysis of *why* it was flagged.
5. **Inspect the Encrypted Audit Trail**: 
   - Under the hood, the backend automatically encrypts all flagged anomalies with AES-256 and writes them to a binary file `audit_trail.enc`.
   - Click the **"Decrypt & Inspect Audit Trail"** button in the dashboard to decrypt and view the logs in real time.
6. **Remediation**: Click the **Unlock** key icon next to the user in the scoreboard or incident queue to restore the account and reset the demo.
