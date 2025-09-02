Risk, Time & Location — RiBAC Simulator (Banking Insider-Threat Demo)
===================================================================

This project demonstrates a Risk-Adaptive Access Control (RiBAC) simulator, combining RBAC + ABAC + Time + Risk scoring.
Policies are defined in XML files per role. The simulator evaluates user actions against policies, context (device, time, location),
and a risk engine. Outcomes are Permit / Deny / NeedsApproval (with Read-Only).

-------------------------------------------------------------------
1) Project Files
-------------------------------------------------------------------
- RiBAC Simulator.py                : Flask API implementing PDP/PEP/PIP and risk engine
- IT_Admin.xml                      : XML policy for IT Admin role
- Manager.xml                       : XML policy for Manager role
- Finance_Employee.xml              : XML policy for Finance Employee role
- IT_Auditor.xml                    : XML policy for IT Auditor role
- 5610708_JSON_Scripts.postman_collection.json : Postman collection for testing API

-------------------------------------------------------------------
2) Quick Start
-------------------------------------------------------------------
1. Create and activate a virtual environment:
   python -m venv .venv
   # macOS/Linux
   source .venv/bin/activate
   # Windows
   .venv\Scripts\activate

2. Install dependencies:
   pip install flask tzdata
   # If Python < 3.9:
   pip install backports.zoneinfo

3. Run the simulator:
   python "RiBAC Simulator.py"

   Server will start at: http://127.0.0.1:5000

-------------------------------------------------------------------
3) API Endpoints
-------------------------------------------------------------------
Base URL: http://127.0.0.1:5000

POST /login
- Authenticate a user, evaluate context and risk.
- May return NeedsApproval if BYOD/unregistered device or off-hours.

POST /access
- Authorize an action on a resource.
- Returns decision (Permit / Deny / NeedsApproval) with risk score.

POST /approve
- Managers approve pending requests.
- Prevents self-approval.

-------------------------------------------------------------------
4) Using Postman
-------------------------------------------------------------------
- Import 5610708_JSON_Scripts.postman_collection.json into Postman.
- Set baseUrl = http://127.0.0.1:5000 in Collection Variables.
- Run login → capture token.
- Run access → check decision.
- If NeedsApproval, run approve with Manager token.

-------------------------------------------------------------------
5) Policy Model (XML)
-------------------------------------------------------------------
Each XML policy file defines:
- Operation (Read, Write, Delete, Export, Approve)
- Resource (e.g., logs, files, configs)
- Decision (Allow/Deny)
- RiskAllowed (band) and TimeWindow (STD, EXT, Always)
- Device rules (registered vs OtherDevices)

-------------------------------------------------------------------
6) Risk Engine
-------------------------------------------------------------------
- Score range: 0–10
- Bands: negligible (0–2), low (3–4), medium (5–7), high (8–10)
- Factors: action base cost, resource sensitivity, device registration, time window
- Certain actions (log delete, export) add bias → high risk

-------------------------------------------------------------------
7) Troubleshooting
-------------------------------------------------------------------
- Timezone warnings → install tzdata
- Python < 3.9 → install backports.zoneinfo
- 401 /approve → invalid or missing token (must be Manager)
- 403 self-approval → expected
- Deny on delete logs/export → expected categorical policy

-------------------------------------------------------------------
8) Security Notes
-------------------------------------------------------------------
- Demo only; tokens in memory, no database.
- Not production-ready; for educational scenarios only.

