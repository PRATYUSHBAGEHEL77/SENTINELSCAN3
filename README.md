# SentinelScan — Retest & Finding Lifecycle Build

## Demonstration workflow

**START SENTINELSCAN → SECURITY CENTER → RUN ASSESSMENT → 20 CHECKS → HIGH: Broken Authorization → OPEN POC EVIDENCE → SHOW REMEDIATION → FIX LAB → RETEST → PASS → RESOLVED**

### Finding lifecycle

`OPEN → CONFIRMED → REMEDIATION_REQUIRED → FIXED → RETESTED → RESOLVED`

The lifecycle is persisted locally in `backend/security_state.json` and audit events are appended to `backend/sentinelscan_audit.jsonl`.

### Retest behavior

The RETEST action sends the **same no-credential request** used by the original finding:

`GET /api/lab/vulnerable/admin`

It then compares the previous request/response evidence with the new evidence.

- Before remediation: `200 OK` → HIGH → OPEN/CONFIRMED.
- After **FIX LAB**: `403 Forbidden` → PASS → RESOLVED.

The displayed retest timestamp is generated at runtime; it is not fabricated.

### CVSS

For the authorization PoC, CVSS is derived from the observed condition. Because the original request contains **no credentials** and the endpoint returns the protected marker, the observed privilege requirement is `PR:N`, producing:

`6.5 · CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N`

The UI explains why `PR:N` was selected. Do not claim this score applies to an arbitrary real-world authorization flaw; it is specific to the synthetic observed condition.

## Scope and safety

This build is local-first and non-destructive. The vulnerable endpoint is synthetic and never connects to production users or data. Automated assessment is restricted to localhost.

## Run

Double-click `START_SENTINELSCAN.bat`, then open `http://127.0.0.1:8000/`.

### Assessment evidence

The assessment report contains 20 checks. Automatically confirmed controlled-lab findings include LAB-AUTHZ-001, LAB-IDOR-001, LAB-XSS-001, LAB-JWT-001, and LAB-SSRF-001. Each finding records description, affected component, severity, CVSS rationale, request/response evidence, impact, remediation, reproduction steps, and safe-scope statement. FIX LAB changes all five synthetic controls to their secure behavior; RETEST repeats the same request and records before/after evidence.


### World Monitor local finding

`WM-HEADERS-001` documents the observed security-header gap on the local World Monitor deployment. It is explicitly classified as a deployment hardening finding and is supported by the captured root-response headers. It is kept separate from the five synthetic lab vulnerabilities so the report does not imply that the lab behavior exists in production.
