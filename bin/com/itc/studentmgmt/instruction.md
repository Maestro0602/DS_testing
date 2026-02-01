🔐 Prompt: Max-Security Adversary Simulation (SAFE)

I am building a school management system with advanced security features (IDS, rate limiting, audit logging, alerting).

I need you to generate SAFE attack-simulation code (for defensive testing only) that demonstrates the maximum security capability of the system.

⚠️ IMPORTANT CONSTRAINTS (DO NOT VIOLATE):

This is NOT malware

Do NOT encrypt files

Do NOT access the OS, registry, filesystem, or network scanning

Do NOT include persistence, self-propagation, or destructive actions

Only simulate application-layer behavior

✅ Allowed actions:

HTTP requests to local endpoints (e.g. /login, /api/student/{id})

Fake login attempts

SQL injection strings (no execution)

Fake or modified session tokens

High-volume but rate-limited API access

Behavior-based simulation (mass reads, repeated access)

🔥 Generate a single Java class called MaxSecurityAttackSimulation

The class should simulate a multi-phase adversary attack, similar to a real APT, but completely safe.

Phases to include:

Phase 1 – Reconnaissance

Repeated harmless GET requests to /login

Purpose: trigger rate-limiting counters

Phase 2 – Credential Stuffing

Attempt logins on multiple users with common passwords

Purpose: trigger brute-force & correlation detection

Phase 3 – Injection Attempts

Send login requests with SQLi, XSS, and path traversal payload strings

Purpose: trigger IDS pattern detection

Phase 4 – Session Token Abuse

Send requests with fake, modified, and replayed tokens

Purpose: test HMAC, AES, and session integrity

Phase 5 – Ransomware-Like Behavior (SAFE)

Simulate rapid access to many student records (READ-ONLY)

NO file encryption

Purpose: trigger abnormal access / insider abuse detection

🛡️ Security Expectations

Each phase should be clearly commented

Add small delays (Thread.sleep) to avoid real DoS

Code must be readable and explainable

No external attack tools

No real harm possible

🎯 Output Goal

This code should trigger:

Intrusion Detection

Rate Limiting

Audit Logging

Telegram / Device Alerts (CRITICAL)

The result should demonstrate the upper limit of the system’s defensive capability.

for the attack code dont use actual attack to could actually cause harm to the device it doesnt need to be a single code 



and for the alert make me a class that sent to my discord and telegram that alert attacks 