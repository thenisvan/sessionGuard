# SessionGuard Analyzer — Quick Start

A concise, printable setup to validate and renew sessions while testing authorization.

---

## Install

1) Build the extension
```bash
cd auth-analyzer
make build
# outputs: target/AuthAnalyzer-1.1.15-jar-with-dependencies.jar
```

2) Load in Burp Suite
- Extender → Extensions → Add → Type: Java
- Select the shaded JAR above
- Verify: "SessionGuard Analyzer successfully started"

---

## Configure a Session (User Role)

1) Add a new session (e.g., "User")
2) Headers to Replace:
```
Cookie: SESSIONID=placeholder
```
3) Add token `SESSIONID`
- Extraction: Auto Extract
- Extract From: Set-Cookie Header
- Replace In: Cookie Parameter

---

## Enable Session Monitoring

Open Session Monitoring:
- Method: GET
- URL: https://target.app/health
- Expected Status: 200
- Body contains: success (or use regex)
- Interval: 60s (default)

---

## Create a Renewal Macro

Session Monitor → Renewal Macros → Add Macro → "Login Flow"

Step 1:
```
Method: POST
URL: https://target.app/login
Headers:
  Content-Type: application/x-www-form-urlencoded
Body:
  username=testuser&password=testpass123
```

(Optional) Use placeholders like `{{csrfToken}}` in the body and define that token in the session.

Link the macro to your session: Session Monitoring → Renewal Macro: Login Flow → Save.

---

## Run & Analyze

1) Start SessionGuard (▶)
2) Browse the app (admin/high-priv user)
3) Watch Session Status (VALID / EXPIRED / ERROR / UNKNOWN)
4) Trigger expiry (invalidate cookie) to test auto-renew
5) Inspect results table for bypass status (SAME/SIMILAR/DIFFERENT)
6) Export results (HTML/XML) for reporting

---

## Tips
- Use From-To extraction to grab tokens embedded in scripts
- Adjust SIMILAR threshold via code if needed (default ±5%)
- After 3 failed renewals, a dialog appears — review macro steps
- Use Only In Scope filter to focus on your target

---

## Placeholders to Replace Later
Add screenshots to `docs/images/` and update README if needed:
- placeholder-first-setup.png
- placeholder-monitoring-panel.png
- placeholder-macro-editor.png
- placeholder-results-table.png
- placeholder-diff-view.png
