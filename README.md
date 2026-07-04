# SME Header Auditor

Chrome extension + local backend to (1) check the 6 headers on any site you
browse, and (2) log qualifying sites straight into your research dataset.

## 1. Backend setup

```bash
pip install flask flask-cors --break-system-packages
```

Edit `server.py` and set `DB_PATH` to your actual dataset `.db` file
(so it writes into the same table you're already building, not a new one).
If your existing table has a different name/columns than `sites`
(business_name, url, category, city, state, source, date_added, notes),
either rename the table in your DB to `sites` or edit the SQL in
`init_db()` / `add_site()` to match your real schema.

Run it:
```bash
python server.py
```
Leave this running in a terminal while you browse — the extension talks to
it on `localhost:5000`.

## 2. Load the extension in Chrome

1. Go to `chrome://extensions`
2. Turn on "Developer mode" (top right)
3. Click "Load unpacked"
4. Select this folder (`sme-extension/`)

## 3. Use it

1. Visit any SME site
2. Click the extension icon
3. You'll see pass/fail on the 6 headers and a 0–1 score with A–F tier
   (equal-weighted by default — edit the `weight` values in `popup.js` if
   your paper uses a different weighting)
4. If it's a site you want in your dataset, fill in business name /
   category / city / state / notes and click "Add to dataset" — it checks
   for duplicates first via the URL UNIQUE constraint

## Scoring methodology

Each header contributes a different amount to the overall score, reflecting
the relative severity of the attack class it mitigates:

| Header | Weight | Attack class mitigated | Severity rationale |
|---|---|---|---|
| Content-Security-Policy | 0.25 | Cross-site scripting (XSS), data injection | Highest-prevalence, highest-impact web vulnerability class (OWASP Top 10) |
| Strict-Transport-Security | 0.20 | MITM / SSL-stripping / downgrade attacks | Compromises confidentiality and integrity of the entire connection |
| X-Frame-Options | 0.15 | Clickjacking | Real but narrower attack surface than XSS/MITM |
| Referrer-Policy | 0.15 | Sensitive-data leakage via URLs | Information disclosure, not code execution |
| Permissions-Policy | 0.15 | Unauthorized hardware/feature access | Situational impact, depends on what features a page actually uses |
| X-Content-Type-Options | 0.10 | MIME-sniffing / content-type confusion | Older, narrower attack class; largely mitigated in modern browsers by default |

Weights sum to 1.0. A header counts as "present" for scoring purposes if
it's set at all — a header flagged ⚠ "weak" in the popup (e.g. CSP with
`unsafe-inline`) still earns its full weight, since the score is
presence-based, not quality-graded. The ⚠ flags are there so you can spot
superficial compliance during manual review, without changing the
reported score itself.

Tiers: **A** ≥ 0.90, **B** ≥ 0.75, **C** ≥ 0.60, **D** ≥ 0.40, **F** < 0.40.

If you later decide to also dock partial credit for "weak" headers (quality-
graded rather than presence-based scoring), that's a small change to the
scoring loop in `popup.js` — but it changes what you're claiming
methodologically, so decide that deliberately rather than as an
implementation detail.

## Notes / limits

- Headers are only captured for pages you actually navigate to (the
  extension listens via `webRequest.onHeadersReceived`) — if you open the
  popup before the page finishes loading once, reload the tab.
- Redirects (e.g. http → https) are handled: only the final response's
  headers are captured, not the intermediate redirect's.
- Each of the 6 headers is checked for both **presence** (feeds your
  paper's 0–1 score, unchanged) and basic **quality** (shown as ⚠ "weak"
  in the popup — e.g. CSP with `unsafe-inline`, HSTS with a short
  `max-age`, a leaky Referrer-Policy). Weak still counts as "present" for
  scoring, since your paper's methodology is presence-based, but you can
  see at a glance which sites are only superficially compliant.
- "Additional signals" (cookie flags, Server/X-Powered-By disclosure) are
  informational only and are NOT part of the 6-header score.
- This only reads headers of pages rendered in your browser. It does not
  do SSL/cert checks or probe for exposed files — that's still the job of
  the server-side backend for your full remediation tool later.
- Reload the extension (chrome://extensions → refresh icon) after editing
  any file.
