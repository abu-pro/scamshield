# ScamShield 🛡️

**Paste any message. Know in seconds if it's a trap.**

ScamShield is a free scam checker built for **HackGlobal 2026**
(Polaris School of Technology × Vultr), Track 4: *Civic and real-world
impact*.

Consumers around the world lost **over $1 trillion to scams in a single
year** (Global Anti-Scam Alliance). The victims are not careless — they
are rushed, frightened and isolated by design. ScamShield is the
30-second pause that breaks the script: paste a suspicious SMS, chat
message, email or link, and get a **risk score, every red flag explained
in plain English, and an action plan** — including what to do if you
already clicked, paid or shared a code.

## What it checks

**Thirteen red-flag families** (transparent rules, no black-box AI):
urgency & threats · credential/OTP asks · fake prizes · advance fees ·
crypto doubling & "guaranteed" returns · untraceable payment demands ·
authority impersonation · remote-access traps · job scams · secrecy
tactics · romance scripts · parcel traps · phishing style signals.

**Link forensics** for every URL in the message:
look-alike brand domains (Levenshtein + substring matching against the
real domains of PayPal, Amazon, Apple, banks, couriers and more) ·
punycode · raw-IP hosts · URL shorteners · high-abuse TLDs · the "@"
userinfo trick · deep subdomain stacks · unencrypted login pages.

**Output:** a 0–100 risk score with a level (LOOKS OK / BE CAREFUL /
HIGH RISK / CRITICAL), the most likely scam category, safe signals when
present, and a recovery-ready action plan.

## System design

```
┌────────────┐   POST /api/analyze   ┌──────────────────┐
│  Browser   │ ────────────────────▶ │  Node server     │
│  (paste +  │                       │  server.js       │
│   verdict) │ ◀──────────────────── │  (zero deps)     │
└────────────┘   JSON score + plan   └────────┬─────────┘
      │                                       │ requires
      │  static fallback (same file)          ▼
      └─────────────────────────────  shield.js
                                      rules + link forensics
```

- `shield.js` — the detection engine (pure JS, zero dependencies). The
  browser loads the identical file as a fallback, so the app also works
  on purely static hosting and can even run fully offline.
- `server.js` — zero-dependency Node HTTP server: static files +
  `POST /api/analyze`.
- `public/` — the English-medium web UI, with one-tap sample scams and a
  red-flag library that teaches the patterns.

## Run it locally

```bash
node server.js          # http://localhost:3000
```

No `npm install` needed — there are no dependencies, and no data is
stored. Messages are analysed in memory only.

## Deploy on Vultr (for the hackathon submission)

1. Claim the event gift-code credits in your Vultr account.
2. Create a **Cloud Compute** instance (Ubuntu 24.04, smallest plan is
   enough) and SSH in.
3. Install Node: `sudo apt update && sudo apt install -y nodejs`
4. Copy this project to the instance (git clone your repo) and run:
   `PORT=80 nohup node server.js &` (or use `pm2`).
5. Open the instance's public IP — that is your public demo URL.

## Honesty note

ScamShield explains *risk signals*; no tool can guarantee a message is
safe. The golden rule it teaches on every result: verify through the
official app or website that you found yourself — never through a link
inside a message.

## Author

**Abu Sufyan** — BS Software Engineering, Riphah International
University, Sahiwal, Pakistan. Built solo for HackGlobal 2026, with AI
assistance.
