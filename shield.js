/*
 * ScamShield — scam detection engine
 * Pure JavaScript, zero dependencies, no paid APIs.
 * Runs in the browser and in Node (same file powers both).
 *
 * Method: transparent, explainable rules — the same red flags human
 * fraud teams teach. Every point in the score can be traced to a
 * specific, named signal, and every verdict ships with an action plan.
 */

// ---------------------------------------------------------------- text rules
// Each rule: id, category, points, label, detail, patterns (regex list).
// A rule fires at most once per message.
const TEXT_RULES = [
  {
    id: "urgency",
    category: "Pressure tactic",
    points: 14,
    label: "Urgency and threats",
    detail:
      "Scammers rush you so you cannot think or check. Real banks and companies give you time and official channels.",
    patterns: [
      /act now/i, /immediately/i, /urgent/i, /within (the next )?\d+\s?(hours?|hrs?|minutes?|days?)/i,
      /account (will be|has been) (suspended|closed|blocked|terminated|frozen)/i,
      /final (warning|notice)/i, /last chance/i, /expires? (today|soon|in \d+)/i,
      /respond (now|immediately|urgently)/i, /failure to (respond|verify|act)/i,
      /will be (suspended|deactivated|deleted)/i,
    ],
  },
  {
    id: "credentials",
    category: "Credential theft",
    points: 22,
    label: "Asks for passwords, PINs or codes",
    detail:
      "No real bank, company or officer will ever ask for your password, PIN, OTP or verification code. Asking for one is the scam itself.",
    patterns: [
      /verify your (account|identity|details|information)/i,
      /confirm your (password|pin|details|account|identity)/i,
      /enter your (password|pin|otp|code|card)/i,
      /share (your|the) (otp|code|pin|password)/i,
      /(send|provide|give) (us )?(your )?(otp|one[- ]time (password|code)|verification code|pin|password)/i,
      /update your (payment|banking|card) (information|details)/i,
      /login (to|and) (secure|protect|verify|confirm)/i,
      /reactivate your account/i,
      /verify (now|here|to keep|your wallet)/i,
    ],
  },
  {
    id: "prize",
    category: "Prize & lottery",
    points: 18,
    label: "You have 'won' something",
    detail:
      "Unsolicited prizes, lotteries you never entered and giveaways that ask for a fee are among the oldest scams in the world.",
    patterns: [
      /you (have )?won/i, /you('re| are) (a|the) (winner|selected)/i,
      /claim your (prize|reward|gift| winnings)/i,
      /congratulations[!,. ]+you/i, /lottery/i, /giveaway/i,
      /free (iphone|gift card|voucher|prize)/i,
      /selected (as|to be) (a|the) winner/i,
      /prize (money|draw|winning)/i,
    ],
  },
  {
    id: "fee",
    category: "Advance fee",
    points: 16,
    label: "Pay a small fee to unlock money",
    detail:
      "A 'processing', 'delivery', 'customs' or 'release' fee before you receive a prize, parcel, loan or inheritance is an advance-fee scam. The big money never comes.",
    patterns: [
      /(processing|delivery|redelivery|customs|release|handling|clearance|activation) fee/i,
      /pay (a|the|only)? ?\$?\d+(\.\d+)? ?(to|fee)/i,
      /small (fee|payment|charge) (to|of)/i,
      /registration fee/i,
    ],
  },
  {
    id: "crypto",
    category: "Crypto & investment",
    points: 20,
    label: "Crypto doubling or 'guaranteed' returns",
    detail:
      "Nobody doubles crypto. Guaranteed profits, celebrity giveaways and pressure to move to crypto are fraud — and crypto payments cannot be reversed.",
    patterns: [
      /double your (money|bitcoin|btc|crypto|investment)/i,
      /guaranteed (returns?|profits?|income|earnings?)/i,
      /(send|deposit) \d*\.?\d+ ?(btc|eth|bitcoin|ethereum|usdt)/i,
      /crypto(currency)? (giveaway|investment|doubling|event)/i,
      /(bitcoin|btc|crypto) back/i,
      /investment opportunity/i,
      /\d{2,3}% (returns?|profit|roi) (per|every|in) (day|week|month)/i,
    ],
  },
  {
    id: "payment",
    category: "Untraceable payment",
    points: 18,
    label: "Payment by gift card, crypto or wire only",
    detail:
      "Legitimate organisations do not demand gift cards, crypto or wire transfers. These methods are used because they cannot be traced or refunded.",
    patterns: [
      /gift cards?/i, /itunes card/i, /steam card/i, /google play card/i,
      /wire transfer/i, /western union/i, /moneygram/i,
      /pay (only )?(in|with|via) (bitcoin|crypto)/i,
      /payment (only )?(in|through) cryptocurrency/i,
    ],
  },
  {
    id: "authority",
    category: "Impersonation",
    points: 14,
    label: "Claims to be an authority or big brand support",
    detail:
      "Police, tax departments, courts and tech giants do not threaten people by text or demand instant payment. Impersonation is the scammer's costume.",
    patterns: [
      /(tax|revenue) department/i, /arrest warrant/i,
      /legal action (will be|against)/i, /court (notice|summons) by (sms|text|email)/i,
      /(microsoft|apple|amazon|google|meta) (security )?(support|team|department)/i,
      /(bank|account) security (department|team)/i,
      /customs (officer|department)/i, /police (case|action|complaint)/i,
      /your computer (is|has been) (infected|hacked|compromised)/i,
    ],
  },
  {
    id: "remote",
    category: "Remote access",
    points: 18,
    label: "Wants remote access to your device",
    detail:
      "AnyDesk, TeamViewer or 'let our technician connect' — a stranger controlling your screen can empty your accounts in minutes.",
    patterns: [
      /remote access/i, /anydesk/i, /teamviewer/i,
      /(do not|don't) (turn off|switch off|shut down) your (computer|pc|laptop)/i,
      /call (our )?(support|technician|helpline)/i,
      /(install|download) (this|the) (app|software|tool) (so|to) (we|our)/i,
    ],
  },
  {
    id: "job",
    category: "Job scam",
    points: 16,
    label: "Too-good job offer",
    detail:
      "High pay for tiny tasks, interviews only on chat apps, or a fee before you start — fake jobs harvest money and personal data from people who need work most.",
    patterns: [
      /earn \$?\d[\d,]* ?(per day|daily|per week|a day|from home)/i,
      /work from home.{0,40}(earn|income|\$\d)/i,
      /no experience (needed|required)/i,
      /like (videos|posts|products).{0,30}(earn|paid|money)/i,
      /simple tasks?.{0,30}(earn|income)/i,
      /(contact|message|apply).{0,20}(whatsapp|telegram) only/i,
      /part[- ]time job.{0,40}\$\d/i,
    ],
  },
  {
    id: "secrecy",
    category: "Isolation tactic",
    points: 14,
    label: "Tells you to keep it secret",
    detail:
      "'Do not tell anyone' cuts you off from the one thing that stops scams — a second opinion. Secrecy is a weapon, not a procedure.",
    patterns: [
      /do not tell (anyone|anybody|your)/i, /don't tell (anyone|anybody|your)/i,
      /keep (this|it) (a )?secret/i, /stay on (the )?(line|phone|call)/i,
      /do not (hang up|disconnect)/i, /confidential (matter|case)/i,
    ],
  },
  {
    id: "romance",
    category: "Romance & trust",
    points: 12,
    label: "Stranger building trust, then a crisis",
    detail:
      "A soldier, doctor or executive abroad who falls for you quickly and then needs money for an emergency is a script — played on thousands of victims.",
    patterns: [
      /i am (a )?(soldier|officer|doctor|engineer) (stationed|working|deployed)/i,
      /stuck (in|at) (a )?(foreign|another) country/i,
      /my (late|deceased) (husband|wife|father|client).{0,40}(inheritance|fortune|millions)/i,
      /inheritance of \$?\d/i,
      /send money (so|to) (i|me) can/i,
    ],
  },
  {
    id: "parcel",
    category: "Parcel & delivery",
    points: 12,
    label: "Parcel problem that needs payment",
    detail:
      "A held parcel plus a small payment link is a classic card-harvesting trap. Real couriers do not collect fees through random text links.",
    patterns: [
      /your (parcel|package|shipment) (is|has been) (held|pending|delayed|stopped|waiting)/i,
      /(redelivery|re-?delivery|delivery attempt)/i,
      /track your (parcel|package|shipment).{0,40}http/i,
      /(customs|warehouse) (hold|holds) your (parcel|package)/i,
    ],
  },
  {
    id: "generic",
    category: "Phishing style",
    points: 6,
    label: "Generic greeting, no name",
    detail:
      "Your real bank knows your name. 'Dear customer / user / beneficiary' is how mass phishing talks.",
    patterns: [
      /dear (customer|user|valued customer|beneficiary|account holder)/i,
      /dear sir\/?madam/i,
    ],
  },
  {
    id: "shouting",
    category: "Phishing style",
    points: 5,
    label: "Shouting and panic formatting",
    detail: "ALL-CAPS lines and chains of exclamation marks are designed to spike your heart rate, not inform you.",
    patterns: [/[A-Z]{4,}( [A-Z]{3,}){2,}/, /!{3,}/],
  },
];

// ------------------------------------------------------------- link analysis
const SHORTENERS = [
  "bit.ly", "tinyurl.com", "cutt.ly", "rb.gy", "is.gd", "t.co", "goo.gl",
  "shorturl.at", "rebrand.ly", "bl.ink", "short.io", "s.id", "clck.ru",
  "tiny.cc", "yourls.org", "ow.ly", "buff.ly",
];

const RISKY_TLDS = ["zip", "mov", "xyz", "top", "click", "gq", "tk", "ml", "cf", "work", "live", "buzz", "icu", "rest", "quest", "best"];

// Brand -> official domains + match keys
const BRANDS = [
  { name: "PayPal", domains: ["paypal.com"], keys: ["paypal"] },
  { name: "Amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.in", "amazon.pk"], keys: ["amazon"] },
  { name: "Apple", domains: ["apple.com", "icloud.com"], keys: ["apple", "icloud"] },
  { name: "Microsoft", domains: ["microsoft.com", "live.com", "outlook.com"], keys: ["microsoft", "outlook"] },
  { name: "Google", domains: ["google.com", "gmail.com", "youtube.com"], keys: ["google", "gmail", "youtube"] },
  { name: "Facebook / Meta", domains: ["facebook.com", "meta.com", "instagram.com", "whatsapp.com"], keys: ["facebook", "instagram", "whatsapp", "meta"] },
  { name: "Netflix", domains: ["netflix.com"], keys: ["netflix"] },
  { name: "Binance", domains: ["binance.com"], keys: ["binance"] },
  { name: "DHL", domains: ["dhl.com"], keys: ["dhl"] },
  { name: "FedEx", domains: ["fedex.com"], keys: ["fedex"] },
  { name: "UPS", domains: ["ups.com"], keys: ["ups"] },
  { name: "Chase Bank", domains: ["chase.com"], keys: ["chase"] },
  { name: "Bank of America", domains: ["bankofamerica.com"], keys: ["bankofamerica"] },
  { name: "Wells Fargo", domains: ["wellsfargo.com"], keys: ["wellsfargo"] },
];

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => [i, ...Array(n).fill(0)]);
  for (let j = 1; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1)
      );
    }
  }
  return dp[m][n];
}

function registrableDomain(host) {
  const parts = host.toLowerCase().split(".").filter(Boolean);
  if (parts.length <= 2) return parts.join(".");
  // handle common two-part public suffixes (co.uk, com.pk, com.au)
  const twoPart = ["co.uk", "com.pk", "com.au", "co.in", "com.bd", "co.za"];
  const lastTwo = parts.slice(-2).join(".");
  if (twoPart.includes(lastTwo)) return parts.slice(-3).join(".");
  return parts.slice(-2).join(".");
}

function extractUrls(text) {
  const withPath = text.match(/https?:\/\/[^\s<>"')\]]+|www\.[^\s<>"')\]]+|[a-z0-9-]+\.(com|net|org|io|xyz|top|click|zip|mov|live|info|site|online|tk|gq|ml|cf|buzz|icu|work|quest|best|co|me|tv|app|dev|ly|gy|gd|cc|at)\/[^\s<>"')\]]*/gi) || [];
  // Bare domains on high-abuse TLDs (no path) are still links a victim can tap.
  const bare = text.match(/\b[a-z0-9][a-z0-9-]*\.(xyz|top|click|zip|mov|live|icu|buzz|quest|best|site|online|work|tk|gq|ml|cf)\b/gi) || [];
  return Array.from(new Set([...withPath, ...bare].map((u) => u.replace(/[.,;:!?]+$/, ""))));
}

function analyzeUrl(rawUrl) {
  const findings = [];
  let points = 0;
  const withScheme = /^https?:\/\//i.test(rawUrl) ? rawUrl : "http://" + rawUrl;
  let u;
  try {
    u = new URL(withScheme);
  } catch (e) {
    return { url: rawUrl, points: 4, findings: [{ label: "Malformed link", detail: "The link cannot even be parsed as a normal web address — a common trait of hastily built phishing pages.", points: 4 }] };
  }
  const host = u.hostname.toLowerCase();
  const reg = registrableDomain(host);
  const tld = host.split(".").pop();

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    points += 18;
    findings.push({ label: "Link uses a raw IP address", detail: "Real companies use domain names, not bare IP numbers. Fraud pages hide behind IPs to avoid registration records.", points: 18 });
  }
  if (host.startsWith("xn--") || reg.startsWith("xn--")) {
    points += 15;
    findings.push({ label: "Punycode (look-alike) domain", detail: "This domain uses punycode encoding — the trick behind look-alike addresses that visually mimic real brands.", points: 15 });
  }
  if (SHORTENERS.includes(reg) || SHORTENERS.includes(host)) {
    points += 10;
    findings.push({ label: "Shortened link hides its destination", detail: `Shorteners like ${reg} hide where a link really goes. Never enter passwords or card details after a shortened link.`, points: 10 });
  }
  if (RISKY_TLDS.includes(tld)) {
    points += 8;
    findings.push({ label: `High-abuse domain ending (.${tld})`, detail: `The .${tld} ending is heavily used by disposable scam sites because domains there are cheap and anonymous.`, points: 8 });
  }
  if (u.username) {
    points += 15;
    findings.push({ label: "'@' trick inside the link", detail: "Everything before the @ is ignored by the browser — the real destination is what follows it. A classic phishing disguise.", points: 15 });
  }
  const subCount = host.split(".").length - reg.split(".").length;
  if (subCount >= 2 && !/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    points += 8;
    findings.push({ label: "Deep stack of subdomains", detail: "Long chains like secure.login.verify.example are built to make a fake page look official at a glance.", points: 8 });
  }
  if (u.protocol === "http:" && /login|verify|secure|account|bank|pay/i.test(u.pathname + u.hostname)) {
    points += 6;
    findings.push({ label: "Unencrypted page asking for trust", detail: "A login or verification page over plain http (no padlock) exposes everything typed into it.", points: 6 });
  }

  // Brand impersonation / official check
  let official = null;
  BRANDS.forEach((b) => {
    if (b.domains.includes(reg)) official = b;
  });
  if (official) {
    findings.push({ label: `Official ${official.name} domain`, detail: `This link really does belong to ${official.name} (${reg}). That is a good sign — though the message around it still matters.`, points: 0, good: true });
  } else {
    // Compare the domain's name part — whole, split into pieces, and with
    // filler words (secure/verify/login…) stripped — against brand names.
    const labelPart = reg.split(".")[0];
    const fillers = ["secure", "login", "verify", "account", "support", "official", "update", "confirm", "online", "service", "help", "safe", "protect", "auth", "id", "my", "the", "web", "app"];
    const pieces = labelPart.split(/[-_]/).filter(Boolean);
    const stripped = pieces.filter((p) => !fillers.includes(p)).join("");
    const candidates = Array.from(new Set([labelPart, stripped, ...pieces].filter((c) => c.length >= 4)));
    BRANDS.forEach((b) => {
      b.keys.forEach((k) => {
        if (findings.some((f) => f.impersonation)) return;
        const hit = reg.includes(k) || candidates.some((c) => c.includes(k) || levenshtein(c, k) <= 2);
        if (hit) {
          points += 26;
          findings.push({
            label: `Pretends to be ${b.name}`,
            detail: `The address ${reg} is NOT ${b.name}'s real domain (${b.domains.join(", ")}). Look-alike domains are the #1 phishing weapon.`,
            points: 26,
            impersonation: true,
          });
        }
      });
    });
  }
  return { url: rawUrl, host: reg, points, findings, official: official ? official.name : null };
}

// ------------------------------------------------------------------- actions
function buildActions(flags, urls, level) {
  const actions = [];
  const has = (id) => flags.some((f) => f.id === id);
  const hasLink = urls.length > 0;

  actions.push({ title: "Stop — do not reply, pay or click", detail: "Scammers win by keeping you inside their message. Leave it. Nothing real is lost by pausing." });
  if (hasLink) actions.push({ title: "Never open the link from the message", detail: "If the service is real, open its official app or type its real address yourself. That one habit defeats most phishing." });
  if (has("credentials")) actions.push({ title: "If you already shared a password or code", detail: "Change that password NOW (from the official app/site), turn on two-factor authentication, and check recent account activity. Treat any shared OTP as already used." });
  if (has("payment") || has("crypto") || has("fee")) actions.push({ title: "If you already paid", detail: "Call your bank immediately and report fraud — speed matters. Gift-card and crypto payments are almost never recoverable, which is exactly why scammers demand them." });
  if (has("authority")) actions.push({ title: "Verify through a number YOU trust", detail: "Hang up / ignore the message. Find the organisation's number on its official website, your card, or a bill — never the number inside the suspicious message." });
  if (has("job")) actions.push({ title: "Protect your job search", detail: "Real employers do not interview only on chat apps or charge fees to start work. Apply through official company pages, and never pay to be hired." });
  if (has("remote")) actions.push({ title: "If you installed anything they asked for", detail: "Disconnect from the internet, uninstall the app, change banking passwords from a different device, and have the machine checked before using it for money again." });
  actions.push({ title: "Report and block", detail: "Report the message in your app (spam/phishing), block the sender, and warn anyone who might get the same text — sharing a screenshot can save a friend." });
  if (level === "low") actions.length = 0;
  return actions;
}

// -------------------------------------------------------------------- levels
function levelFor(score) {
  if (score >= 70) return { id: "critical", label: "CRITICAL RISK", verdict: "This carries the fingerprints of a scam. Do not engage with it." };
  if (score >= 45) return { id: "high", label: "HIGH RISK", verdict: "Strong scam signals. Treat this as fraud unless you can verify it through an official channel you found yourself." };
  if (score >= 20) return { id: "caution", label: "BE CAREFUL", verdict: "Some red flags are present. Slow down and verify before you act." };
  return { id: "low", label: "LOOKS OK", verdict: "No strong scam signals found. Stay alert anyway — no checker is perfect, and context matters." };
}

// -------------------------------------------------------------------- main
function analyze(input) {
  const text = String(input || "");
  const flags = [];
  let score = 0;

  TEXT_RULES.forEach((rule) => {
    const hit = rule.patterns.some((re) => re.test(text));
    if (hit) {
      flags.push({ id: rule.id, category: rule.category, label: rule.label, detail: rule.detail, points: rule.points });
      score += rule.points;
    }
  });

  const rawUrls = extractUrls(text);
  const urls = rawUrls.map(analyzeUrl);
  let linkPoints = 0;
  let officialOnly = urls.length > 0;
  urls.forEach((u) => {
    linkPoints += u.points;
    if (!u.official) officialOnly = false;
  });
  score += linkPoints;

  const safeSignals = [];
  if (officialOnly && urls.length > 0) {
    safeSignals.push("Every link points to an official brand domain.");
    score -= 10;
  }
  if (urls.length === 0 && !flags.some((f) => ["credentials", "crypto", "payment", "fee"].includes(f.id))) {
    safeSignals.push("No links and no request for money or codes.");
  }

  score = Math.max(0, Math.min(100, score));
  const level = levelFor(score);

  // dominant scam category = category of the highest-points flag
  let category = "General phishing";
  if (flags.length) {
    category = flags.slice().sort((a, b) => b.points - a.points)[0].category;
  }
  if (urls.some((u) => u.findings.some((f) => f.impersonation))) category = "Brand impersonation / phishing";

  return {
    score,
    level: level.id,
    levelLabel: level.label,
    verdict: level.verdict,
    category,
    flags: flags.sort((a, b) => b.points - a.points),
    urls,
    safeSignals,
    actions: buildActions(flags, urls, level.id),
  };
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { analyze, analyzeUrl, SAMPLES: null };
}
if (typeof window !== "undefined") {
  window.Shield = { analyze, analyzeUrl };
}
