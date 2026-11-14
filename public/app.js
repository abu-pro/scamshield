(function () {
  const input = document.getElementById("input");
  const analyzeBtn = document.getElementById("analyze-btn");
  const clearBtn = document.getElementById("clear-btn");
  const resultsEl = document.getElementById("results");
  const ringEl = document.getElementById("ring");
  const scoreEl = document.getElementById("score");
  const levelEl = document.getElementById("level");
  const verdictEl = document.getElementById("verdict");
  const categoryEl = document.getElementById("category");
  const safeEl = document.getElementById("safe");
  const flagsEl = document.getElementById("flags");
  const linkboxEl = document.getElementById("linkbox");
  const actionsEl = document.getElementById("actions");
  const chipsEl = document.getElementById("sample-chips");

  const SAMPLES = [
    {
      name: "🏦 Bank SMS",
      text: "ALERT from your bank security department: Your account will be SUSPENDED within 24 hours due to suspicious activity. Verify your identity immediately to avoid closure: http://secure-bankverify.xyz/login",
    },
    {
      name: "📦 Parcel fee",
      text: "DHL: Your parcel is held at customs. Pay the $1.99 redelivery fee within 12 hours or it will be returned to sender. Pay here: https://bit.ly/3xYz9Ab",
    },
    {
      name: "₿ Crypto giveaway",
      text: "OFFICIAL GIVEAWAY! Send 0.5 BTC and get 1 BTC back instantly. Double your money — guaranteed! Event ends soon, join now: crypto-double-event.live",
    },
    {
      name: "💼 WhatsApp job",
      text: "Earn $300 per day from home! Simple task: like YouTube videos and get paid. No experience needed. Contact us on WhatsApp only to start. A small $20 registration fee applies. ACT NOW — positions are filling fast!",
    },
    {
      name: "🎁 Prize email",
      text: "Dear Beneficiary, CONGRATULATIONS! You have won a $1,000 gift card in our international lottery. To claim your prize within 48 hours, confirm your details and pay the processing fee here: http://claim-prize-now.top/claim",
    },
    {
      name: "🖥️ Tech support",
      text: "Microsoft Security Alert: Your computer is infected with a dangerous virus. Call our support team immediately and do not turn off your computer. Stay on the phone while our technician takes remote access to fix it.",
    },
    {
      name: "✅ A normal message",
      text: "Hi! Your Amazon order #402-8812345 has shipped and arrives on Thursday. You can view your order any time in the Amazon app or at https://www.amazon.com/orders. Thank you for shopping with us.",
    },
  ];

  SAMPLES.forEach((s) => {
    const b = document.createElement("button");
    b.type = "button";
    b.className = "chip";
    b.textContent = s.name;
    b.addEventListener("click", () => {
      input.value = s.text;
      run();
    });
    chipsEl.appendChild(b);
  });

  const LEVEL_COLORS = {
    low: "#0d7a5f",
    caution: "#b97d0c",
    high: "#c2540a",
    critical: "#b3232a",
  };

  async function analyze(text) {
    try {
      const res = await fetch("/api/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text }),
      });
      if (!res.ok) throw new Error("api");
      return await res.json();
    } catch (e) {
      return window.Shield.analyze(text);
    }
  }

  function render(data) {
    const color = LEVEL_COLORS[data.level] || "#35506b";
    scoreEl.textContent = data.score;
    ringEl.style.background = `conic-gradient(${color} ${data.score * 3.6}deg, #e8eef0 0deg)`;
    levelEl.textContent = data.levelLabel;
    levelEl.style.background = color;
    verdictEl.textContent = data.verdict;
    categoryEl.textContent = data.flags.length || data.urls.some((u) => u.findings.length)
      ? `Most likely type: ${data.category}`
      : "";

    safeEl.innerHTML = "";
    (data.safeSignals || []).forEach((s) => {
      const p = document.createElement("p");
      p.className = "safe-line";
      p.textContent = "🟢 " + s;
      safeEl.appendChild(p);
    });

    flagsEl.innerHTML = "";
    if (!data.flags.length) {
      const li = document.createElement("li");
      li.className = "none";
      li.textContent = "No text red flags found in this message.";
      flagsEl.appendChild(li);
    }
    data.flags.forEach((f) => {
      const li = document.createElement("li");
      li.innerHTML = `<div class="flag-head"><strong></strong><span class="pts"></span></div><p></p>`;
      li.querySelector("strong").textContent = `${f.label} · ${f.category}`;
      li.querySelector(".pts").textContent = `+${f.points}`;
      li.querySelector("p").textContent = f.detail;
      flagsEl.appendChild(li);
    });

    linkboxEl.innerHTML = "";
    if (data.urls.length) {
      const h = document.createElement("h3");
      h.textContent = "🔗 Link inspection";
      linkboxEl.appendChild(h);
      data.urls.forEach((u) => {
        const box = document.createElement("div");
        box.className = "linkbox";
        const head = document.createElement("p");
        head.className = "link-url";
        head.textContent = u.url + (u.host ? `  →  real destination domain: ${u.host}` : "");
        box.appendChild(head);
        if (!u.findings.length) {
          const p = document.createElement("p");
          p.textContent = "No structural red flags in this link.";
          box.appendChild(p);
        }
        u.findings.forEach((fd) => {
          const p = document.createElement("p");
          p.className = fd.good ? "good" : "bad";
          p.textContent = `${fd.good ? "✅" : "🚩"} ${fd.label} — ${fd.detail}`;
          box.appendChild(p);
        });
        linkboxEl.appendChild(box);
      });
    }

    actionsEl.innerHTML = "";
    if (!data.actions.length) {
      const li = document.createElement("li");
      li.textContent = "Nothing urgent. Keep the habit: verify big claims through official apps and websites, not through links in messages.";
      actionsEl.appendChild(li);
    }
    data.actions.forEach((a) => {
      const li = document.createElement("li");
      const strong = document.createElement("strong");
      strong.textContent = a.title;
      li.appendChild(strong);
      li.appendChild(document.createTextNode(a.detail));
      actionsEl.appendChild(li);
    });

    resultsEl.hidden = false;
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  async function run() {
    const text = input.value.trim();
    if (!text) {
      input.focus();
      return;
    }
    const data = await analyze(text);
    render(data);
  }

  analyzeBtn.addEventListener("click", run);
  clearBtn.addEventListener("click", () => {
    input.value = "";
    resultsEl.hidden = true;
    input.focus();
  });
})();
