// InjectShield dashboard — pure client-side. Key lives in sessionStorage so
// it doesn't survive a tab close. We do NOT use localStorage for this on
// purpose (less convenient, but reduces credential persistence risk).
(function () {
  const API = window.PROMPTSHIELD_API_BASE || "https://api.injectshield.dev";
  const KEY_NAME = "injectshield.api_key";

  const el = (id) => document.getElementById(id);
  const login = el("login");
  const dash = el("dashboard");
  const form = el("login-form");
  const input = el("key-input");
  const status = el("login-status");
  const logout = el("logout-btn");

  function setKey(k) { sessionStorage.setItem(KEY_NAME, k); }
  function getKey() { return sessionStorage.getItem(KEY_NAME) || ""; }
  function clearKey() { sessionStorage.removeItem(KEY_NAME); }

  async function api(path, opts = {}) {
    const headers = {
      "content-type": "application/json",
      authorization: "Bearer " + getKey(),
      ...(opts.headers || {}),
    };
    const r = await fetch(API + path, { ...opts, headers });
    let body;
    try { body = await r.json(); } catch { body = { error: { code: "http_" + r.status, message: r.statusText } }; }
    if (!r.ok) {
      const e = new Error(body?.error?.message || ("HTTP " + r.status));
      e.code = body?.error?.code || ("http_" + r.status);
      e.status = r.status;
      throw e;
    }
    return body;
  }

  async function loadDashboard() {
    try {
      const [me, usage] = await Promise.all([
        api("/v1/keys/me"),
        api("/v1/usage"),
      ]);
      el("account-line").innerHTML =
        "Signed in as <strong>" + escapeHtml(me.email) + "</strong> · " +
        '<span class="pill ' + me.tier + '">' + me.tier + "</span> · " +
        "key created " + new Date(me.created).toLocaleDateString();
      el("stat-tier").textContent = me.tier.toUpperCase();
      el("stat-tier-sub").textContent = me.monthly_limit.toLocaleString() + " req/mo";
      el("stat-scans").textContent = (usage.count ?? 0).toLocaleString();
      const limit = me.monthly_limit || 1;
      const pct = Math.min(100, ((usage.count ?? 0) / limit) * 100);
      el("stat-scans-sub").textContent = pct.toFixed(0) + "% of monthly limit";
      const bar = el("bar-scans");
      bar.style.width = pct + "%";
      bar.classList.toggle("warn", pct >= 80 && pct < 100);
      bar.classList.toggle("danger", pct >= 100);
      el("stat-blocked").textContent = (usage.blocked ?? 0).toLocaleString();
      el("stat-blocked-sub").textContent =
        usage.count > 0 ? ((usage.blocked / usage.count) * 100).toFixed(1) + "% block rate" : "—";
      el("stat-nolog").textContent = me.no_logging ? "ON" : "OFF";
      login.classList.add("hide");
      dash.classList.remove("hide");
      logout.style.display = "inline-block";
    } catch (e) {
      if (e.code === "invalid_api_key" || e.code === "missing_api_key") {
        clearKey();
        status.textContent = "Invalid key. Check that you pasted the full key (starts with is_live_ or ps_live_).";
        login.classList.remove("hide");
        dash.classList.add("hide");
        logout.style.display = "none";
      } else {
        status.textContent = "Error: " + (e.message || e);
      }
    }
  }

  function escapeHtml(s) {
    return String(s).replace(/[&<>"]/g, (c) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;"}[c]));
  }

  form.addEventListener("submit", (e) => {
    e.preventDefault();
    const k = input.value.trim();
    if (!/^(is|ps)_(live|test)_[a-z0-9]{20,}$/i.test(k)) {
      status.textContent = "That doesn't look like a valid key (expected is_live_… or ps_live_… format).";
      return;
    }
    setKey(k);
    status.textContent = "loading…";
    loadDashboard();
  });

  logout.addEventListener("click", () => {
    clearKey();
    location.reload();
  });

  // Auto-load if a key is already in session.
  if (getKey()) loadDashboard();

  // Quick scan tester
  el("test-run").addEventListener("click", async () => {
    const text = el("test-input").value.trim();
    const ctx = el("test-context").value;
    const s = el("test-status");
    const out = el("test-output");
    if (!text) { s.textContent = "paste some text first"; return; }
    s.textContent = "scanning…";
    out.textContent = "";
    try {
      const r = await api("/v1/scan", {
        method: "POST",
        body: JSON.stringify({ text, context: ctx, options: { sensitivity: "medium" } }),
      });
      s.textContent = "";
      out.textContent = JSON.stringify(r, null, 2);
      // refresh stats — usage just incremented
      loadDashboard();
    } catch (e) {
      s.textContent = "scan failed: " + e.message;
    }
  });

  // Stripe checkout buttons (re-use main page logic)
  document.querySelectorAll(".buy").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const tier = btn.getAttribute("data-tier");
      try {
        const me = await api("/v1/keys/me");
        const r = await fetch(API + "/v1/checkout", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tier, email: me.email }),
        });
        const data = await r.json();
        if (data.url) location.href = data.url;
        else alert("Checkout error: " + (data.error?.message || JSON.stringify(data)));
      } catch (e) { alert("Failed: " + e.message); }
    });
  });
})();
