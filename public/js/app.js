// PromptShield landing-page glue. No bundler — keep it small and readable.
(function () {
  const API = window.PROMPTSHIELD_API_BASE || "https://promptshield.bch1212.workers.dev";
  // Replace API base placeholder in code snippets too.
  document.querySelectorAll(".api-base").forEach((el) => (el.textContent = API));

  const ta = document.getElementById("demo-input");
  const out = document.getElementById("demo-output");
  const status = document.getElementById("demo-status");
  const ctxSel = document.getElementById("demo-context");
  const senSel = document.getElementById("demo-sensitivity");
  const go = document.getElementById("demo-go");

  document.querySelectorAll(".examples button.example").forEach((b) => {
    b.addEventListener("click", () => {
      ta.value = b.getAttribute("data-text").replace(/\\n/g, "\n");
      ta.focus();
    });
  });

  async function runDemo() {
    const text = ta.value.trim();
    if (!text) { status.textContent = "paste some text first"; return; }
    status.textContent = "scanning…";
    out.textContent = "";
    try {
      const r = await fetch(API + "/v1/demo", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          text,
          context: ctxSel.value,
          options: { sensitivity: senSel.value },
        }),
      });
      const data = await r.json();
      status.textContent = "";
      const verdict = data.safe
        ? '<span class="safe">SAFE</span>'
        : '<span class="unsafe">UNSAFE — ' + (data.threat_type || "") + "</span>";
      out.innerHTML =
        verdict +
        "  confidence=" +
        (data.confidence ?? "?") +
        "\n\n" +
        JSON.stringify(data, null, 2);
    } catch (e) {
      status.textContent = "scan failed: " + e.message;
    }
  }
  go && go.addEventListener("click", runDemo);
  ta && ta.addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") runDemo();
  });

  // Signup form
  const form = document.getElementById("signup-form");
  const formStatus = document.getElementById("signup-status");
  if (form) {
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const email = document.getElementById("signup-email").value.trim();
      formStatus.textContent = "creating key…";
      try {
        const r = await fetch(API + "/v1/keys", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ email }),
        });
        const data = await r.json();
        if (data.error) {
          formStatus.textContent = "error: " + data.error.message;
          return;
        }
        formStatus.innerHTML = data.email_sent
          ? "✓ key sent to <strong>" + email + "</strong> — check your inbox"
          : "✓ key: <code>" + (data.api_key || "(see email)") + "</code>";
      } catch (err) {
        formStatus.textContent = "signup failed: " + err.message;
      }
    });
  }

  // Stripe Checkout
  document.querySelectorAll(".buy").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const tier = btn.getAttribute("data-tier");
      const email = prompt("Email for the subscription:");
      if (!email) return;
      btn.textContent = "redirecting…";
      btn.disabled = true;
      try {
        const r = await fetch(API + "/v1/checkout", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ tier, email }),
        });
        const data = await r.json();
        if (data.url) window.location = data.url;
        else {
          alert("Checkout error: " + (data.error?.message || JSON.stringify(data)));
          btn.textContent = "Start " + tier.charAt(0).toUpperCase() + tier.slice(1);
          btn.disabled = false;
        }
      } catch (e) {
        alert("Checkout failed: " + e.message);
      }
    });
  });
})();
