// Copy buttons, and the auto-submit form for the SAML POST binding.
document.addEventListener("click", async (e) => {
  const btn = e.target.closest("button.copy");
  if (!btn) return;
  const text = btn.hasAttribute("data-copy-pre")
    ? btn.parentElement.querySelector("pre").textContent
    : btn.dataset.copy;
  try {
    await navigator.clipboard.writeText(text);
    flash(btn, "Copied");
  } catch {
    // The clipboard API needs a secure context; select the text instead.
    const target = btn.parentElement.querySelector("pre, code");
    const range = document.createRange();
    range.selectNodeContents(target);
    getSelection().removeAllRanges();
    getSelection().addRange(range);
    flash(btn, "Press Ctrl+C");
  }
});

function flash(btn, label) {
  btn.classList.add("done");
  const tip = document.createElement("span");
  tip.className = "tip";
  tip.setAttribute("role", "status");
  tip.textContent = label;
  btn.appendChild(tip);
  setTimeout(() => { btn.classList.remove("done"); tip.remove(); }, 1500);
}

document.querySelectorAll("form[data-autosubmit]").forEach((f) => f.submit());

// Theme switch: system, light, dark, in that order. Remembered per browser.
(function () {
  const order = ["system", "light", "dark"];
  const root = document.documentElement;
  const current = () => root.getAttribute("data-theme") || "system";
  const label = (t) => "Theme: " + t;
  const sync = () => document.querySelectorAll("[data-theme-toggle]").forEach((b) => {
    b.setAttribute("aria-label", label(current()));
    b.title = label(current());
    if (b.classList.contains("theme-text")) b.textContent = label(current());
  });
  document.addEventListener("click", (e) => {
    if (!e.target.closest("[data-theme-toggle]")) return;
    const next = order[(order.indexOf(current()) + 1) % order.length];
    if (next === "system") root.removeAttribute("data-theme");
    else root.setAttribute("data-theme", next);
    try { localStorage.setItem("ssobench.theme", next); } catch (err) {}
    sync();
  });
  sync();
})();

// Drop one-time notices (?done=...) from the address, so a reload doesn't repeat them.
(function () {
  const u = new URL(location.href);
  if (!u.searchParams.has("done")) return;
  u.searchParams.delete("done");
  u.searchParams.delete("added");
  try { history.replaceState(null, "", u.pathname + (u.search || "") + u.hash); } catch (e) {}
})();

// Forms that hand the browser to the identity provider in a new tab leave a
// note behind in this one.
document.addEventListener("submit", (e) => {
  // A sign-out that continues at the identity provider in a new tab: this
  // tab goes back to the sign-in page once the sign-out has reached
  // SSOBench, which ends the session before redirecting.
  const then = e.target.closest("form[data-then]");
  if (then) setTimeout(() => location.replace(then.dataset.then), 1200);
  const f = e.target.closest("form[data-new-tab]");
  if (!f) return;
  setTimeout(() => {
    const note = document.createElement("p");
    note.className = "note new-tab-note";
    note.setAttribute("role", "status");
    note.textContent = f.dataset.newTab;
    f.replaceWith(note);
  }, 0);
});

// On narrow screens the app tabs scroll sideways; keep the current one in view.
document.querySelectorAll(".tabs [aria-current], .subtabs [aria-current]").forEach((a) => {
  a.scrollIntoView({ block: "nearest", inline: "nearest" });
});

// Passkeys for the console: add one under Settings, sign in with one.
(function () {
  const enc = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  const dec = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
  const post = async (url, body) => {
    const r = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : "{}" });
    const data = await r.json().catch(() => ({ error: "SSOBench sent an unexpected answer." }));
    if (!r.ok) throw new Error(data.error || "Something went wrong.");
    return data;
  };
  const show = (el, msg) => {
    const box = el.querySelector("[data-passkey-error]") || el.parentElement.querySelector("[data-passkey-error]");
    if (!box) return;
    box.querySelector("p").textContent = msg;
    box.hidden = !msg;
  };
  // The browser's own errors, in plain words.
  const why = (e) => {
    if (e && e.name === "NotAllowedError") return "The passkey request was canceled or timed out.";
    if (e && e.name === "InvalidStateError") return "That passkey is already added.";
    if (e && e.name === "SecurityError") return "The browser refused passkeys at this address.";
    return (e && e.message) || "Something went wrong.";
  };
  const supported = () => window.PublicKeyCredential && window.isSecureContext;

  const add = document.querySelector("form[data-passkey-add]");
  if (add) {
    add.addEventListener("submit", async (e) => {
      e.preventDefault();
      const btn = add.querySelector("button");
      show(add, "");
      if (!supported()) { show(add, "This browser can't use passkeys here."); return; }
      btn.disabled = true;
      try {
        const o = await post("/settings/passkeys/options");
        o.challenge = dec(o.challenge);
        o.user.id = dec(o.user.id);
        o.excludeCredentials = (o.excludeCredentials || []).map((c) => ({ ...c, id: dec(c.id) }));
        const cred = await navigator.credentials.create({ publicKey: o });
        const done = await post("/settings/passkeys", {
          name: add.querySelector("[name=name]").value,
          clientDataJSON: enc(cred.response.clientDataJSON),
          attestationObject: enc(cred.response.attestationObject),
        });
        location.assign(done.next);
      } catch (err) {
        show(add, why(err));
        btn.disabled = false;
      }
    });
  }

  const login = document.querySelector("[data-passkey-login]");
  if (login) {
    login.addEventListener("click", async () => {
      show(login, "");
      if (!supported()) { show(login, "This browser can't use passkeys here."); return; }
      login.disabled = true;
      try {
        const o = await post("/console/passkey/options");
        o.challenge = dec(o.challenge);
        o.allowCredentials = o.allowCredentials.map((c) => ({ ...c, id: dec(c.id) }));
        const cred = await navigator.credentials.get({ publicKey: o });
        const done = await post("/console/passkey?next=" + encodeURIComponent(login.dataset.next || "/"), {
          id: enc(cred.rawId),
          clientDataJSON: enc(cred.response.clientDataJSON),
          authenticatorData: enc(cred.response.authenticatorData),
          signature: enc(cred.response.signature),
        });
        location.assign(done.next);
      } catch (err) {
        show(login, why(err));
        login.disabled = false;
      }
    });
  }
})();
