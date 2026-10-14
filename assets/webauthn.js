// Passkey ceremonies for the approval and enrollment pages; no build step
"use strict";

(() => {
  const main = document.querySelector("main[data-kind]");
  if (!main) return;
  const base = main.dataset.base;
  const status = document.getElementById("status");

  const toBuffer = (text) => {
    const base64 = text.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "===".slice((base64.length + 3) % 4);
    return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)).buffer;
  };
  const toText = (buffer) => {
    if (!buffer) return null;
    let binary = "";
    for (const byte of new Uint8Array(buffer)) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  };
  const post = async (path, body) => {
    const response = await fetch(base + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.error || `request failed (${response.status})`);
    return data;
  };
  const show = (text) => { status.textContent = text; };
  const setBusy = (busy) => {
    for (const button of document.querySelectorAll("button")) button.disabled = busy;
  };
  let countdown = null;
  // outcome is approved, denied or expired; the page styles it as a banner in place of the buttons
  const finish = (outcome, text) => {
    if (countdown) clearInterval(countdown);
    status.textContent = text;
    const hint = document.createElement("small");
    hint.textContent = "You can close this page.";
    status.append(hint);
    main.dataset.outcome = outcome;
    for (const button of document.querySelectorAll("button")) button.disabled = true;
    window.scrollTo({ top: 0, behavior: "smooth" });
  };

  if (!window.PublicKeyCredential) {
    show("This browser does not support passkeys; open the link in Safari.");
  }

  if (main.dataset.kind === "approve") {
    const left = document.getElementById("left");
    if (left) {
      let seconds = Number(left.dataset.seconds);
      const tick = () => {
        if (seconds <= 0) { finish("expired", "Expired"); return; }
        const minutes = Math.floor(seconds / 60);
        left.textContent = minutes > 0 ? `${minutes}m ${seconds % 60}s` : `${seconds}s`;
        seconds -= 1;
      };
      tick();
      countdown = setInterval(tick, 1000);
    }

    const approve = async (button) => {
      const choice = button.dataset.choice;
      const { ceremony, options } = await post("/options", { choice });
      const publicKey = options.publicKey;
      publicKey.challenge = toBuffer(publicKey.challenge);
      for (const credential of publicKey.allowCredentials || []) {
        credential.id = toBuffer(credential.id);
      }
      const assertion = await navigator.credentials.get({ publicKey });
      const response = assertion.response;
      const result = await post("/confirm", {
        ceremony,
        credential: {
          id: assertion.id,
          rawId: toText(assertion.rawId),
          type: assertion.type,
          response: {
            authenticatorData: toText(response.authenticatorData),
            clientDataJSON: toText(response.clientDataJSON),
            signature: toText(response.signature),
            userHandle: toText(response.userHandle),
          },
          extensions: assertion.getClientExtensionResults(),
        },
      });
      // name the choice so a session or client grant reads differently from a single call
      const label = button.textContent.trim().replace(/^Approve\b/, "Approved");
      finish("approved", `\u2713 ${label}`);
    };

    for (const button of document.querySelectorAll("button[data-choice]")) {
      button.addEventListener("click", async () => {
        const choice = button.dataset.choice;
        setBusy(true);
        show(choice === "deny" ? "Denying..." : "Waiting for your passkey...");
        try {
          if (choice === "deny") {
            await post("/deny", {});
            finish("denied", "\u2715 Denied");
          } else {
            await approve(button);
          }
        } catch (error) {
          show(error.message || String(error));
          setBusy(false);
        }
      });
    }
  }

  if (main.dataset.kind === "enroll") {
    const button = document.getElementById("enroll");
    button.addEventListener("click", async () => {
      const label = document.getElementById("label").value.trim();
      if (!label) { show("Enter a label first."); return; }
      setBusy(true);
      show("Waiting for your passkey...");
      try {
        const { ceremony, options } = await post("/options", { label });
        const publicKey = options.publicKey;
        publicKey.challenge = toBuffer(publicKey.challenge);
        publicKey.user.id = toBuffer(publicKey.user.id);
        for (const credential of publicKey.excludeCredentials || []) {
          credential.id = toBuffer(credential.id);
        }
        const created = await navigator.credentials.create({ publicKey });
        const response = created.response;
        await post("/finish", {
          ceremony,
          credential: {
            id: created.id,
            rawId: toText(created.rawId),
            type: created.type,
            response: {
              attestationObject: toText(response.attestationObject),
              clientDataJSON: toText(response.clientDataJSON),
              transports: response.getTransports ? response.getTransports() : null,
            },
            extensions: created.getClientExtensionResults(),
          },
        });
        finish("approved", "\u2713 Passkey added");
      } catch (error) {
        show(error.message || String(error));
        setBusy(false);
      }
    });
  }
})();
