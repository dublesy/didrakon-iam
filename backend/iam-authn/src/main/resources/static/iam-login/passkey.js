// 패스키(WebAuthn) 로그인·등록. 로그인 화면(data-passkey-login)과 패스키 관리 화면(data-passkey-register)이 쓴다.
// 서버 쪽은 Spring Security 의 WebAuthn 엔드포인트다. 요청에는 화면이 data-* 로 넘긴 CSRF 토큰을 붙인다.
(() => {
  "use strict";

  const base64url = {
    encode(buffer) {
      const base64 = window.btoa(String.fromCharCode(...new Uint8Array(buffer)));
      return base64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
    },
    decode(value) {
      const binary = window.atob(value.replace(/-/g, "+").replace(/_/g, "/"));
      return Uint8Array.from(binary, (c) => c.charCodeAt(0)).buffer;
    },
  };

  function post(url, holder, body) {
    return fetch(url, {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json", [holder.dataset.csrfHeader]: holder.dataset.csrfToken },
      body: body ? JSON.stringify(body) : undefined,
    });
  }

  async function fetchOptions(holder) {
    const response = await post(holder.dataset.options, holder);
    if (!response.ok) throw new Error(`options HTTP ${response.status}`);
    return response.json();
  }

  const decodeCredentials = (list) => (list || []).map((c) => ({ ...c, id: base64url.decode(c.id) }));

  function showError(holder, message) {
    const box = holder.querySelector("[data-passkey-error]");
    box.textContent = message;
    box.hidden = false;
  }

  const supported = Boolean(window.PublicKeyCredential && navigator.credentials);

  const login = document.querySelector("[data-passkey-login]");
  if (login && supported) {
    login.hidden = false;
    const button = login.querySelector("button");
    button.addEventListener("click", async () => {
      button.disabled = true;
      try {
        const options = await fetchOptions(login);
        const credential = await navigator.credentials.get({
          publicKey: { ...options, challenge: base64url.decode(options.challenge), allowCredentials: decodeCredentials(options.allowCredentials) },
        });
        const r = credential.response;
        const result = await post(login.dataset.submit, login, {
          id: credential.id,
          rawId: base64url.encode(credential.rawId),
          response: {
            authenticatorData: base64url.encode(r.authenticatorData),
            clientDataJSON: base64url.encode(r.clientDataJSON),
            signature: base64url.encode(r.signature),
            userHandle: r.userHandle ? base64url.encode(r.userHandle) : undefined,
          },
          type: credential.type,
          clientExtensionResults: credential.getClientExtensionResults(),
          authenticatorAttachment: credential.authenticatorAttachment,
        });
        // 성공·실패 모두 서버가 정한 곳(원래 가려던 곳 또는 로그인 화면의 안내)으로 간다
        const { redirectUrl } = await result.json();
        window.location.href = redirectUrl;
      } catch (e) {
        console.error(e);
        showError(login, "패스키 인증을 마치지 못했습니다. 취소했거나 시간이 지났다면 다시 시도하세요.");
        button.disabled = false;
      }
    });
  }

  const register = document.querySelector("[data-passkey-register]");
  if (register) {
    if (supported) register.hidden = false;
    else document.querySelector("[data-passkey-unsupported]").hidden = false;
    register.addEventListener("submit", async (event) => {
      event.preventDefault();
      const button = register.querySelector("button");
      button.disabled = true;
      try {
        const options = await fetchOptions(register);
        const credential = await navigator.credentials.create({
          publicKey: {
            ...options,
            user: { ...options.user, id: base64url.decode(options.user.id) },
            challenge: base64url.decode(options.challenge),
            excludeCredentials: decodeCredentials(options.excludeCredentials),
          },
        });
        const r = credential.response;
        const result = await post(register.dataset.submit, register, {
          publicKey: {
            label: register.elements.label.value.trim(),
            credential: {
              id: credential.id,
              rawId: base64url.encode(credential.rawId),
              response: {
                attestationObject: base64url.encode(r.attestationObject),
                clientDataJSON: base64url.encode(r.clientDataJSON),
                transports: r.getTransports ? r.getTransports() : [],
              },
              type: credential.type,
              clientExtensionResults: credential.getClientExtensionResults(),
              authenticatorAttachment: credential.authenticatorAttachment,
            },
          },
        });
        const body = result.ok ? await result.json() : null;
        if (!body || !body.success) throw new Error(`register HTTP ${result.status}`);
        window.location.href = register.dataset.done;
      } catch (e) {
        console.error(e);
        // 이미 이 기기에 등록한 패스키면 브라우저가 InvalidStateError 를 낸다
        showError(
          register,
          e && e.name === "InvalidStateError"
            ? "이 기기에는 이미 패스키를 등록했습니다."
            : "패스키를 등록하지 못했습니다. 취소했거나 시간이 지났다면 다시 시도하세요.",
        );
        button.disabled = false;
      }
    });
  }

  // 삭제처럼 되돌릴 수 없는 요청은 한 번 더 묻는다
  document.querySelectorAll("form[data-confirm]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (!window.confirm(form.dataset.confirm)) event.preventDefault();
    });
  });
})();
