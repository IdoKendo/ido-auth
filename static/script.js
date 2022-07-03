const { startRegistration, startAuthentication } = SimpleWebAuthnBrowser;

const registered = document.getElementById("registered");
const authenticated = document.getElementById("authenticated");
const registerButton = document.getElementById("register");
const authenticateButton = document.getElementById("authenticate");

async function checkVerification(resp, span) {
  const respJson = await resp.json();
  const { verified, msg } = respJson;
  if (verified) {
    span.innerHTML = "✅";
  } else {
    span.innerHTML = `❌ (${msg})`;
  }
}

registerButton.addEventListener("click", async () => {
  registered.innerHTML = "";
  const username = document.querySelector("input").value;
  let resp = await fetch("http://localhost:8000/register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: username }),
  });
  const options = (await resp.json()).options;
  try {
    resp = await startRegistration(options);
    resp.username = username;
  } catch (err) {
    registered.innerHTML = `❌ (${err})`;
    throw new Error(err);
  }
  resp = await fetch("http://localhost:8000/verify-register", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(resp),
  });
  await checkVerification(resp, registered);
});

authenticateButton.addEventListener("click", async () => {
  authenticated.innerHTML = "";
  const username = document.querySelector("input").value;
  let resp = await fetch("http://localhost:8000/login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ username: username }),
  });
  if (resp.status === 401) {
    authenticated.innerHTML = `❌ (Unauthorized username.)`;
    throw new Error("Unauthorized username.");
  }
  const options = (await resp.json()).options;
  try {
    resp = await startAuthentication(options);
    resp.username = username;
  } catch (err) {
    authenticated.innerHTML = `❌ (${err})`;
    throw new Error(err);
  }
  resp = await fetch("http://localhost:8000/verify-login", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(resp),
  });
  await checkVerification(resp, authenticated);
});
