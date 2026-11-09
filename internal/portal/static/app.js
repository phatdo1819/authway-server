"use strict";

const PROBLEMS = {
  forbidden: "This page works only through the VPN. Connect it, then open this page again.",
  blocked: "This VPN configuration is blocked. Ask your administrator.",
  no_user: "This VPN configuration isn't linked to a user. Ask your administrator.",
  no_otp: "Your account has no authenticator app set up. Ask your administrator.",
  device_required: "This VPN accepts only the Authway app on your enrolled computer.",
  unreachable: "The server doesn't answer. Check that the VPN is connected.",
};

const LOGIN_ERRORS = {
  invalid_credentials: "Wrong username, password or code.",
  no_user: PROBLEMS.no_user,
  no_otp: PROBLEMS.no_otp,
  blocked: PROBLEMS.blocked,
  forbidden: PROBLEMS.forbidden,
  device_required: PROBLEMS.device_required,
  device_mismatch: "This VPN configuration is enrolled on another device. Ask your administrator.",
  device_not_enrolled: "No device can be enrolled for this VPN configuration now. Ask your administrator.",
  challenge_expired: "The login took too long. Try again.",
};

const $ = (id) => document.getElementById(id);
let refreshTimer = null;

function show(id) {
  for (const state of document.querySelectorAll(".state")) {
    state.hidden = state.id !== id;
  }
}

async function call(method, path, body) {
  const options = { method, headers: { Accept: "application/json" }, cache: "no-store" };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  let response;
  try {
    response = await fetch(path, options);
  } catch {
    return { status: 0, data: { error: "unreachable" } };
  }
  let data = {};
  try {
    data = await response.json();
  } catch {
    data = { error: "unreachable" };
  }
  return { status: response.status, data };
}

function problem(code) {
  $("problem-text").textContent = PROBLEMS[code] || "Something went wrong. Try again in a moment.";
  show("problem");
}

function formatTime(iso) {
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) {
    return iso;
  }
  return date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

function schedule(seconds) {
  clearTimeout(refreshTimer);
  refreshTimer = setTimeout(load, seconds * 1000);
}

async function load() {
  const { status, data } = await call("GET", "api/status");
  if (status !== 200) {
    problem(data.error);
    return;
  }
  if (data.server) {
    $("server").textContent = data.server;
    document.title = `${data.server} · VPN login`;
  }
  if (data.authenticated) {
    $("user").textContent = data.user || "";
    $("expires").textContent = data.expires ? formatTime(data.expires) : "";
    show("done");
    // the page follows the end of the session
    const left = data.expires ? (new Date(data.expires).getTime() - Date.now()) / 1000 : 60;
    schedule(Math.max(5, Math.min(60, left + 2)));
    return;
  }
  for (const code of ["blocked", "no_user", "no_otp"]) {
    if (data[code]) {
      problem(code);
      return;
    }
  }
  if (data.device && data.device.required) {
    problem("device_required");
    return;
  }
  $("otp-field").hidden = !data.otp_required;
  $("otp").required = Boolean(data.otp_required);
  show("login");
  if (!$("username").value) {
    $("username").focus();
  }
}

function setError(text) {
  $("error").textContent = text;
  $("error").hidden = !text;
}

async function login(event) {
  event.preventDefault();
  const username = $("username").value.trim();
  const password = $("password").value;
  const otp = $("otp").value.replace(/\s+/g, "");
  if (!username || !password || (!$("otp-field").hidden && !/^[0-9]{6}$/.test(otp))) {
    setError($("otp-field").hidden ? "Enter your username and password." : "Enter your username, password and the 6-digit code.");
    return;
  }
  setError("");
  $("submit").disabled = true;
  $("submit").textContent = "Logging in…";
  const { status, data } = await call("POST", "api/login", { username, password, otp });
  $("submit").disabled = false;
  $("submit").textContent = "Log in";
  if (status === 200) {
    $("password").value = "";
    $("otp").value = "";
    load();
    return;
  }
  $("otp").value = "";
  if (status === 429) {
    const seconds = Number(data.retry_after) || 60;
    setError(`Too many attempts. Wait ${seconds} seconds, then try again.`);
    return;
  }
  setError(LOGIN_ERRORS[data.error] || "The login failed. Try again in a moment.");
}

async function logout() {
  $("logout").disabled = true;
  await call("POST", "api/logout", {});
  $("logout").disabled = false;
  load();
}

$("login").addEventListener("submit", login);
$("logout").addEventListener("click", logout);
$("retry").addEventListener("click", () => {
  show("loading");
  load();
});
document.addEventListener("visibilitychange", () => {
  if (document.visibilityState === "visible") {
    load();
  }
});
load();
