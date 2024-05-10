export let assert = console.assert;

export function log(section, message, classeName = "", prefix = "") {
  let p = document.createElement("p");
  p.className = classeName;
  p.textContent = prefix + message;
  document.getElementById(section).appendChild(p);
}

export function logSuccess(section, message) {
  log(section, message, "success", "✔ ");
}

let errors = 0;
export function logError(section, message) {
  log(section, message, "error", "✘ ");
  errors++;
}

export function check(section, message, test) {
  if (test) {
    logSuccess(section, message);
  } else {
    logError(section, message);
  }
}

export function clear() {
  errors = 0;
  document.getElementById("top").innerHTML = "";
  document.getElementById("database").innerHTML = "";
  document.getElementById("setup").innerHTML = "";
  document.getElementById("ballots").innerHTML = "";
}

export function showResult() {
  if (errors === 0) {
    logSuccess("top", "All checks passed.");
  } else {
    logError("top", "Some checks failed.");
  }
}
