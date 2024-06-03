import _ from "lodash";

export const assert = console.assert;

export function log(section, message, classeName = "", prefix = "") {
  const p = document.createElement("p");
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

export function logAlert(message, className) {
  // Use a _.template and a uikit alert component
  const alertTemplate = `<div class='uk-margin-top ${className}' uk-alert><a class='uk-alert-close' uk-close></a><p><%- message %></p></div>`;
  const alertCompiled = _.template(alertTemplate)({ message });
  document.getElementById("alerts").innerHTML += alertCompiled;
}

export function logAlertSuccess(message) {
  logAlert(message, "uk-alert-success");
}

export function logAlertError(message) {
  logAlert(message, "uk-alert-danger");
}


export function check(section, message, test, log = false) {
  if (test) {
    if (log) {
      logSuccess(section, message);
    }
  } else {
    logError(section, message);
  }
}

export function getErrors() {
  return errors;
}

export function clear() {
  errors = 0;
  document.getElementById("top").innerHTML = "";
  document.getElementById("database").innerHTML = "";
  document.getElementById("setup").innerHTML = "";
  document.getElementById("ballots").innerHTML = "";

  logSuccess("top", "In progress...");
}

export function showResult() {
  if (errors === 0) {
    logAlertSuccess("Finished. All checks passed.");
  } else {
    logAlertError("Finished. Some checks failed.");
  }
}

export async function _async(f, ...args) {
  return new Promise((resolve, reject) => {
    requestAnimationFrame(() => {
      f(...args);
      resolve();
    });
  });
}
