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

  document.getElementById("ballot-list").innerHTML = "";

  logSuccess("top", "In progress...");
}

export function setupUI() {
  document.getElementById("import").classList.add("uk-hidden");
  document.getElementById("spinner").classList.remove("uk-hidden");

  document.getElementById("find-your-ballot").addEventListener("click", () => {
    UIkit.tab(document.querySelector('.uk-tab')).show(2);
  });
}

export function showResult(state) {
  if (errors === 0) {
    logAlertSuccess("Finished. All checks passed.");
  } else {
    logAlertError("Finished. Some checks failed.");
  }

  document.getElementById("spinner").classList.add("uk-hidden");
  document.getElementById("actions").classList.remove("uk-hidden");

  const electionInfoTemplate = document.getElementById("election-info-template").innerHTML;
  const electionInfoCompiled = _.template(electionInfoTemplate)({
    name: state.setup.payload.election.name,
    description: state.setup.payload.election.description,
    uuid: state.setup.payload.election.uuid,
    fingerprint: state.setup.fingerprint,
    countBallots: state.ballots.length,
  });
  document.getElementById("election-info").innerHTML = electionInfoCompiled;

  const generateBallotFormTemplate = document.getElementById("generate-ballot-form-template").innerHTML;
  const generateBallotFormCompiled = _.template(generateBallotFormTemplate)({
    questions: state.setup.payload.election.questions,
  });
  document.getElementById("generate-ballot-form").innerHTML = generateBallotFormCompiled;

  // Show election infos
  UIkit.tab(document.querySelector('.uk-tab')).show(1);

  const renderBallots = (ballots) => {
    document.getElementById("ballot-list").innerHTML = "";
    for (let i = 0; i < ballots.length; i++) {
      const ballotCardTemplate =
        document.getElementById("election-ballot-template").innerHTML;
      const ballotCardCompiled = _.template(ballotCardTemplate)({
        state: state,
        ballot: ballots[i]
      });
      document.getElementById("ballot-list").innerHTML += ballotCardCompiled;
    }
  }
  renderBallots(state.ballots);

  document.getElementById("ballot-search").addEventListener("input", () => {
    const ballots = state.ballots.filter((ballot) => {
      return ballot.tracker === document.getElementById("ballot-search").value;
    });
    renderBallots(ballots);
  });

  if (state.result) {
    const resultsCardTemplate = document.getElementById("election-results-template").innerHTML;
    const resultsCardCompiled = _.template(resultsCardTemplate)({
      result: state.result.payload.result,
      questions: state.setup.payload.election.questions,
    });
    document.getElementById("election-results").innerHTML = resultsCardCompiled;
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
