/*
 * This software is licensed under the GNU Affero General Public License (AGPL).
 * By using, modifying, or distributing this software, you agree to the terms and conditions of the AGPL.
 * A copy of the license can be found in the LICENSE file.
 *
 * Whenver possible we try to use the hungarian notation for variable names.
 * It can be useful to quickly know if a variable is a number, curve point,
 * hex string, or something else.
 * Here are the prefixes:
 *
 * - n for BigInt
 * - p for curve points
 * - s for strings
 * - h for hexadecimal strings
 */

import _ from "lodash";
import {
  clear,
  getErrors,
  logError,
  logSuccess,
  showResult,
  _async,
} from "./utils.js";
import load from "./load.js";
import checkFiles from "./checkFiles.js";
import checkSetup from "./checkSetup.js";
import checkBallot from "./checkBallot.js";
import checkEncryptedTally from "./checkEncryptedTally.js";
import checkPartialDecryptions from "./checkPartialDecryptions.js";
import checkResult from "./checkResult.js";

export default async function (fileEntries) {
  clear();
  document.getElementById("import").classList.add("uk-hidden");
  document.getElementById("spinner").classList.remove("uk-hidden");
  try {
    const state = load(fileEntries);

    await _async(checkFiles, state);
    await _async(checkSetup, state);
    if (!getErrors()) {
      logSuccess("top", "Database valid.");
    }

    for (let i = 0; i < state.ballots.length; i++) {
      await _async(checkBallot, state, state.ballots[i]);
    }
    await _async(checkEncryptedTally, state);
    await _async(checkPartialDecryptions, state);
    await _async(checkResult, state);
    document.getElementById("spinner").classList.add("uk-hidden");
    document.getElementById("content").classList.remove("uk-hidden");
    // Add a text to element info-name
    console.log(state.setup.payload.election);
    document.getElementById("info-name").textContent
      = state.setup.payload.election.name;
    document.getElementById("info-description").textContent
      = state.setup.payload.election.description;
    document.getElementById("info-uuid").textContent
      = state.setup.payload.election.uuid;
    document.getElementById("info-fingerprint").textContent
      = state.setup.fingerprint;

    const electionInfoTemplate = document.getElementById("election-info-template").innerHTML;
    const electionInfoCompiled = _.template(electionInfoTemplate)({
      name: state.setup.payload.election.name,
      description: state.setup.payload.election.description,
      uuid: state.setup.payload.election.uuid,
      fingerprint: state.setup.fingerprint,
      countBallots: state.ballots.length,
    });
    document.getElementById("election-info").innerHTML = electionInfoCompiled;

    UIkit.tab(document.querySelector('.uk-tab')).show(1);

    const resultsCardTemplate = document.getElementById("election-results-template").innerHTML;
    const resultsCardCompiled = _.template(resultsCardTemplate)({
      result: state.result.payload.result,
      questions: state.setup.payload.election.questions,
    });
    document.getElementById("election-results").innerHTML = resultsCardCompiled;
  } catch (e) {
    logError("top", "Something wrong happened.");
    console.error(e);
  }
  showResult();
}
