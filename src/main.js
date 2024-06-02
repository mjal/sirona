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

    const statsCardTemplate = document.getElementById("stats-card-template").innerHTML;
    const statsCardCompiled = _.template(statsCardTemplate)({
        ballots: state.ballots.length,
        trustees: state.setup.payload.trustees.length,
        partialDecryptions: state.partialDecryptions.length,
        decryptedTally: state.encryptedTally.payload.encrypted_tally.length,
      });
    document.getElementById("stats-card").innerHTML = statsCardCompiled;

    const electionCardTemplate = document.getElementById("election-card-template").innerHTML;
    const electionCardCompiled = _.template(electionCardTemplate)({
      name: state.setup.payload.election.name,
      description: state.setup.payload.election.description,
      uuid: state.setup.payload.election.uuid,
      fingerprint: state.setup.fingerprint,
    });
    document.getElementById("election-card").innerHTML = electionCardCompiled;

    const resultsCardTemplate = document.getElementById("results-card-template").innerHTML;
    const resultsCardCompiled = _.template(resultsCardTemplate)({
      result: state.result.payload.result,
      questions: state.setup.payload.election.questions,
    });
    document.getElementById("results-card").innerHTML = resultsCardCompiled;
    console.log(state.setup.payload.election.questions);
  } catch (e) {
    logError("top", "Something wrong happened.");
    console.error(e);
  }
  showResult();
}
