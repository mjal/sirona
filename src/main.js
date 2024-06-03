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
  setupUI,
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
  setupUI();
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
    if (state.encryptedTally) {
      await _async(checkEncryptedTally, state);
    }
    if (state.partialDecryptions.length > 0) {
      await _async(checkPartialDecryptions, state);
    }
    if (state.result) {
      await _async(checkResult, state);
    }
    showResult(state);
  } catch (e) {
    logError("top", "Something wrong happened.");
    console.error(e);
  }
}
