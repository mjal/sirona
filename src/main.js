/*
 * This software is licensed under the GNU Affero General Public License (AGPL).
 * By using, modifying, or distributing this software, you agree to the terms and conditions of the AGPL.
 * A copy of the license can be found in the LICENSE file.
 *
 * Whenver possible we try to use the hungarian notation for variable names.
 * It can be useful to quickly assess if a variable is a number, curve point,
 * hex string, or anything else.
 * Here are the prefixes:
 *
 * - n for BigInt
 * - p for curve points
 * - s for strings
 * - h for hexadecimal strings
 */

import { clear, logError, showResult } from "./utils.js";
import load from "./load.js";
import checkFiles from "./checkFiles.js";
import checkSetup from "./checkSetup.js";
import checkBallot from "./checkBallot.js";
import checkEncryptedTally from "./checkEncryptedTally.js";
import checkPartialDecryptions from "./checkPartialDecryptions.js";
import checkResult from "./checkResult.js";

export default function (fileEntries) {
  clear();
  try {
    const state = load(fileEntries);
    checkFiles(state);
    checkSetup(state);
    for (let i = 0; i < state.ballots.length; i++) {
      checkBallot(state, state.ballots[i]);
    }
    checkEncryptedTally(state);
    checkPartialDecryptions(state);
    checkResult(state);
  } catch (e) {
    logError("top", "Something wrong happened.");
    console.error(e);
  }
  showResult();
}
