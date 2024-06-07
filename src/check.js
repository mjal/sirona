import _ from "lodash";
import { clear, getErrors, logError, logSuccess, _async } from "./utils.js";
import load from "./load.js";
import checkFiles from "./checkFiles.js";
import checkSetup from "./checkSetup.js";
import checkBallot from "./checkBallot.js";
import checkEncryptedTally from "./checkEncryptedTally.js";
import checkPartialDecryptions from "./checkPartialDecryptions.js";
import checkResult from "./checkResult.js";

export default async function (fileEntries) {
  clear();
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
    return state;
    //showResult(state);
  } catch (e) {
    logError("top", "Something wrong happened.");
    console.error(e);
  }
  return null;
}
