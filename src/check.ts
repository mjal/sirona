import { log } from "./logger";
import { _async } from "./utils";
import load from "./load";
import checkFiles from "./checkFiles";
import checkSetup from "./checkSetup";
import checkEncryptedTally from "./checkEncryptedTally";
import checkPartialDecryptions from "./checkPartialDecryptions";
import checkResult from "./checkResult";
import * as Ballot from "./ballot";
import * as Shuffle from "./Shuffle";

export default async function (fileEntries) {
  try {
    Ballot.resetProcessedBallots();
    let state: any = load(fileEntries);

    await _async(checkFiles, state);
    await _async(checkSetup, state);
    for (let i = 0; i < state.ballots.length; i++) {
      await _async(Ballot.check, state, state.ballots[i]);
    }
    for (let i = 0; i < state.shuffles.length; i++) {
      await _async(Shuffle.check, state, state.shuffles[i]);
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
    log("top", true, "Verification done.");
    return state;
  } catch (e) {
    log("top", false, "Something wrong happened.");
    console.error(e);
  }
  return null;
}
