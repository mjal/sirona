import { log } from "./logger";
import { _async } from "./utils";
import load from "./load";
import checkFiles from "./checkFiles";
import checkSetup from "./checkSetup";
import checkEncryptedTally from "./checkEncryptedTally";
import checkPartialDecryptions from "./checkPartialDecryptions";
import * as Ballot from "./ballot";
import * as Shuffle from "./Shuffle";
import * as Result from "./Result";

export default async function (fileEntries) {
  try {
    Ballot.resetProcessedBallots();
    let state: any = load(fileEntries);

    await _async(checkFiles, state);
    await _async(checkSetup, state);
    for (let i = 0; i < state.ballots.length; i++) {
      await _async(Ballot.verify, state, state.ballots[i]);
    }

    if (!state.encryptedTally) return state;
    await _async(checkEncryptedTally, state);

    // Check shuffles
    let tally = state.encryptedTally.payload.encrypted_tally;
    for (let i = 0; i < state.shuffles.length; i++) {
      await _async(Shuffle.verify, state, state.shuffles[i], tally);
      tally = state.shuffles[i].payload.payload.ciphertexts;
    }

    if (state.partialDecryptions.length > 0) {
      await _async(checkPartialDecryptions, state);
    }

    if (state.result) {
      await _async(Result.verify, state);
    }
    log("top", true, "Verification done.");
    return state;
  } catch (e) {
    log("top", false, "Something wrong happened.");
    console.error(e);
  }
  return null;
}
