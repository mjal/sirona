// TODO: Use `check` instead of assert and logSuccess
import { clear, logError, showResult } from "./utils.js";
import load from "./load.js";
import checkFiles from "./checkFiles.js";
import checkSetup from "./checkSetup.js";
import checkBallot from "./checkBallot.js";

export default function(fileEntries) {
  clear();
  try {
    let state = load(fileEntries);
    checkFiles(state);
    checkSetup(state);
    for (let i = 0; i < state.ballots.length; i++) {
      checkBallot(state, state.ballots[i]);
    }
  } catch (e) {
    logError("top", "Something wrong happened.");
    console.error(e);
  }
  showResult();
}
