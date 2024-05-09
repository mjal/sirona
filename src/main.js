// TODO: Use `check` instead of assert and logSuccess
import { readFile, logError } from "./utils.js";
import load from "./load.js";
import checkFiles from "./checkFiles.js";
import checkSetup from "./checkSetup.js";
import checkBallot from "./checkBallot.js";

export default function(fileEntries) {
  try {
    let state = load(fileEntries.map(readFile));
    checkFiles(state);
    checkSetup(state);
    for (let i = 0; i < state.ballots.length; i++) {
      checkBallot(state, state.ballots[i]);
    }
  } catch (e) {
    logError("critical", "Something wrong happened.");
  }
}
