import { assert, readFile, log,
  loadElection, loadBallots, } from "./utils.js";

import {
  checkEventChain,
  checkSignature,
  checkIndividualProofs,
  checkOverallProof
} from "./core.js";

let state = { files: [], }

export const main = (files) => {
  document.getElementById("content").innerHTML = "";

  state.files = files.map(readFile).filter((e)=>e);
  log(`Checked ${state.files.length} files`);

  checkEventChain(state.files);

  state.election = loadElection(state.files);
  state.ballots  = loadBallots(state.files);

  console.log(state.election); 
  console.log(state.files); 

  // TODO: Recalculer election_hash ?

  for (let i = 0; i < state.ballots.length; i++) {
    log(`Ballot ${i}`);

    // NOTE: Check election_uuid
    assert(state.election.payload.election.uuid
      === state.ballots[i].payload.election_uuid);

    checkSignature(state.ballots[i]);
    checkIndividualProofs(state, state.ballots[i]);
  }
}
