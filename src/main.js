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

  state.setup    = loadElection(state.files);
  state.ballots  = loadBallots(state.files);

  console.log(state.election); 
  console.log(state.files); 

  // Recalculer election_hash ?
  // TODO: Check election
  // TODO: Check trustees

  for (let i = 0; i < state.ballots.length; i++) {
    log(`Ballot ${i}`);

    // NOTE: Check ballot's infos
    assert(state.setup.payload.election.uuid
      === state.ballots[i].payload.election_uuid);

    checkSignature(state.ballots[i]);
    checkIndividualProofs(state, state.ballots[i]);
    checkOverallProof(state, state.ballots[i]);
  }
}
