// import sjcl from "sjcl";
import { assert, readTar, readFile, findEvent, findData, log,
  loadElection, loadBallots, } from "./utils.js";

import { checkSignature, checkIndividualProofs } from "./core.js";

let state = { files: [], }

function main(files) {
  //console.log(files);
  document.getElementById("content").innerHTML = "";

  state.files = files.map(readFile).filter((e)=>e);
  log(`Checked ${state.files.length} files`);
  //console.log(state.files);

  // Check the chain of events
  let parent = undefined;
  let nEvent = 0;
  for (let i = 0; i < state.files.length; i++) {
    let [entryHash, type, content] = state.files[i];
    if (type === "event") {
      assert(content.parent == parent);
      parent = entryHash;
      nEvent++;
    }
  }
  log(`Checked ${nEvent} events`);

  state.election = loadElection(state.files);
  state.ballots  = loadBallots(state.files);

  // TODO: Recalculer election_hash ?

  console.log(state.ballots);

  for (let i = 0; i < state.ballots.length; i++) {
    log(`Ballot ${i}`);

    // NOTE: Check election_uuid
    assert(state.election.payload.election.uuid
      === state.ballots[i].payload.election_uuid);

    checkSignature(state.ballots[i]);
    checkIndividualProofs(state.ballots[i]);

    // TODO: Check election_hash ?
    //console.log(state.ballots[i]);
    let answers = state.ballots[i].payload.answers;
    for (let j = 0; j < answers.length; j++) {
      let answer = answers[j];
      let choices = answer.choices;
      let individual_proofs = answer.individual_proofs;
      //console.log(choices)
      //console.log(individual_proofs);
    }
  }
}

document.getElementById("verify")
  .addEventListener("click", function() {
    let uuid = document.getElementById("uuid").value;
    readTar(`/${uuid}.bel`, function(files) {
      main(files);
    });
  });

document.getElementById("verify").click();
