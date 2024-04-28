import sjcl from "sjcl";
import { assert, readTar, readFile, findEvent, findData, log,
  loadElection, loadBallots, } from "./utils.js";

function H_signature(H, A) {
  let content = `sig|${H}|${A}`;
}

export function checkSignature(ballot) {
  console.log("checkSignature");

  // TODO: Récupérer g
  let g = null;

  // FIX: Recompute hash of ballot_without_signature ?
  // TODO: check equal to ballot.payload.signature.hash
  /*
  console.log("ballot_without_signature");
  let ballot_without_signature = Object.assign({}, ballot.payload); // copy
  ballot_without_signature.signature = null;
  console.log(
    sjcl.codec.base64.fromBits(
      sjcl.hash.sha256.hash(
        JSON.stringify(ballot_without_signature))));
  */

  let signature = ballot.payload.signature;

  console.log(signature.hash);
  console.log(signature.proof);

  let response = null;
  let challenge = null;
  let credential = null;

  let A = null; //g^response * credential^challenge;

  assert(challenge == H_signature(hash, A)); // mod q
}

export function checkIndividualProofs(ballot) {
  console.log("checkIndividualProofs");
}
