// TODO: Cli implementation
// TODO: File input to import .bel
import sjcl from "sjcl";
import { ed25519 } from '@noble/curves/ed25519';
import { assert, readTar, readFile, findEvent, findData, log,
  loadElection, loadBallots, } from "./utils.js";

function hashWithoutSignature(ballot) {
  let copy = Object.assign({}, ballot.payload);
  delete copy.signature;
  let serialized = JSON.stringify(copy);
  let hash = sjcl.codec.base64.fromBits(
    sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, '');
}

let rev = (hexStr) => {
  return hexStr.match(/.{1,2}/g).reverse().join('')
}

export function checkSignature(ballot) {
  console.log("checkSignature");

  assert(ballot.payload.signature.hash
    == hashWithoutSignature(ballot));
  log("Hashes are equal");

  const credential = ed25519.ExtendedPoint.fromHex(rev(ballot.payload.credential));
  console.log("credential", credential.toHex());

  let signature = ballot.payload.signature;

  const g = ed25519.ExtendedPoint.BASE;
  const challenge = BigInt(signature.proof.challenge);
  const response  = BigInt(signature.proof.response);

  const g_response = g.multiply(response);
  const credential_challenge = credential.multiply(challenge);
  console.log("gChallenge:", g_response.toHex());
  console.log("credentialResponse:", credential_challenge.toHex());

  const A = g_response.add(credential_challenge);
  console.log("A:", A.toHex()); // Output the result as hex

  let H = ballot.payload.signature.hash;

  // FIX:
  // TODO: Use A.toHex() ? and check against the string used by belenios
  // TODO: Do the modulo
  let verificationHash = sjcl.codec.base64.fromBits(
    sjcl.hash.sha256.hash(`sig|${H}|${A}`));

  console.log(verificationHash);

  // FIX:
  assert(challenge == verificationHash); // mod q
}

export function checkIndividualProofs(ballot) {
  console.log("checkIndividualProofs");
}
