// TODO: Cli implementation
// TODO: File input to import .bel
import sjcl from "sjcl";
import { ed25519 } from '@noble/curves/ed25519';
import { assert, readFile, findEvent, findData, log,
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

let erem = (a, b) => {
  let remainder = a % b;
  
  if (remainder < 0) {
      remainder += b;
  }
  
  return remainder;
}

export function checkSignature(ballot) {
  assert(ballot.payload.signature.hash
    == hashWithoutSignature(ballot));
  log("Hashes are equal");

  const credential = ed25519.ExtendedPoint.fromHex(rev(ballot.payload.credential));

  let signature = ballot.payload.signature;

  const g = ed25519.ExtendedPoint.BASE;
  const challenge = BigInt(signature.proof.challenge);
  const response  = BigInt(signature.proof.response);

  const g_response = g.multiply(response);
  const credential_challenge = credential.multiply(challenge);

  const A = g_response.add(credential_challenge);

  let H = ballot.payload.signature.hash;

  let verificationHash = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${H}|${rev(A.toHex())}`));

  const q = 2n ** 255n - 19n;
  const l = BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

  const hexReducedVerificationHash = erem(BigInt('0x'+verificationHash), l).toString(16);

  assert(challenge.toString(16) == hexReducedVerificationHash);
  log("Valid signature");
}

export function checkIndividualProofs(ballot) {
  console.log("checkIndividualProofs");
}
