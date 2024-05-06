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

  console.log("message:", `sig|${H}|${A.toHex()}`);

  console.log("Hash of hardcoded str:");
  console.log(sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash("sig|BiwgwZSI8rwjmodNJE12B9eFht3XVo2Sq5kTV5eC2hw|6da112273a5d288dfa93561265c59576caaa8d0581981b25a8f119e22d1564bd")));

  let verificationHash = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${H}|${rev(A.toHex())}`));

  const q = 2n ** 255n - 19n;
  const hexVerificationHashMod = (BigInt('0x' + verificationHash) % q).toString(16);

  const hexChallengeMod = (challenge % q).toString(16);

  console.log("verificationHash:", verificationHash);
  console.log("hexVerificationHashMod:", hexVerificationHashMod);
  console.log("hexChallengeMod:", hexChallengeMod);

  assert(hexChallengeMod == hexVerificationHashMod); // mod q
}

export function checkIndividualProofs(ballot) {
  console.log("checkIndividualProofs");
}
