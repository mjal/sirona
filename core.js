// TODO: Cli implementation
// TODO: File input to import .bel
import sjcl from "sjcl";
import { ed25519 } from '@noble/curves/ed25519';
import { assert, readFile, findEvent, findData, log,
  loadElection, loadBallots, } from "./utils.js";

const q = 2n ** 255n - 19n;
const l = BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

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

  const hexReducedVerificationHash = erem(BigInt('0x'+verificationHash), l).toString(16);

  assert(challenge.toString(16) == hexReducedVerificationHash);
  log("Valid signature");
}

export function checkIndividualProofs(state, ballot) {
  console.log("checkIndividualProofs");
  console.log(state.election);
  console.log(ballot);

  findEvent(state.files, ballot.payload.election_uuid);

  const g = ed25519.ExtendedPoint.BASE;

  let y = state.election.payload.election.public_key;
  y = ed25519.ExtendedPoint.fromHex(rev(y));
  console.log(y);

  let answers = ballot.payload.answers;
  console.log("answers", answers);
  for (let i = 0; i < answers.length; i++) {
    let answer = answers[i];
    let choices = answer.choices;
    let individual_proofs = answer.individual_proofs;

    for (let j = 0; j < individual_proofs.length; j++) {
      let alpha = ed25519.ExtendedPoint.fromHex(rev(choices[j].alpha));
      let beta  = ed25519.ExtendedPoint.fromHex(rev(choices[j].beta));
      // TODO: Check alpha, beta are on the curve

      let A = [];
      let B = [];
      let sum_challenges = 0n;
      for (let k = 0; k < individual_proofs[j].length; k++) {
        const challenge = BigInt(individual_proofs[j][k].challenge);
        const response = BigInt(individual_proofs[j][k].response);

        const g_response = g.multiply(response);
        const alpha_challenge = alpha.multiply(challenge);
        const a = g_response.add(alpha_challenge);
        A.push(a);

        let g_k;
        const y_response = y.multiply(response);
        if (k == 0) {
          g_k = ed25519.ExtendedPoint.ZERO;
        } else {
          g_k = g.multiply(BigInt(k));
        }
        const b_div_g_k_challenge = beta.add(g_k.negate()).multiply(challenge);
        const b = y_response.add(b_div_g_k_challenge)
        B.push(b);

        sum_challenges = erem(sum_challenges + challenge, l);
      }

      let S = `${state.election.fingerprint}|${ballot.payload.credential}`;
      let hashedStr = `prove|${S}|${choices[j].alpha},${choices[j].beta}|`;
      for (let k = 0; k < individual_proofs[j].length; k++) {
        hashedStr += `${k==0?"":","}${rev(A[k].toHex())},${rev(B[k].toHex())}`;
      }

      let verificationHash = sjcl.codec.hex.fromBits(
        sjcl.hash.sha256.hash(hashedStr));
      const hexReducedVerificationHash = erem(BigInt('0x'+verificationHash), l).toString(16);

      assert(sum_challenges.toString(16) == hexReducedVerificationHash);
      log("Valid individual proof");
    }
  }
}
