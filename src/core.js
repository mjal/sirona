// TODO: Cli implementation
// TODO: File input to import .bel
import sjcl from "sjcl";
import { ed25519 } from '@noble/curves/ed25519';
import { assert, readFile, findEvent, findData, log,
  loadElection, loadBallots, } from "./utils.js";

const g = ed25519.ExtendedPoint.BASE;
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

// TODO: isolate formula1 (signature)

let formula2 = (y, alpha, beta, challenge, response, k) => {
  const g_response = g.multiply(response);
  const alpha_challenge = alpha.multiply(challenge);
  const a = g_response.add(alpha_challenge);

  let g_k;
  const y_response = y.multiply(response);
  if (k == 0) {
    g_k = ed25519.ExtendedPoint.ZERO;
  } else {
    g_k = g.multiply(BigInt(k));
  }
  const b_div_g_k_challenge = beta.add(g_k.negate()).multiply(challenge);
  const b = y_response.add(b_div_g_k_challenge)

  return [a, b];
}

export function checkEventChain(files) {
  // Check the chain of events
  let parent = undefined;
  let nEvent = 0;
  for (let i = 0; i < files.length; i++) {
    let [entryHash, type, content] = files[i];
    if (type === "event") {
      assert(content.parent == parent);
      parent = entryHash;
      nEvent++;
    }
  }
  log(`Checked ${nEvent} events`);
}

export function checkSignature(ballot) {
  assert(ballot.payload.signature.hash
    == hashWithoutSignature(ballot));
  log("Hashes are equal");

  const credential = ed25519.ExtendedPoint.fromHex(rev(ballot.payload.credential));

  let signature = ballot.payload.signature;

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
  let y = state.setup.payload.election.public_key;
  y = ed25519.ExtendedPoint.fromHex(rev(y));

  let answers = ballot.payload.answers;
  for (let i = 0; i < answers.length; i++) {
    let answer = answers[i];
    let choices = answer.choices;
    let individual_proofs = answer.individual_proofs;

    assert(individual_proofs.length == state.setup.payload.election.questions[i].answers.length);
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

        let [a, b] = formula2(y, alpha, beta, challenge, response, k);
        A.push(a);
        B.push(b);

        sum_challenges = erem(sum_challenges + challenge, l);
      }

      let S = `${state.setup.fingerprint}|${ballot.payload.credential}`;
      let hashedStr = `prove|${S}|${choices[j].alpha},${choices[j].beta}|`;
      for (let k = 0; k < individual_proofs[j].length; k++) {
        hashedStr += `${k==0?"":","}${rev(A[k].toHex())},${rev(B[k].toHex())}`;
      }

      console.log(hashedStr);

      let verificationHash = sjcl.codec.hex.fromBits(
        sjcl.hash.sha256.hash(hashedStr));
      const hexReducedVerificationHash = erem(BigInt('0x'+verificationHash), l).toString(16);

      assert(sum_challenges.toString(16) == hexReducedVerificationHash);
      log("Valid individual proof");
    }
  }
}

export function checkOverallProof(state, ballot) {
  let y = state.setup.payload.election.public_key;
  y = ed25519.ExtendedPoint.fromHex(rev(y));

  for (let i = 0; i < ballot.payload.answers.length; i++) {
    console.log(ballot);
    console.log(state.setup);
    let answer = ballot.payload.answers[i];

    let sumc = {
      alpha: ed25519.ExtendedPoint.ZERO,
      beta: ed25519.ExtendedPoint.ZERO
    };

    for (let j = 0; j < answer.choices.length; j++) {
      sumc.alpha = sumc.alpha.add(ed25519.ExtendedPoint.fromHex(rev(answer.choices[j].alpha)));
      sumc.beta = sumc.beta.add(ed25519.ExtendedPoint.fromHex(rev(answer.choices[j].beta)));
    }

    let A = [];
    let B = [];

    let alpha, beta;
    let a, b;
    let challenge, response;

    /*
    alpha = ed25519.ExtendedPoint.fromHex(rev(answer.choices[0].alpha));
    beta  = ed25519.ExtendedPoint.fromHex(rev(answer.choices[0].beta));
    challenge = BigInt(answer.individual_proofs[0][0].challenge);
    response  = BigInt(answer.individual_proofs[0][0].response);
    [a, b] = formula2(y, alpha, beta, challenge, response, 0);
    A.push(alpha);
    B.push(beta);
    */

    alpha = sumc.alpha;
    beta  = sumc.beta;
    challenge = BigInt(answer.overall_proof[0].challenge);
    response  = BigInt(answer.overall_proof[0].response);
    [a, b] = formula2(y, alpha, beta, challenge, response, 0);
    A.push(a);
    B.push(b);

    /*
    for (let j = 0; j < answer.choices.length; j++) {
      let alpha, beta;
      if (j == 0) {
        alpha = ed25519.ExtendedPoint.fromHex(rev(answer.choices[0].alpha));
        beta  = ed25519.ExtendedPoint.fromHex(rev(answer.choices[0].beta));
      } else {
        alpha = sumc.alpha;
        beta  = sumc.beta;
      }

      alpha = sumc.alpha;
      beta  = sumc.beta;

      const challenge = BigInt(answer.individual_proofs[j][0].challenge);
      const response = BigInt(answer.individual_proofs[j][0].response);

      let [a, b] = formula2(y, alpha, beta, challenge, response, 0);
      A.push(alpha);
      B.push(beta);

      //for (let k = 0; k < answer.individual_proofs[j].length; k++) {
      //  const challenge = BigInt(answer.individual_proofs[j][k].challenge);
      //  const response = BigInt(answer.individual_proofs[j][k].response);

      //  let [a, b] = formula2(y, alpha, beta, challenge, response, k);

      //  A.push(alpha);
      //  B.push(beta);
      //}
    }
    */

    let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
    let alphas_betas = [];
    for (let j = 0; j < answer.choices.length; j++) {
      alphas_betas.push(`${answer.choices[j].alpha},${answer.choices[j].beta}`);
    }
    S += alphas_betas.join(',');

    let hashedStr = `prove|${S}|`
    hashedStr += `${rev(sumc.alpha.toHex())},${rev(sumc.beta.toHex())}|`;
    //for (let k = 0; k < A.length; k++) {
    //  hashedStr += `${k==0?"":","}${rev(A[k].toHex())},${rev(B[k].toHex())}`;
    //}
    console.log(hashedStr);
  }
}
