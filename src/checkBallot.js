import sjcl from "sjcl";
import { ed25519 } from '@noble/curves/ed25519';
import { check, assert, logSuccess } from './utils.js';
import { g, l, rev, erem } from './math.js';

export default function(state, ballot) {
  assert(state.setup.payload.election.uuid
    === ballot.payload.election_uuid);

  checkIsCanonical(ballot);
  checkCredential(state, ballot);
  checkIsUnique(ballot);

  checkSignature(ballot);
  checkIndividualProofs(state, ballot);
  checkOverallProof(state, ballot);
}

function values_for_proof_of_interval_membership(y, alpha, beta, transcripts, ms) {
  let values = [];  

  for (let i = 0; i < transcripts.length; i++) {
    const m = ms[i];

    const challenge = BigInt(transcripts[i].challenge);
    const response = BigInt(transcripts[i].response);

    const g_response = g.multiply(response);
    const alpha_challenge = alpha.multiply(challenge);
    const a = g_response.add(alpha_challenge);
    const y_response = y.multiply(response);
    const g_m = (m == 0) ? ed25519.ExtendedPoint.ZERO : g.multiply(BigInt(m));
    const b_div_g_m_challenge = beta.add(g_m.negate()).multiply(challenge);
    const b = y_response.add(b_div_g_m_challenge)

    values.push(a);
    values.push(b);
  }

  return values;
}

function hashWithoutSignature(ballot) {
  let copy = Object.assign({}, ballot.payload);
  delete copy.signature;
  let serialized = JSON.stringify(copy);
  let hash = sjcl.codec.base64.fromBits(
    sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, '');
}

function checkIsCanonical(ballot) {
  // Force the field order
  let obj = {
    election_uuid: ballot.payload.election_uuid,
    election_hash: ballot.payload.election_hash,
    credential: ballot.payload.credential,
    answers: ballot.payload.answers.map((answer) => {
      let obj = {
        choices: answer.choices.map((choice) => {
          return {
            alpha: choice.alpha,
            beta: choice.beta
          }
        }),
        individual_proofs: answer.individual_proofs.map((iproof) => {
          return iproof.map((proof) => {
            return {
              challenge: proof.challenge,
              response: proof.response
            }
          });
        }),
        overall_proof: answer.overall_proof.map((proof) => {
          return {
            challenge: proof.challenge,
            response: proof.response
          }
        })
      };
      if (answer.blank_proof !== undefined) {
        obj.blank_proof = {
          challenge: answer.blank_proof.response,
          response: answer.blank_proof.response
        };
      }
      return obj;
    }),
    signature: ballot.payload.signature
  }
  assert(JSON.stringify(obj) === ballot.payloadStr);
  logSuccess("ballots", "Is canonical");
}

function checkCredential(state, ballot) {
  check(
    "ballots", "Has a valid credential",
    state.setup.payload.credentials.indexOf(ballot.payload.credential) !== -1
  );
}

let processedBallots = {};

function checkIsUnique(ballot) {
  check(
    "ballots", "Is unique",
    processedBallots[ballot.payload.credential] === undefined
  );

  processedBallots[ballot.payload.credential] = ballot;
}

export function checkSignature(ballot) {
  assert(ballot.payload.signature.hash
    == hashWithoutSignature(ballot));
  logSuccess("ballots", "Hashes are equal");

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
  logSuccess("ballots", "Valid signature");
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

      let sum_challenges = 0n;
      for (let k = 0; k < individual_proofs[j].length; k++) {
        const challenge = BigInt(individual_proofs[j][k].challenge);
        sum_challenges = erem(sum_challenges + challenge, l);
      }

      const values = values_for_proof_of_interval_membership(y, alpha, beta, individual_proofs[j], [0, 1]);

      let S = `${state.setup.fingerprint}|${ballot.payload.credential}`;
      let challengeStr = `prove|${S}|${choices[j].alpha},${choices[j].beta}|`;
      challengeStr += values.map((v) => rev(v.toHex())).join(',');

      let verificationHash = sjcl.codec.hex.fromBits(
        sjcl.hash.sha256.hash(challengeStr));
      const hexReducedVerificationHash = erem(BigInt('0x'+verificationHash), l).toString(16);

      assert(sum_challenges.toString(16) == hexReducedVerificationHash);
      logSuccess("ballots", "Valid individual proof");
    }
  }
}

export function checkOverallProof(state, ballot) {
  let y = state.setup.payload.election.public_key;
  y = ed25519.ExtendedPoint.fromHex(rev(y));

  for (let i = 0; i < ballot.payload.answers.length; i++) {
    let answer = ballot.payload.answers[i];

    let sumc = {
      alpha: ed25519.ExtendedPoint.ZERO,
      beta: ed25519.ExtendedPoint.ZERO
    };

    for (let j = 0; j < answer.choices.length; j++) {
      sumc.alpha = sumc.alpha.add(ed25519.ExtendedPoint.fromHex(rev(answer.choices[j].alpha)));
      sumc.beta = sumc.beta.add(ed25519.ExtendedPoint.fromHex(rev(answer.choices[j].beta)));
    }

    let sum_challenges = 0n;
    for (let k = 0; k < answer.overall_proof.length; k++) {
      const challenge = BigInt(answer.overall_proof[k].challenge);
      sum_challenges = erem(sum_challenges + challenge, l);
    }

    let min = state.setup.payload.election.questions[i].min;
    let max = state.setup.payload.election.questions[i].max;
    let ms = [];
    for (let j = min; j <= max; j++) {
      ms.push(j);
    }
    const values = values_for_proof_of_interval_membership(y,
      sumc.alpha, sumc.beta, answer.overall_proof, ms);

    let challengeStr = `prove|`;
    challengeStr += `${state.setup.fingerprint}|${ballot.payload.credential}|`;
    let alphas_betas = [];
    for (let j = 0; j < answer.choices.length; j++) {
      alphas_betas.push(`${answer.choices[j].alpha},${answer.choices[j].beta}`);
    }
    challengeStr += alphas_betas.join(',');
    challengeStr += `|${rev(sumc.alpha.toHex())},${rev(sumc.beta.toHex())}|`;
    challengeStr += values.map((v) => rev(v.toHex())).join(',');

    let verificationHash = sjcl.codec.hex.fromBits(
      sjcl.hash.sha256.hash(challengeStr));
    const hexReducedVerificationHash = erem(BigInt('0x'+verificationHash), l).toString(16);

    assert(sum_challenges.toString(16) == hexReducedVerificationHash);
    logSuccess("ballots", "Valid overall proof");
  }
}
