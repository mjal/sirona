import sjcl from "sjcl";
import { check, logError } from "./utils.js";
import { g, L, rev, mod, isValidPoint, parsePoint, zero,
  formula, formula2, Hiprove, Hbproof0, Hbproof1, Hsignature } from "./math";
import { canonicalSerialization } from "./serializeBallot";

export default function (state, ballot) {
  checkMisc(state, ballot);
  checkCredential(state, ballot);
  checkIsUnique(ballot);
  checkValidPoints(ballot);
  checkSignature(ballot);

  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (question.type === undefined) {
      // question_h
      checkIndividualProofs(state, ballot, i);
      if (question.blank) {
        checkBlankProof(state, ballot, i);
        checkOverallProofWithBlank(state, ballot, i);
      } else {
        checkOverallProofWithoutBlank(state, ballot, i);
      }
    } else if (question.type === "NonHomomorphic") {
      logError("ballots", "NonHomomorphic questions not implemented yet");
    } else {
      logError("ballots", `Unknow question type (${question.type})`);
    }
  }
}

function checkMisc(state, ballot) {
  check(
    "ballots",
    "election.uuid correspond to election uuid",
    state.setup.payload.election.uuid === ballot.payload.election_uuid,
    true,
  );

  check(
    "ballots",
    "election.hash correspond to election hash",
    state.setup.fingerprint === ballot.payload.election_hash,
    true,
  );

  const sSerializedBallot = canonicalSerialization(ballot);
  check(
    "ballots",
    "Is canonical",
    sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sSerializedBallot)) ===
      ballot.payloadHash,
    true,
  );
}

function hashWithoutSignature(ballot) {
  const copy = Object.assign({}, ballot.payload);
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkCredential(state, ballot) {
  const credentials = state.credentialsWeights.map((cw) => cw.credential);
  check(
    "ballots",
    "Has a valid credential",
    credentials.indexOf(ballot.payload.credential) !== -1,
    true,
  );
}

const processedBallots = {};
function checkIsUnique(ballot) {
  check(
    "ballots",
    "Is unique",
    processedBallots[ballot.payloadHash] === undefined,
    true,
  );
  processedBallots[ballot.payloadHash] = ballot;
}

export function checkSignature(ballot) {
  check(
    "ballots",
    "Hash without signature is correct",
    ballot.payload.signature.hash === hashWithoutSignature(ballot),
    true,
  );

  const signature = ballot.payload.signature;
  const nChallenge = BigInt(signature.proof.challenge);
  const nResponse = BigInt(signature.proof.response);

  const pA = formula(g, nResponse,
    parsePoint(ballot.payload.credential), nChallenge);
  const H = Hsignature(signature.hash, pA);

  check(
    "ballots",
    "Valid signature",
    nChallenge.toString(16) === H.toString(16),
    true,
  );
}

export function checkValidPoints(ballot) {
  const answers = ballot.payload.answers;
  for (let i = 0; i < answers.length; i++) {
    for (let j = 0; j < answers[i].choices.length; j++) {
      const choices = Array.isArray(answers[i].choices[j])
        ? answers[i].choices[j]
        : [answers[i].choices[j]];
      for (let k = 0; k < choices.length; k++) {
        const pAlpha = parsePoint(choices[k].alpha);
        const pBeta = parsePoint(choices[k].beta);
        check(
          "ballots",
          "Encrypted choices alpha,beta are valid curve points",
          isValidPoint(pAlpha) && isValidPoint(pBeta),
          true,
        );
      }
    }
  }
}

export function checkIndividualProofs(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];
  const choices = answer.choices;
  const individualProofs = answer.individual_proofs;

  check(
    "ballots",
    "Has a proof for every answer answers",
    individualProofs.length ===
      question.answers.length + (question.blank ? 1 : 0),
    true,
  );

  for (let j = 0; j < individualProofs.length; j++) {
    const pAlpha = parsePoint(choices[j].alpha);
    const pBeta = parsePoint(choices[j].beta);

    let nSumChallenges = 0n;
    for (let k = 0; k < individualProofs[j].length; k++) {
      const challenge = BigInt(individualProofs[j][k].challenge);
      nSumChallenges = mod(nSumChallenges + challenge, L);
    }

    const [pA0, pB0] = formula2(pY, pAlpha, pBeta,
      BigInt(individualProofs[j][0].challenge),
      BigInt(individualProofs[j][0].response),
    0);
    const [pA1, pB1] = formula2(pY, pAlpha, pBeta,
      BigInt(individualProofs[j][1].challenge),
      BigInt(individualProofs[j][1].response),
    1);
    const commitments = [pA0, pB0, pA1, pB1];

    let S = `${state.setup.fingerprint}|${ballot.payload.credential}`;
    const H = Hiprove(S, pAlpha, pBeta, ...commitments);

    check(
      "ballots",
      "Valid individual proof",
      nSumChallenges.toString(16) === H.toString(16),
      true,
    );
  }
}

export function checkOverallProofWithoutBlank(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];

  const sumc = {
    alpha: zero,
    beta: zero,
  };

  for (let j = 0; j < answer.choices.length; j++) {
    sumc.alpha = sumc.alpha.add(parsePoint(answer.choices[j].alpha));
    sumc.beta = sumc.beta.add(parsePoint(answer.choices[j].beta));
  }

  let nSumChallenges = 0n;
  for (let k = 0; k < answer.overall_proof.length; k++) {
    const challenge = BigInt(answer.overall_proof[k].challenge);
    nSumChallenges = mod(nSumChallenges + challenge, L);
  }

  let commitments = [];
  // TODO: j = 0; j <= (question.max - question.min)
  for (let j = question.min; j <= question.max; j++) {
    const [pA, pB] = formula2(pY, sumc.alpha, sumc.beta,
      BigInt(answer.overall_proof[j - question.min].challenge),
      BigInt(answer.overall_proof[j - question.min].response),
      j);
    commitments.push(pA, pB);
  }

  let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const H = Hiprove(S, sumc.alpha, sumc.beta, ...commitments);

  check(
    "ballots",
    "Valid overall proof (without blank vote)",
    nSumChallenges.toString(16) === H.toString(16),
    true,
  );
}

export function checkBlankProof(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];

  const nChallenge0 = BigInt(answer.blank_proof[0].challenge);
  const nResponse0 = BigInt(answer.blank_proof[0].response);
  const nChallengeS = BigInt(answer.blank_proof[1].challenge);
  const nResponseS = BigInt(answer.blank_proof[1].response);

  const pAlpha0 = parsePoint(answer.choices[0].alpha);
  const pBeta0 = parsePoint(answer.choices[0].beta);

  let pAlphaS = zero;
  let pBetaS = zero;

  for (let j = 1; j < answer.choices.length; j++) {
    pAlphaS = pAlphaS.add(parsePoint(answer.choices[j].alpha));
    pBetaS = pBetaS.add(parsePoint(answer.choices[j].beta));
  }

  const nSumChallenges = answer.blank_proof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.challenge), L),
    0n,
  );

  const pA0 = formula(g, nResponse0, pAlpha0, nChallenge0);
  const pB0 = formula(pY, nResponse0, pBeta0, nChallenge0);

  const pAS = formula(g, nResponseS, pAlphaS, nChallengeS);
  const pBS = formula(pY, nResponseS, pBetaS, nChallengeS);

  let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const H = Hbproof0(S, ...[pA0, pB0, pAS, pBS]);

  check(
    "ballots",
    "Valid blank proof",
    nSumChallenges.toString(16) === H.toString(16),
    true,
  );
}

export function checkOverallProofWithBlank(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];

  let pAlphaS = zero;
  let pBetaS = zero;
  for (let j = 1; j < answer.choices.length; j++) {
    pAlphaS = pAlphaS.add(parsePoint(answer.choices[j].alpha));
    pBetaS = pBetaS.add(parsePoint(answer.choices[j].beta));
  }

  let commitments = [];
  const [pA, pB] =
    formula2(pY,
      parsePoint(answer.choices[0].alpha),
      parsePoint(answer.choices[0].beta),
      BigInt(answer.overall_proof[0].challenge),
      BigInt(answer.overall_proof[0].response),
      1
    );
  commitments.push(pA, pB);
  for (let j = 1; j < question.max - question.min + 2; j++) {
    const [pA, pB] =
      formula2(pY, pAlphaS, pBetaS,
        BigInt(answer.overall_proof[j].challenge),
        BigInt(answer.overall_proof[j].response),
        (question.min + j - 1)
      );
    commitments.push(pA, pB);
  }

  const nSumChallenges = answer.overall_proof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.challenge), L),
    BigInt(0),
  );

  let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const H = Hbproof1(S, ...commitments);

  check(
    "ballots",
    "Valid overall proof (with blank vote)",
    nSumChallenges.toString(16) === H.toString(16),
    true,
  );
}
