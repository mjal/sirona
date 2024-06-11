import sjcl from "sjcl";
import { logBallot } from "./logger";
import {
  g,
  L,
  rev,
  mod,
  isValidPoint,
  parsePoint,
  zero,
  formula,
  formula2,
  Hiprove,
  Hbproof0,
  Hbproof1,
  Hsignature,
} from "./math";
import canonicalBallot from "./canonicalBallot.js";

export default function (state, ballot) {
  checkMisc(state, ballot);
  checkCredential(state, ballot);
  checkIsUnique(ballot);
  checkValidPoints(ballot);
  checkSignature(ballot);

  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (question.type === undefined) { // question_h
      checkIndividualProofs(state, ballot, i);
      if (question.blank) {
        checkBlankProof(state, ballot, i);
        checkOverallProofWithBlank(state, ballot, i);
      } else {
        checkOverallProofWithoutBlank(state, ballot, i);
      }
    } else if (question.type === "Lists") {
      logBallot(ballot.tracker, false, `Ballot of type 'Lists' not yet supported`);
      checkIndividualProofs(state, ballot, i);
    } else if (question.type === "NonHomomorphic") {
      logBallot(ballot.tracker, false, "NonHomomorphic questions not implemented yet");
    } else {
      logBallot(ballot.tracker, false, `Unknow question type (${question.type})`);
    }
  }
}

function checkMisc(state, ballot) {
  const sSerializedBallot = JSON.stringify(canonicalBallot(ballot.payload));

  logBallot(
    ballot.tracker, 
    state.setup.payload.election.uuid === ballot.payload.election_uuid &&
    state.setup.fingerprint === ballot.payload.election_hash,
    "election.uuid correspond to election uuid"
  );

  logBallot(
    ballot.tracker,
    sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sSerializedBallot)) ===
      ballot.payloadHash,
    "Is canonical"
  );
}

export function hashWithoutSignature(ballot) {
  const copy = Object.assign({}, canonicalBallot(ballot.payload));
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkCredential(state, ballot) {
  const credentials = state.credentialsWeights.map((cw) => cw.credential);

  logBallot(
    ballot.tracker,
    credentials.indexOf(ballot.payload.credential) !== -1,
    "Has a valid credential",
  );
}

const processedBallots = {};
function checkIsUnique(ballot) {
  logBallot(
    ballot.tracker,
    processedBallots[ballot.payloadHash] === undefined,
    "Is unique",
  );

  processedBallots[ballot.payloadHash] = ballot;
}

export function checkSignature(ballot) {
  logBallot(
    ballot.tracker,
    ballot.payload.signature.hash === hashWithoutSignature(ballot),
    "Hash without signature is correct",
  );

  const signature = ballot.payload.signature;
  const nChallenge = BigInt(signature.proof.challenge);
  const nResponse = BigInt(signature.proof.response);

  const pA = formula(
    g,
    nResponse,
    parsePoint(ballot.payload.credential),
    nChallenge,
  );
  const nH = Hsignature(signature.hash, pA);

  logBallot(
    ballot.tracker,
    nChallenge.toString(16) === nH.toString(16),
    "Valid signature",
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

        logBallot(
          ballot.tracker,
          isValidPoint(pAlpha) && isValidPoint(pBeta),
          "Encrypted choices alpha,beta are valid curve points",
        );
      }
    }
  }
}

export function checkIndividualProof(
  S,
  individualProof,
  pY,
  pAlpha,
  pBeta,
) {
  let nSumChallenges = individualProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.challenge), L),
    0n,
  );

  const [pA0, pB0] = formula2(
    pY,
    pAlpha,
    pBeta,
    BigInt(individualProof[0].challenge),
    BigInt(individualProof[0].response),
    0,
  );
  const [pA1, pB1] = formula2(
    pY,
    pAlpha,
    pBeta,
    BigInt(individualProof[1].challenge),
    BigInt(individualProof[1].response),
    1,
  );
  const commitments = [pA0, pB0, pA1, pB1];

  const nH = Hiprove(S, pAlpha, pBeta, ...commitments);

  return nSumChallenges.toString(16) === nH.toString(16);
}

export function checkIndividualProofs(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];
  const choices = answer.choices;
  const individualProofs = answer.individual_proofs;


  if (question.type === undefined) { // question_h
    logBallot(
      ballot.tracker,
        individualProofs.length ===
          question.answers.length + (question.blank ? 1 : 0),
      "Has a proof for every answer",
    );
  } else if (question.type === "Lists") {
    for (let i = 0; i < question.value.answers.length; i++) {
      logBallot(
        ballot.tracker,
        individualProofs[i].length === question.value.answers[i].length,
        "Has a proof for every answer",
      );
    }
  }

  const S = `${state.setup.fingerprint}|${ballot.payload.credential}`;

  if (question.type === undefined) { // question_h
    for (let j = 0; j < individualProofs.length; j++) {
      let bCheckResult = checkIndividualProof(S,
        individualProofs[j],
        pY,
        parsePoint(choices[j].alpha),
        parsePoint(choices[j].beta)
      );

      logBallot(ballot.tracker, bCheckResult, "Valid individual proof");
    }
  } else if (question.type === "Lists") {
    for (let j = 0; j < individualProofs.length; j++) {
      for (let k = 0; k < individualProofs[j].length; k++) {
        let bCheckResult = checkIndividualProof(S,
          individualProofs[j][k],
          pY,
          parsePoint(choices[j][k].alpha),
          parsePoint(choices[j][k].beta)
        );
        logBallot(ballot.tracker, bCheckResult, "Valid individual proof");
      }
    }
  } else {
    logBallot(
      ballot.tracker,
      false,
      `Unknow question type (${question.type})`
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
  for (let j = 0; j <= question.max - question.min; j++) {
    const [pA, pB] = formula2(
      pY,
      sumc.alpha,
      sumc.beta,
      BigInt(answer.overall_proof[j].challenge),
      BigInt(answer.overall_proof[j].response),
      question.min + j,
    );
    commitments.push(pA, pB);
  }

  let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = Hiprove(S, sumc.alpha, sumc.beta, ...commitments);

  logBallot(
    ballot.tracker,
    nSumChallenges.toString(16) === nH.toString(16),
    "Valid overall proof (without blank vote)",
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
  const nH = Hbproof0(S, ...[pA0, pB0, pAS, pBS]);

  logBallot(
    ballot.tracker,
    nSumChallenges.toString(16) === nH.toString(16),
    "Valid blank proof",
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
  const [pA, pB] = formula2(
    pY,
    parsePoint(answer.choices[0].alpha),
    parsePoint(answer.choices[0].beta),
    BigInt(answer.overall_proof[0].challenge),
    BigInt(answer.overall_proof[0].response),
    1,
  );
  commitments.push(pA, pB);
  for (let j = 1; j < question.max - question.min + 2; j++) {
    const [pA, pB] = formula2(
      pY,
      pAlphaS,
      pBetaS,
      BigInt(answer.overall_proof[j].challenge),
      BigInt(answer.overall_proof[j].response),
      question.min + j - 1,
    );
    commitments.push(pA, pB);
  }

  const nSumChallenges = answer.overall_proof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.challenge), L),
    BigInt(0),
  );

  let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = Hbproof1(S, ...commitments);

  logBallot(
    ballot.tracker,
    nSumChallenges.toString(16) === nH.toString(16),
    "Valid overall proof (with blank vote)",
  );
}
