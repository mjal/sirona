import sjcl from "sjcl";
import { logBallot } from "./logger";
import {
  g,
  L,
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
import { Point } from "./types";
import * as Serialized from "./serialized";
import canonicalBallot from "./canonicalBallot.js";

import {
  Proof,
  Ciphertext,
  parseProof,
  parseCiphertext,
  IsAnswerH,
  IsAnswerNH,
  IsAnswerL,
} from "./types";

export default function (state: any, ballot: any) {
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

function checkMisc(state: any, ballot: any) {
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

export function hashWithoutSignature(ballot: any) {
  const copy = Object.assign({}, canonicalBallot(ballot.payload));
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkCredential(state: any, ballot: any) {
  const credentials = state.credentialsWeights.map((cw) => cw.credential);

  logBallot(
    ballot.tracker,
    credentials.indexOf(ballot.payload.credential) !== -1,
    "Has a valid credential",
  );
}

const processedBallots = {};
function checkIsUnique(ballot: any) {
  logBallot(
    ballot.tracker,
    processedBallots[ballot.payloadHash] === undefined,
    "Is unique",
  );

  processedBallots[ballot.payloadHash] = ballot;
}

export function checkSignature(ballot: any) {
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

export function checkValidPoints(ballot: any) {
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
  S: string,
  zIndividualProof: Array<Proof>,
  pY: Point,
  eCiphertext: Ciphertext,
) {
  const nSumChallenges = mod(zIndividualProof[0].nChallenge + zIndividualProof[1].nChallenge, L);
  const [pA0, pB0] = formula2(
    pY,
    eCiphertext.pAlpha,
    eCiphertext.pBeta,
    zIndividualProof[0].nChallenge,
    zIndividualProof[0].nResponse,
    0,
  );
  const [pA1, pB1] = formula2(
    pY,
    eCiphertext.pAlpha,
    eCiphertext.pBeta,
    zIndividualProof[1].nChallenge,
    zIndividualProof[1].nResponse,
    1,
  );
  const nH = Hiprove(S, eCiphertext.pAlpha, eCiphertext.pBeta, pA0, pB0, pA1, pB1);
  return nSumChallenges.toString(16) === nH.toString(16);
}

export function checkIndividualProofs(state: any, ballot: any, idx: number) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx]

  const S = `${state.setup.fingerprint}|${ballot.payload.credential}`;

  if (IsAnswerH(answer, question)) {
    const aeChoices = answer.choices.map(parseCiphertext);
    const aazIndividualProofs = answer.individual_proofs.map((a) => a.map(parseProof));
    for (let j = 0; j < question.answers.length + (question.blank ? 1 : 0); j++) {
      let bCheckResult = checkIndividualProof(S,
        aazIndividualProofs[j],
        pY,
        aeChoices[j]
      );
      logBallot(ballot.tracker, bCheckResult, "Valid individual proof");
    }
  } else if (IsAnswerL(answer, question)) {
    const aaeChoices = answer.choices.map((a) => a.map(parseCiphertext));
    const aaazIndividualProofs = answer.individual_proofs.map((a) => a.map((a) => a.map(parseProof)));
    for (let j = 0; j < question.value.answers.length; j++) {
      for (let k = 0; k < question.value.answers[j].length; k++) {
        let bCheckResult = checkIndividualProof(S,
          aaazIndividualProofs[j][k],
          pY,
          aaeChoices[j][k]
        );
        logBallot(ballot.tracker, bCheckResult, "Valid individual proof");
      }
    }
  } else if (IsAnswerNH(answer, question)) {
    logBallot(
      ballot.tracker,
      false,
      `Question type "NonHomomorphic" not supported`
    );
  } else {
    logBallot(
      ballot.tracker,
      false,
      `Unknow question type (${question.type})`
    );
  }
}

export function checkOverallProofWithoutBlank(state: any, ballot: any, idx: number) {
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

export function checkBlankProof(state: any, ballot: any, idx: number) {
  const pY = parsePoint(state.setup.payload.election.public_key);
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
    (acc: bigint, proof: Serialized.Proof) => mod(acc + BigInt(proof.challenge), L),
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

export function checkOverallProofWithBlank(state: any, ballot: any, idx: number) {
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
    (acc: bigint, proof: Serialized.Proof) => mod(acc + BigInt(proof.challenge), L),
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
