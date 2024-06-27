import sjcl from "sjcl";
import { logBallot } from "./logger";
import { map2, map3 } from "./utils";
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
  Hnonzero,
  Hlproof,
} from "./math";

import * as Point from "./point";
import * as Proof from "./proof";
import * as Answer from "./answer";
import * as Ciphertext from "./ciphertext";
import * as Election from "./election";
import * as Event from "./event";
import * as Ballot from "./ballot";

import canonicalBallot from "./canonicalBallot";

export default function (state: any, ballot: Event.t<Ballot.t>) {
  const election = state.setup.payload.election;
  checkMisc(ballot, election, state.electionFingerprint);
  checkCredential(ballot, state.credentialsWeights);
  checkIsUnique(ballot);
  checkValidPoints(ballot, election);
  checkSignature(ballot, election);

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
      checkIndividualProofs(state, ballot, i);
      checkOverallProofLists(state, ballot, i);
      checkNonZeroProof(state, ballot, i);
      checkListProofs(state, ballot, i);
    } else if (question.type === "NonHomomorphic") {
      logBallot(ballot.tracker, false, "NonHomomorphic questions not implemented yet");
    } else {
      logBallot(ballot.tracker, false, `Unknow question type (${question.type})`);
    }
  }
}

function checkMisc(ballot: Event.t<Ballot.t>, election: Election.t, electionFingerprint: string) {
  const sSerializedBallot = JSON.stringify(canonicalBallot(ballot.payload, election));

  logBallot(
    ballot.tracker, 
    election.uuid === ballot.payload.election_uuid &&
    electionFingerprint === ballot.payload.election_hash,
    "election.uuid correspond to election uuid"
  );

  logBallot(
    ballot.tracker,
    sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sSerializedBallot)) ===
      ballot.payloadHash,
    "Is canonical"
  );
}

export function hashWithoutSignature(ballot: Event.t<Ballot.t>, election: Election.t) {
  const copy = Object.assign({}, canonicalBallot(ballot.payload, election));
  delete copy.signature;
  const serialized = JSON.stringify(copy);
  const hash = sjcl.codec.base64.fromBits(sjcl.hash.sha256.hash(serialized));
  return hash.replace(/=+$/, "");
}

function checkCredential(ballot: Event.t<Ballot.t>, credentialsWeights: any) {
  const credentials = credentialsWeights.map((cw) => cw.credential);

  logBallot(
    ballot.tracker,
    credentials.indexOf(ballot.payload.credential) !== -1,
    "Has a valid credential",
  );
}

const processedBallots = {};

export function resetProcessedBallots() {
  for (const key in processedBallots) {
    delete processedBallots[key];
  }
}

function checkIsUnique(ballot: any) {
  logBallot(
    ballot.tracker,
    processedBallots[ballot.payloadHash] === undefined,
    "Is unique",
  );

  processedBallots[ballot.payloadHash] = ballot;
}

export function checkSignature(ballot: Event.t<Ballot.t>, election: Election.t) {
  logBallot(
    ballot.tracker,
    ballot.payload.signature.hash === hashWithoutSignature(ballot, election),
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

export function checkValidPoints(ballot: Event.t<Ballot.t>, election: Election.t) {
  const answers = ballot.payload.answers;

  const check = (choice: Ciphertext.Serialized.t) => {
    const ct = Ciphertext.parse(choice);
    logBallot(
      ballot.tracker,
      isValidPoint(ct.pAlpha) && isValidPoint(ct.pBeta),
      "Encrypted choices alpha,beta are valid curve points",
    );
  };

  for (let i = 0; i < answers.length; i++) {
    const answer = answers[i];
    if (Answer.Serialized.IsAnswerH(answer, election.questions[i])) {
      for (let j = 0; j < answer.choices.length; j++) {
        check(answer.choices[i]);
      }
    } else if (Answer.Serialized.IsAnswerL(answer, election.questions[i])) {
      for (let j = 0; j < answer.choices.length; j++) {
        for (let k = 0; k < answer.choices[j].length; k++) {
          check(answer.choices[j][k]);
        }
      }
    } else if (Answer.Serialized.IsAnswerNH(answer, election.questions[i])) {
      check(answer.choices);
    }
  }
}

export function checkIndividualProof(
  S: string,
  zIndividualProof: Array<Proof.t>,
  pY: Point.t,
  eCiphertext: Ciphertext.t,
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

  const S = `${state.electionFingerprint}|${ballot.payload.credential}`;

  if (Answer.Serialized.IsAnswerH(answer, question)) {
    const a = Answer.AnswerH.parse(answer);
    for (let j = 0; j < question.answers.length + (question.blank ? 1 : 0); j++) {
      let bCheckResult = checkIndividualProof(S,
        a.aazIndividualProofs[j],
        pY,
        a.aeChoices[j]
      );
      logBallot(ballot.tracker, bCheckResult, "Valid individual proof");
    }
  } else if (Answer.Serialized.IsAnswerL(answer, question)) {
    // TODO: parseAnswerL
    const aaeChoices = map2(answer.choices, Ciphertext.parse);
    const aaazIndividualProofs = map3(answer.individual_proofs, Proof.parse);
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
  } else if (Answer.Serialized.IsAnswerNH(answer, question)) {
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
  const a = Answer.AnswerH.parse(answer);

  const sumc = a.aeChoices.reduce((acc, c) => {
    return {
      pAlpha: acc.pAlpha.add(c.pAlpha),
      pBeta: acc.pBeta.add(c.pBeta),
    };
  }, { pAlpha: zero, pBeta: zero });

  const nSumChallenges = a.azOverallProof.reduce(
    (acc: bigint, proof: Proof.t) => mod(acc + proof.nChallenge, L),
    0n,
  );

  let commitments = [];
  for (let j = 0; j <= question.max - question.min; j++) {
    const [pA, pB] = formula2(
      pY,
      sumc.pAlpha,
      sumc.pBeta,
      a.azOverallProof[j].nChallenge,
      a.azOverallProof[j].nResponse,
      question.min + j,
    );
    commitments.push(pA, pB);
  }

  let S = `${state.electionFingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = Hiprove(S, sumc.pAlpha, sumc.pBeta, ...commitments);

  logBallot(
    ballot.tracker,
    nSumChallenges.toString(16) === nH.toString(16),
    "Valid overall proof (without blank vote)",
  );
}

export function checkBlankProof(state: any, ballot: any, idx: number) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const answer = ballot.payload.answers[idx];
  const a = Answer.AnswerH.parse(answer);

  const pAlphaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pBetaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pBeta), zero);

  const nSumChallenges = a.azBlankProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  const [pA0, pB0] = formula2(pY, a.aeChoices[0].pAlpha, a.aeChoices[0].pBeta,
                              a.azBlankProof[0].nChallenge, a.azBlankProof[0].nResponse, 0);
  const [pAS, pBS] = formula2(pY, pAlphaS, pBetaS,
                              a.azBlankProof[1].nChallenge, a.azBlankProof[1].nResponse, 0);

  let S = `${state.electionFingerprint}|${ballot.payload.credential}|`;
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
  const a = Answer.AnswerH.parse(answer);

  const pAlphaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pBetaS = a.aeChoices.slice(1).reduce((acc, c) => acc.add(c.pBeta), zero);

  let commitments = [];
  const [pA, pB] = formula2(
    pY,
    a.aeChoices[0].pAlpha,
    a.aeChoices[0].pBeta,
    a.azOverallProof[0].nChallenge,
    a.azOverallProof[0].nResponse,
    1,
  );
  commitments.push(pA, pB);
  for (let j = 1; j < question.max - question.min + 2; j++) {
    const [pA, pB] = formula2(
      pY,
      pAlphaS,
      pBetaS,
      a.azOverallProof[j].nChallenge,
      a.azOverallProof[j].nResponse,
      question.min + j - 1,
    );
    commitments.push(pA, pB);
  }

  const nSumChallenges = a.azOverallProof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
    0n,
  );

  let S = `${state.electionFingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = Hbproof1(S, ...commitments);

  logBallot(
    ballot.tracker,
    nSumChallenges.toString(16) === nH.toString(16),
    "Valid overall proof (with blank vote)",
  );
}

function checkOverallProofLists(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];
  const a = Answer.AnswerL.parse(answer);

  const sumc = a.choices.reduce((acc, c) => {
    return {
      pAlpha: acc.pAlpha.add(c[0].pAlpha),
      pBeta: acc.pBeta.add(c[0].pBeta),
    };
  }, { pAlpha: zero, pBeta: zero });

  const [pA, pB] = formula2(
    pY,
    sumc.pAlpha,
    sumc.pBeta,
    a.overall_proof.nChallenge,
    a.overall_proof.nResponse,
    1,
  );

  let S = `${state.electionFingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((cs) => {
    return cs.map((c) => `${c.alpha},${c.beta}`).join(",")
  }).join(",")
  const nH = Hiprove(S, sumc.pAlpha, sumc.pBeta, pA, pB);

  logBallot(
    ballot.tracker,
    a.overall_proof.nChallenge.toString(16) === nH.toString(16),
    "Valid overall proof (lists)",
  );
}

function checkNonZeroProof(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const answer = ballot.payload.answers[idx];
  const a = Answer.AnswerL.parse(answer);

  const ct = a.choices.reduce((acc, choices) => {
    const temp = choices.slice(1).reduce((acc, c) => {
      return {
        pAlpha: acc.pAlpha.add(c.pAlpha),
        pBeta: acc.pBeta.add(c.pBeta),
      }
    }, { pAlpha: zero, pBeta: zero });
    return {
      pAlpha: acc.pAlpha.add(temp.pAlpha),
      pBeta: acc.pBeta.add(temp.pBeta),
    }
  }, { pAlpha: zero, pBeta: zero });

  const A0 = a.nonzero_proof.pCommitment;
  const c =  a.nonzero_proof.nChallenge;
  const [t1, t2] = a.nonzero_proof.nResponse;

  logBallot(
    ballot.tracker,
    Point.serialize(A0) !== Point.serialize(zero),
    "Commitment isn't one (Nonzero proof)",
  );

  const A1 = formula(ct.pAlpha, t1, g, t2);
  const A2 = formula(ct.pBeta, t1, pY, t2).add(A0.multiply(c));

  let S = `${state.electionFingerprint}|${ballot.payload.credential}|`;
  S += answer.choices.map((cs) => {
    return cs.map((c) => `${c.alpha},${c.beta}`).join(",")
  }).join(",")
  const nH = Hnonzero(S, A0, A1, A2);

  logBallot(
    ballot.tracker,
    c.toString(16) === nH.toString(16),
    "Valid nonzero proof (lists)",
  );
}

function checkListProofs(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];
  const a = Answer.AnswerL.parse(answer);

  for (let i = 0; i < question.value.answers.length; i++) {
    const proofs = a.list_proofs[i];
    const ct0 = a.choices[i][0];
    const ct = a.choices[i].slice(1).reduce(Ciphertext.combine, Ciphertext.zero);

    const [A0, B0] = formula2(
      pY,
      ct0.pAlpha,
      ct0.pBeta,
      proofs[0].nChallenge,
      proofs[0].nResponse,
      1,
    );

    const A1 = formula(g, proofs[1].nResponse, ct.pAlpha, proofs[1].nChallenge);
    const B1 = formula(pY, proofs[1].nResponse, ct.pBeta, proofs[1].nChallenge);

    let S = `${state.electionFingerprint}|${ballot.payload.credential}|`;
    S += answer.choices.map((cs) => {
      return cs.map((c) => `${c.alpha},${c.beta}`).join(",")
    }).join(",")

    const nH = Hlproof(S, A0, B0, A1, B1);

    const nSumChallenges = mod(proofs[0].nChallenge + proofs[1].nChallenge, L);

    logBallot(
      ballot.tracker,
      a.choices[i].length === question.value.answers[i].length &&
      nSumChallenges === nH,
      `Valid list proof (list ${i})`,
    );
  }
}
