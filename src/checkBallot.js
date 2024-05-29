import sjcl from "sjcl";
import { check, logError } from "./utils.js";
import { g, L, rev, mod, isValidPoint, parsePoint, zero } from "./math";
import { canonicalSerialization } from "./serializeBallot";

export default function (state, ballot) {
  checkMisc(state, ballot);
  checkCredential(state, ballot);
  checkIsUnique(ballot);
  checkValidPoints(ballot);
  checkSignature(ballot);

  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (question.type === "NonHomomorphic") {
      // TODO
      logError("ballots", "NonHomomorphic questions not implemented yet");
    } else {
      checkIndividualProofs(state, ballot, i);
      if (question.blank) {
        checkBlankProof(state, ballot, i);
        checkOverallProofWithBlank(state, ballot, i);
      } else {
        checkOverallProofWithoutBlank(state, ballot, i);
      }
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

  const sSerializedBallot = canonicalSerialization(ballot);
  check(
    "ballots",
    "Is canonical",
    sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(sSerializedBallot)) ===
      ballot.payloadHash,
    true,
  );
}

function valuesForProofOfIntervalMembership(y, alpha, beta, transcripts, ms) {
  const values = [];

  for (let i = 0; i < transcripts.length; i++) {
    const m = ms[i];

    const nChallenge = BigInt(transcripts[i].challenge);
    const nResponse = BigInt(transcripts[i].response);

    const a = g.multiply(nResponse).add(alpha.multiply(nChallenge));
    const gPowerM = m === 0 ? zero : g.multiply(BigInt(m));
    const b = y
      .multiply(nResponse)
      .add(beta.add(gPowerM.negate()).multiply(nChallenge));

    values.push(a);
    values.push(b);
  }

  return values;
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

  const credential = parsePoint(ballot.payload.credential);
  const signature = ballot.payload.signature;
  const nChallenge = BigInt(signature.proof.challenge);
  const nResponse = BigInt(signature.proof.response);
  const pA = g.multiply(nResponse).add(credential.multiply(nChallenge));
  const verificationHash = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${signature.hash}|${rev(pA.toHex())}`),
  );

  const hexReducedVerificationHash = mod(
    BigInt("0x" + verificationHash),
    L,
  ).toString(16);

  check(
    "ballots",
    "Valid signature",
    nChallenge.toString(16) === hexReducedVerificationHash,
    true,
  );
}

export function checkValidPoints(ballot) {
  const answers = ballot.payload.answers;
  for (let i = 0; i < answers.length; i++) {
    for (let j = 0; j < answers[i].choices.length; j++) {
      const pAlpha = parsePoint(answers[i].choices[j].alpha);
      const pBeta = parsePoint(answers[i].choices[j].beta);
      check(
        "ballots",
        "Encrypted choices alpha,beta are valid curve points",
        isValidPoint(pAlpha) && isValidPoint(pBeta),
        true,
      );
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

    const values = valuesForProofOfIntervalMembership(
      pY,
      pAlpha,
      pBeta,
      individualProofs[j],
      [0, 1],
    );

    const S = `${state.setup.fingerprint}|${ballot.payload.credential}`;
    let sChallenge = `prove|${S}|${choices[j].alpha},${choices[j].beta}|`;
    sChallenge += values.map((v) => rev(v.toHex())).join(",");

    const hVerification = sjcl.codec.hex.fromBits(
      sjcl.hash.sha256.hash(sChallenge),
    );
    const hReducedVerification = mod(BigInt("0x" + hVerification), L).toString(
      16,
    );

    check(
      "ballots",
      "Valid individual proof",
      nSumChallenges.toString(16) === hReducedVerification,
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

  const min = question.min;
  const max = question.max;
  const ms = [];
  for (let j = min; j <= max; j++) {
    ms.push(j);
  }
  const values = valuesForProofOfIntervalMembership(
    pY,
    sumc.alpha,
    sumc.beta,
    answer.overall_proof,
    ms,
  );

  let sChallenge = "prove|";
  sChallenge += `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  const alphasBetas = [];
  for (let j = 0; j < answer.choices.length; j++) {
    alphasBetas.push(`${answer.choices[j].alpha},${answer.choices[j].beta}`);
  }
  sChallenge += alphasBetas.join(",");
  sChallenge += `|${rev(sumc.alpha.toHex())},${rev(sumc.beta.toHex())}|`;
  sChallenge += values.map((v) => rev(v.toHex())).join(",");

  const hVerification = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(sChallenge),
  );
  const hReducedVerification = mod(BigInt("0x" + hVerification), L).toString(
    16,
  );

  check(
    "ballots",
    "Valid overall proof (without blank vote)",
    nSumChallenges.toString(16) === hReducedVerification,
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

  const pA0 = g.multiply(nResponse0).add(pAlpha0.multiply(nChallenge0));
  const pB0 = pY.multiply(nResponse0).add(pBeta0.multiply(nChallenge0));

  const pAS = g.multiply(nResponseS).add(pAlphaS.multiply(nChallengeS));
  const pBS = pY.multiply(nResponseS).add(pBetaS.multiply(nChallengeS));

  let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  const alphasBetas = [];
  for (let j = 0; j < answer.choices.length; j++) {
    alphasBetas.push(`${answer.choices[j].alpha},${answer.choices[j].beta}`);
  }
  S = S + alphasBetas.join(",");
  let sChallenge = `bproof0|${S}|`;
  sChallenge += `${rev(pA0.toHex())},${rev(pB0.toHex())},`;
  sChallenge += `${rev(pAS.toHex())},${rev(pBS.toHex())}`;

  const hVerification = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(sChallenge),
  );
  const hReducedVerification = mod(BigInt("0x" + hVerification), L).toString(
    16,
  );

  check(
    "ballots",
    "Valid blank proof",
    nSumChallenges.toString(16) === hReducedVerification,
    true,
  );
}

export function checkOverallProofWithBlank(state, ballot, idx) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const question = state.setup.payload.election.questions[idx];
  const answer = ballot.payload.answers[idx];

  const nChallenge0 = BigInt(answer.overall_proof[0].challenge);
  const nResponse0 = BigInt(answer.overall_proof[0].response);
  const pAlpha0 = parsePoint(answer.choices[0].alpha);
  const pBeta0 = parsePoint(answer.choices[0].beta);

  let pAlphaS = zero;
  let pBetaS = zero;
  for (let j = 1; j < answer.choices.length; j++) {
    pAlphaS = pAlphaS.add(parsePoint(answer.choices[j].alpha));
    pBetaS = pBetaS.add(parsePoint(answer.choices[j].beta));
  }

  let pABs = [];
  const pA = g.multiply(nResponse0).add(pAlpha0.multiply(nChallenge0));
  const pBDivGPowerM = pBeta0.add(g.negate());
  const pB = pY.multiply(nResponse0).add(pBDivGPowerM.multiply(nChallenge0));
  pABs.push(pA);
  pABs.push(pB);
  for (let j = 1; j < question.max - question.min + 2; j++) {
    const challenge = BigInt(answer.overall_proof[j].challenge);
    const response = BigInt(answer.overall_proof[j].response);
    const pA = g.multiply(response).add(pAlphaS.multiply(challenge));
    const m = question.min + j - 1;
    const gPowerM = m === 0 ? one : g.multiply(BigInt(m));
    const pBDivGPowerM = pBetaS.add(gPowerM.negate());
    const pB = pY.multiply(response).add(pBDivGPowerM.multiply(challenge));
    pABs.push(pA);
    pABs.push(pB);
  }

  const nSumChallenges = answer.overall_proof.reduce(
    (acc, proof) => mod(acc + BigInt(proof.challenge), L),
    BigInt(0),
  );

  let S = `${state.setup.fingerprint}|${ballot.payload.credential}|`;
  const alphasBetas = [];
  for (let j = 0; j < answer.choices.length; j++) {
    alphasBetas.push(`${answer.choices[j].alpha},${answer.choices[j].beta}`);
  }
  S = S + alphasBetas.join(",");
  let sChallenge = `bproof1|${S}|`;
  sChallenge += pABs.map((p) => rev(p.toHex())).join(",");

  const hVerification = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(sChallenge),
  );
  const hReducedVerification = mod(BigInt("0x" + hVerification), L).toString(
    16,
  );

  check(
    "ballots",
    "Valid overall proof (with blank vote)",
    nSumChallenges.toString(16) === hReducedVerification,
    true,
  );
}
