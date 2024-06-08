import sjcl from "sjcl";
import {
  g,
  L,
  rev,
  mod,
  rand,
  formula2,
  formula,
  parsePoint,
  Hiprove,
  Hbproof0,
  Hbproof1,
  zero,
  point,
} from "./math";
import { hashWithoutSignature } from "./checkBallot";
import canonicalBallot from "./canonicalBallot";
import checkBallot from "./checkBallot";

type tProof = { nChallenge: bigint; nResponse: bigint };
type tSerializedProof = { challenge: string; response: string };
type tCiphertext = { pAlpha: point; pBeta: point };
type tSerializedCiphertext = { alpha: string; beta: string };

type tAnswerWithoutBlank = {
  choices: Array<tSerializedCiphertext>;
  individual_proofs: Array<Array<tSerializedProof>>;
  overall_proof: Array<tSerializedProof>;
};

type tAnswerWithBlank = {
  choices: Array<tSerializedCiphertext>;
  individual_proofs: Array<Array<tSerializedProof>>;
  blank_proof: Array<tSerializedProof>;
  overall_proof: Array<tSerializedProof>;
};

type tAnswer = tAnswerWithoutBlank | tAnswerWithBlank;

function serializeProof(proof: tProof): tSerializedProof {
  return {
    challenge: proof.nChallenge.toString(),
    response: proof.nResponse.toString(),
  };
}

function serializeCiphertext(c: tCiphertext): tSerializedCiphertext {
  return {
    alpha: rev(c.pAlpha.toHex()),
    beta: rev(c.pBeta.toHex()),
  };
}

export default function (
  state: any,
  sPriv: string,
  choices: Array<Array<number>>,
) {
  if (!checkVotingCode(state, sPriv)) {
    return false;
  }

  const { hPublicCredential, nPrivateCredential } = deriveCredential(
    state,
    sPriv,
  );

  let answers: Array<tAnswer> = [];
  for (let i = 0; i < choices.length; i++) {
    const question = state.setup.payload.election.questions[i];
    const f = question.blank
      ? generateAnswerWithBlank
      : generateAnswerWithoutBlank;
    const answer = f(state, question, sPriv, choices[i]);
    answers.push(answer);
  }

  const ballotWithoutSignature = {
    answers,
    credential: hPublicCredential,
    election_hash: state.setup.fingerprint,
    election_uuid: state.setup.payload.election.uuid,
  };

  const hH = hashWithoutSignature({ payload: ballotWithoutSignature });

  const ballot = {
    ...ballotWithoutSignature,
    signature: signature(nPrivateCredential, hH),
  };

  // TODO: Remove
  console.log("Generated ballot");
  console.log(ballot);
  console.log(canonicalBallot(ballot));

  checkBallot(state, { payload: ballot });

  return ballot;
}

export function checkVotingCode(state: any, sPriv: string) {
  if (
    !/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(sPriv)
  ) {
    alert("Invalid credential format");
    return false;
  }

  const { hPublicCredential } = deriveCredential(state, sPriv);

  const electionPublicCredentials = state.credentialsWeights.map(
    (c: any) => c.credential,
  );

  if (electionPublicCredentials.includes(hPublicCredential)) {
    return true;
  } else {
    alert("Incorrect voting code");
    return false;
  }
}

function iproof(
  prefix: string,
  pY: point,
  pAlpha: point,
  pBeta: point,
  r: bigint,
  m: number,
  M: Array<number>,
) {
  const w = rand();
  let commitments: Array<point> = [];
  let proofs: Array<tProof> = [];

  for (let i = 0; i < M.length; i++) {
    if (m !== M[i]) {
      const nChallenge = rand();
      const nResponse = rand();
      proofs.push({ nChallenge, nResponse });
      const [pA, pB] = formula2(pY, pAlpha, pBeta, nChallenge, nResponse, M[i]);
      commitments.push(pA, pB);
    } else {
      // m === M[i]
      proofs.push({ nChallenge: BigInt(0), nResponse: BigInt(0) });
      const pA = g.multiply(w);
      const pB = pY.multiply(w);
      commitments.push(pA, pB);
    }
  }

  const nH = Hiprove(prefix, pAlpha, pBeta, ...commitments);

  const nSumChallenge = proofs.reduce((acc, proof) => {
    return mod(acc + proof.nChallenge, L);
  }, BigInt(0));

  for (let i = 0; i < M.length; i++) {
    if (m === M[i]) {
      proofs[i].nChallenge = mod(nH - nSumChallenge, L);
      proofs[i].nResponse = mod(w - r * proofs[i].nChallenge, L);
    }
  }

  return proofs.map(serializeProof);
}

function generateEncryptions(
  state: any,
  pY: point,
  hPublicCredential: string,
  choices: Array<number>,
) {
  let anR: Array<bigint> = [];
  let aCiphertexts: Array<tCiphertext> = [];
  let aIndividualProofs: Array<Array<tSerializedProof>> = [];

  for (let i = 0; i < choices.length; i++) {
    const nR = rand();
    const gPowerM = choices[i] === 0 ? zero : g.multiply(BigInt(choices[i]));
    const pAlpha = g.multiply(nR);
    const pBeta = pY.multiply(nR).add(gPowerM);

    const S = `${state.setup.fingerprint}|${hPublicCredential}`;
    const proof = iproof(S, pY, pAlpha, pBeta, nR, choices[i], [0, 1]);

    aCiphertexts.push({ pAlpha, pBeta });
    aIndividualProofs.push(proof);
    anR.push(nR);
  }

  return { anR, aCiphertexts, aIndividualProofs };
}

function generateAnswerWithoutBlank(
  state: any,
  question: any,
  sPriv: string,
  choices: Array<number>,
): tAnswerWithoutBlank {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const { hPublicCredential } = deriveCredential(state, sPriv);
  const { anR, aCiphertexts, aIndividualProofs } = generateEncryptions(
    state,
    pY,
    hPublicCredential,
    choices,
  );

  const pSumAlpha = aCiphertexts.reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pSumBeta = aCiphertexts.reduce((acc, c) => acc.add(c.pBeta), zero);
  const m = choices.reduce((acc, c) => c + acc, 0);
  const M = Array.from({ length: question.max - question.min + 1 }).map(
    (_, i) => i + question.min,
  );
  const nR = anR.reduce((acc, r) => mod(acc + r, L), BigInt(0));

  let S = `${state.setup.fingerprint}|${hPublicCredential}|`;
  S += aCiphertexts
    .map((c) => `${rev(c.pAlpha.toHex())},${rev(c.pBeta.toHex())}`)
    .join(",");
  const overallProof = iproof(S, pY, pSumAlpha, pSumBeta, nR, m, M);

  return {
    choices: aCiphertexts.map(serializeCiphertext),
    individual_proofs: aIndividualProofs,
    overall_proof: overallProof,
  };
}

function blankProof(
  state: any,
  hPub: string,
  pY: point,
  choices: Array<tCiphertext>,
  pAlphaS: point,
  pBetaS: point,
  nR0: bigint,
  bNonBlank: boolean
): Array<tProof> {
  const nChallengeS = rand();
  const nResponseS = rand();
  const pAS = formula(g,  nResponseS, pAlphaS, nChallengeS);
  const pBS = formula(pY, nResponseS, pBetaS, nChallengeS);
  const nW = rand();
  const pA0 = g.multiply(nW);
  const pB0 = pY.multiply(nW);

  let S = `${state.setup.fingerprint}|${hPub}|`;
  S += choices.map(serializeCiphertext).map((c) => `${c.alpha},${c.beta}`).join(",");
  const nH = (bNonBlank) ? Hbproof0(S, pA0, pB0, pAS, pBS) : Hbproof0(S, pAS, pBS, pA0, pB0)
  const nChallenge0 = mod(nH - nChallengeS, L);
  const nResponse0 = mod(nW - nChallenge0 * nR0, L);

  if (bNonBlank) {
    return [
      { nChallenge: nChallenge0, nResponse: nResponse0 },
      { nChallenge: nChallengeS, nResponse: nResponseS },
    ];
  } else {
    return [
      { nChallenge: nChallengeS, nResponse: nResponseS },
      { nChallenge: nChallenge0, nResponse: nResponse0 },
    ];
  }
}

function overallProofBlank(
  state: any,
  question: any,
  anChoices: Array<number>,
  aeCiphertexts: Array<tCiphertext>,
  hPub: string,
  anR: Array<bigint>
): Array<tProof> {
  const pAlphaS = aeCiphertexts.slice(1).reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pBetaS = aeCiphertexts.slice(1).reduce((acc, c) => acc.add(c.pBeta), zero);
  const pY = parsePoint(state.setup.payload.election.public_key);
  const mS = anChoices.slice(1).reduce((acc, c) => c + acc, 0);
  const M = Array.from({ length: question.max - question.min + 1 }).map(
    (_, i) => i + question.min,
  );
  const nRS = anR.slice(1).reduce((acc, r) => mod(acc + r, L), BigInt(0));
  const nW = rand();

  if (anChoices[0] === 0) {
    const nChallenge0 = rand();
    const nResponse0 = rand();
    const [pA0, pB0] = formula2(pY, aeCiphertexts[0].pAlpha, aeCiphertexts[0].pBeta, nChallenge0, nResponse0, 1);

    let azProofs : Array<tProof> = [{
      nChallenge: nChallenge0,
      nResponse: nResponse0
    }];
    let commitments = [pA0, pB0];
    let nChallengeS = nChallenge0;

    for (let j = 0; j < M.length; j++) {
      const nChallenge = rand();
      const nResponse = rand();
      azProofs.push({ nChallenge, nResponse });
      if (M[j] === mS) {
        //5. Compute Ai = g^w and Bi = y^w.
        const pA = g.multiply(nW);
        const pB = pY.multiply(nW);
        commitments.push(pA, pB);
      } else {
        const [pA, pB] = formula2(pY, pAlphaS, pBetaS, nChallenge, nResponse, M[j]);
        nChallengeS = mod(nChallengeS + nChallenge, L);
        commitments.push(pA, pB);
      }
    }

    let S = `${state.setup.fingerprint}|${hPub}|`;
    S += aeCiphertexts.map(serializeCiphertext).map((c) => `${c.alpha},${c.beta}`).join(",");
    const nH = Hbproof1(S, ...commitments);

    for (let j = 0; j < M.length; j++) {
      if (M[j] === mS) {
        azProofs[j+1].nChallenge = mod(nH - nChallengeS, L);
        azProofs[j+1].nResponse = mod(nW - nRS * azProofs[j+1].nChallenge, L);
      }
    }

    return azProofs;
  } else { // anChoices[0] === 1 (Blank vote)
    console.assert(mS === 0);
    const pA0 = g.multiply(nW);
    const pB0 = pY.multiply(nW);
    let commitments = [pA0, pB0];

    let azProofs : Array<tProof> = [{
      nChallenge: BigInt(0),
      nResponse: BigInt(0)
    }];

    let nChallengeS = BigInt(0);
    for (let j = 0; j < M.length; j++) {
      const nChallenge = rand();
      const nResponse = rand();
      azProofs.push({ nChallenge, nResponse });
      const [pA, pB] = formula2(pY, pAlphaS, pBetaS, nChallenge, nResponse, M[j]);
      nChallengeS = mod(nChallengeS + nChallenge, L);
      commitments.push(pA, pB);
    }

    let S = `${state.setup.fingerprint}|${hPub}|`;
    S += aeCiphertexts.map(serializeCiphertext).map((c) => `${c.alpha},${c.beta}`).join(",");
    const nH = Hbproof1(S, ...commitments);

    azProofs[0].nChallenge = mod(nH - nChallengeS, L);
    azProofs[0].nResponse = mod(nW - anR[0] * azProofs[0].nChallenge, L);

    return azProofs;
  }
}

function generateAnswerWithBlank(
  state: any,
  question: any,
  sPriv: string,
  choices: Array<number>,
): tAnswerWithBlank {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const { hPublicCredential } = deriveCredential(state, sPriv);
  const { anR, aCiphertexts, aIndividualProofs } = generateEncryptions(
    state,
    pY,
    hPublicCredential,
    choices,
  );

  const pAlphaS = aCiphertexts.slice(1).reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pBetaS = aCiphertexts.slice(1).reduce((acc, c) => acc.add(c.pBeta), zero);
  const pAlpha0 = aCiphertexts[0].pAlpha;
  const pBeta0 = aCiphertexts[0].pBeta;
  const m = choices.slice(1).reduce((acc, c) => c + acc, 0);
  const M = Array.from({ length: question.max - question.min + 1 }).map(
    (_, i) => i + question.min,
  );
  const nRS = anR.slice(1).reduce((acc, r) => mod(acc + r, L), BigInt(0));
  const nR0 = anR[0];

  let azBlankProof : Array<tProof> = [];
  if (choices[0] === 0) {
    azBlankProof = blankProof(state, hPublicCredential, pY, aCiphertexts, pAlphaS, pBetaS, nR0, true);
  } else {
    azBlankProof = blankProof(state, hPublicCredential, pY, aCiphertexts, pAlpha0, pBeta0, nRS, false);
  }

  let overall_proof = overallProofBlank(state, question, choices,
                                        aCiphertexts, hPublicCredential, anR);

  return {
    choices: aCiphertexts.map(serializeCiphertext),
    individual_proofs: aIndividualProofs,
    overall_proof: overall_proof.map(serializeProof),
    blank_proof: azBlankProof.map(serializeProof)
  };
}

function signature(nPriv: bigint, sHash: string) {
  const w = rand();
  const pA = g.multiply(w);

  // TODO: Refactor using Hsignature
  // TODO: nChallenge = Hsignature(hash, pA);
  const hashSignature = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${sHash}|${rev(pA.toHex())}`),
  );
  const nChallenge = mod(BigInt("0x" + hashSignature), L);
  const nResponse = mod(w - nPriv * nChallenge, L);

  return {
    hash: sHash,
    proof: serializeProof({ nChallenge, nResponse }),
  };
}

function deriveCredential(state: any, sPriv: string) {
  const prefix = `derive_credential|${state.setup.payload.election.uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${sPriv}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${sPriv}`),
  );

  const nPrivateCredential = mod(BigInt("0x" + x0 + x1), L);
  const pPublicCredential = g.multiply(nPrivateCredential);
  const hPublicCredential = rev(pPublicCredential.toHex());

  return {
    nPrivateCredential,
    hPublicCredential,
  };
}
