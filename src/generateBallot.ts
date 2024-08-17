import sjcl from "sjcl";
import * as Point from "./Point";
import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as Answer from "./Answer";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import {
  g,
  L,
  rev,
  mod,
  rand,
  formula2,
  formula,
  Hiprove,
  Hbproof0,
  Hbproof1,
  zero,
} from "./math";

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
    proof: Proof.serialize({ nChallenge, nResponse }),
  };
}

export default function (
  state: any,
  sPriv: string,
  choices: Array<Array<number>>,
) {
  if (!checkVotingCode(state, sPriv)) {
    return null;
  }

  const { hPublicCredential, nPrivateCredential } = Credential.derive(
    state.setup.election.uuid,
    sPriv,
  );

  let answers: Array<Answer.AnswerH.Serialized.t> = [];
  for (let i = 0; i < choices.length; i++) {
    const question = state.setup.election.questions[i];
    const f = question.blank
      ? generateAnswerWithBlank
      : generateAnswerWithoutBlank;
    const answer = f(state, question, sPriv, choices[i]);
    answers.push(answer);
  }

  const ballotWithoutSignature = {
    answers,
    credential: hPublicCredential,
    election_hash: state.setup.election.fingerprint,
    election_uuid: state.setup.election.uuid,
    signature: {
      hash: null,
      proof: {
        challenge: null,
        response: null,
      },
    },
  };

  const hH = Ballot.hashWithoutSignature(
    ballotWithoutSignature,
    state.setup.election,
  );

  const ballot : Ballot.t = {
    ...ballotWithoutSignature,
    signature: signature(nPrivateCredential, hH),
  };

  const sSerializedBallot = JSON.stringify(
    Ballot.toJSON(ballot, state.setup.election),
  );
  const hash = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(sSerializedBallot),
  );
  ballot.hash = hash;
  Ballot.verify(state, ballot);

  return ballot;
}

function checkVotingCode(state: any, sPriv: string) {
  if (
    !/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(sPriv)
  ) {
    alert("Invalid credential format. Should be XXXXX-XXXXXX-XXXXX-XXXXXX.");
    return false;
  }

  const { hPublicCredential } = Credential.derive(
    state.setup.election.uuid,
    sPriv,
  );

  const electionPublicCredentials = state.setup.credentials.map(
    (line: string) => line.split(",")[0],
  );

  if (!electionPublicCredentials.includes(hPublicCredential)) {
    throw "Invalid credential.";
  }

  return true;
}

function iproof(
  prefix: string,
  pY: Point.t,
  pAlpha: Point.t,
  pBeta: Point.t,
  r: bigint,
  m: number,
  M: Array<number>,
): Array<Proof.t> {
  const w = rand();
  let commitments: Array<Point.t> = [];
  let proofs: Array<Proof.t> = [];

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

  return proofs;
}

function generateEncryptions(
  state: any,
  pY: Point.t,
  hPublicCredential: string,
  choices: Array<number>,
) {
  let anR: Array<bigint> = [];
  let aeChoices: Array<Ciphertext.t> = [];
  let aazIndividualProofs: Array<Array<Proof.t>> = [];

  for (let i = 0; i < choices.length; i++) {
    const nR = rand();
    const gPowerM = choices[i] === 0 ? zero : g.multiply(BigInt(choices[i]));
    const pAlpha = g.multiply(nR);
    const pBeta = pY.multiply(nR).add(gPowerM);

    const S = `${state.setup.election.fingerprint}|${hPublicCredential}`;
    const proof = iproof(S, pY, pAlpha, pBeta, nR, choices[i], [0, 1]);

    aeChoices.push({ pAlpha, pBeta });
    aazIndividualProofs.push(proof);
    anR.push(nR);
  }

  return { anR, aeChoices, aazIndividualProofs };
}

function generateAnswerWithoutBlank(
  state: any,
  question: any,
  sPriv: string,
  choices: Array<number>,
): Answer.AnswerH.Serialized.t {
  const pY = Point.parse(state.setup.election.public_key);
  const { hPublicCredential } = Credential.derive(
    state.setup.election.uuid,
    sPriv,
  );
  const { anR, aeChoices, aazIndividualProofs } = generateEncryptions(
    state,
    pY,
    hPublicCredential,
    choices,
  );

  const pSumAlpha = aeChoices.reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pSumBeta = aeChoices.reduce((acc, c) => acc.add(c.pBeta), zero);
  const m = choices.reduce((acc, c) => c + acc, 0);
  const M = Array.from({ length: question.max - question.min + 1 }).map(
    (_, i) => i + question.min,
  );
  const nR = anR.reduce((acc, r) => mod(acc + r, L), BigInt(0));

  let S = `${state.setup.election.fingerprint}|${hPublicCredential}|`;
  S += aeChoices
    .map((c) => `${rev(c.pAlpha.toHex())},${rev(c.pBeta.toHex())}`)
    .join(",");
  const azOverallProof = iproof(S, pY, pSumAlpha, pSumBeta, nR, m, M);

  return Answer.AnswerH.serialize({
    aeChoices,
    aazIndividualProofs,
    azOverallProof,
  });
}

function blankProof(
  state: any,
  hPub: string,
  pY: Point.t,
  choices: Array<Ciphertext.t>,
  pAlphaS: Point.t,
  pBetaS: Point.t,
  nR0: bigint,
  bNonBlank: boolean,
): Array<Proof.t> {
  const nChallengeS = rand();
  const nResponseS = rand();
  const pAS = formula(g, nResponseS, pAlphaS, nChallengeS);
  const pBS = formula(pY, nResponseS, pBetaS, nChallengeS);
  const nW = rand();
  const pA0 = g.multiply(nW);
  const pB0 = pY.multiply(nW);

  let S = `${state.setup.election.fingerprint}|${hPub}|`;
  S += choices
    .map(Ciphertext.serialize)
    .map((c) => `${c.alpha},${c.beta}`)
    .join(",");
  const nH = bNonBlank
    ? Hbproof0(S, pA0, pB0, pAS, pBS)
    : Hbproof0(S, pAS, pBS, pA0, pB0);
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
  aeCiphertexts: Array<Ciphertext.t>,
  hPub: string,
  anR: Array<bigint>,
): Array<Proof.t> {
  const pAlphaS = aeCiphertexts
    .slice(1)
    .reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pBetaS = aeCiphertexts
    .slice(1)
    .reduce((acc, c) => acc.add(c.pBeta), zero);
  const pY = Point.parse(state.setup.election.public_key);
  const mS = anChoices.slice(1).reduce((acc, c) => c + acc, 0);
  const M = Array.from({ length: question.max - question.min + 1 }).map(
    (_, i) => i + question.min,
  );
  const nRS = anR.slice(1).reduce((acc, r) => mod(acc + r, L), BigInt(0));
  const nW = rand();

  if (anChoices[0] === 0) {
    const nChallenge0 = rand();
    const nResponse0 = rand();
    const [pA0, pB0] = formula2(
      pY,
      aeCiphertexts[0].pAlpha,
      aeCiphertexts[0].pBeta,
      nChallenge0,
      nResponse0,
      1,
    );

    let azProofs: Array<Proof.t> = [
      {
        nChallenge: nChallenge0,
        nResponse: nResponse0,
      },
    ];
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
        const [pA, pB] = formula2(
          pY,
          pAlphaS,
          pBetaS,
          nChallenge,
          nResponse,
          M[j],
        );
        nChallengeS = mod(nChallengeS + nChallenge, L);
        commitments.push(pA, pB);
      }
    }

    let S = `${state.setup.election.fingerprint}|${hPub}|`;
    S += aeCiphertexts
      .map(Ciphertext.serialize)
      .map((c) => `${c.alpha},${c.beta}`)
      .join(",");
    const nH = Hbproof1(S, ...commitments);

    for (let j = 0; j < M.length; j++) {
      if (M[j] === mS) {
        azProofs[j + 1].nChallenge = mod(nH - nChallengeS, L);
        azProofs[j + 1].nResponse = mod(
          nW - nRS * azProofs[j + 1].nChallenge,
          L,
        );
      }
    }

    return azProofs;
  } else {
    // anChoices[0] === 1 (Blank vote)
    console.assert(mS === 0);
    const pA0 = g.multiply(nW);
    const pB0 = pY.multiply(nW);
    let commitments = [pA0, pB0];

    let azProofs: Array<Proof.t> = [
      {
        nChallenge: BigInt(0),
        nResponse: BigInt(0),
      },
    ];

    let nChallengeS = BigInt(0);
    for (let j = 0; j < M.length; j++) {
      const nChallenge = rand();
      const nResponse = rand();
      azProofs.push({ nChallenge, nResponse });
      const [pA, pB] = formula2(
        pY,
        pAlphaS,
        pBetaS,
        nChallenge,
        nResponse,
        M[j],
      );
      nChallengeS = mod(nChallengeS + nChallenge, L);
      commitments.push(pA, pB);
    }

    let S = `${state.setup.election.fingerprint}|${hPub}|`;
    S += aeCiphertexts
      .map(Ciphertext.serialize)
      .map((c) => `${c.alpha},${c.beta}`)
      .join(",");
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
): Answer.AnswerH.Serialized.t {
  const pY = Point.parse(state.setup.election.public_key);
  const { hPublicCredential } = Credential.derive(
    state.setup.election.uuid,
    sPriv,
  );
  const { anR, aeChoices, aazIndividualProofs } = generateEncryptions(
    state,
    pY,
    hPublicCredential,
    choices,
  );

  const pAlphaS = aeChoices
    .slice(1)
    .reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pBetaS = aeChoices.slice(1).reduce((acc, c) => acc.add(c.pBeta), zero);
  const pAlpha0 = aeChoices[0].pAlpha;
  const pBeta0 = aeChoices[0].pBeta;
  const nRS = anR.slice(1).reduce((acc, r) => mod(acc + r, L), BigInt(0));
  const nR0 = anR[0];

  let azBlankProof: Array<Proof.t> = [];
  if (choices[0] === 0) {
    azBlankProof = blankProof(
      state,
      hPublicCredential,
      pY,
      aeChoices,
      pAlphaS,
      pBetaS,
      nR0,
      true,
    );
  } else {
    azBlankProof = blankProof(
      state,
      hPublicCredential,
      pY,
      aeChoices,
      pAlpha0,
      pBeta0,
      nRS,
      false,
    );
  }

  let azOverallProof = overallProofBlank(
    state,
    question,
    choices,
    aeChoices,
    hPublicCredential,
    anR,
  );
  return Answer.AnswerH.serialize({
    aeChoices,
    aazIndividualProofs,
    azOverallProof,
    azBlankProof,
  });
}
