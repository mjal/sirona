import sjcl from "sjcl";
import * as Point from "./Point";
import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as Answer from "./Answer";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import * as Election from "./Election";
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
    const answer = generateAnswer(state, question, sPriv, choices[i]);
    answers.push(answer);
  }

  const ballotWithoutSignature = {
    answers,
    credential: hPublicCredential,
    election_hash: Election.fingerprint(state.setup.election),
    election_uuid: state.setup.election.uuid,
    signature: {
      hash: null,
      proof: {
        challenge: null,
        response: null,
      },
    },
  };

  const hH = Ballot.b64hashWithoutSignature(
    ballotWithoutSignature,
    state.setup.election,
  );

  const ballot: Ballot.t = {
    ...ballotWithoutSignature,
    signature: signature(nPrivateCredential, hH),
  };

  Ballot.verify(state.setup, ballot);

  return ballot;
}

function checkVotingCode(state: any, sPriv: string) {
  if (
    !/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(sPriv)
  ) {
    throw new Error(
      "Invalid credential format. Should be XXXXX-XXXXXX-XXXXX-XXXXXX.",
    );
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

function generateAnswer(
  state: any,
  question: any,
  sPriv: string,
  plaintexts: Array<number>
): Answer.AnswerH.Serialized.t {
  let nonces: Array<bigint> = [];
  let choices: Array<Ciphertext.t> = [];
  let individual_proofs: Array<Array<Proof.t>> = [];
  const pY = Point.parse(state.setup.election.public_key);
  const { hPublicCredential } = Credential.derive(
    state.setup.election.uuid,
    sPriv,
  );

  for (let i = 0; i < plaintexts.length; i++) {
    const r = rand();
    const gPowerM = plaintexts[i] === 0 ? zero : g.multiply(BigInt(plaintexts[i]));
    const alpha = g.multiply(r);
    const beta = pY.multiply(r).add(gPowerM);

    const S = `${Election.fingerprint(state.setup.election)}|${hPublicCredential}`;
    const proof = iproof(S, pY, alpha, beta, r, plaintexts[i], [0, 1]);

    choices.push({ pAlpha: alpha, pBeta: beta });
    individual_proofs.push(proof);
    nonces.push(r);
  }

  if (question.blank) {
    const pAlphaS = choices
      .slice(1)
      .reduce((acc, c) => acc.add(c.pAlpha), zero);
    const pBetaS = choices.slice(1).reduce((acc, c) => acc.add(c.pBeta), zero);
    const pAlpha0 = choices[0].pAlpha;
    const pBeta0 = choices[0].pBeta;
    const nRS = nonces.slice(1).reduce((acc, r) => mod(acc + r, L), BigInt(0));
    const nR0 = nonces[0];

    let blank_proof: Array<Proof.t> = [];
    if (plaintexts[0] === 0) {
      blank_proof = blankProof(
        state.setup.election,
        hPublicCredential,
        pY,
        choices,
        pAlphaS,
        pBetaS,
        nR0,
        true,
      );
    } else {
      blank_proof = blankProof(
        state.setup.election,
        hPublicCredential,
        pY,
        choices,
        pAlpha0,
        pBeta0,
        nRS,
        false,
      );
    }

    let overall_proof = overallProofBlank(
      state.setup.election,
      question,
      plaintexts,
      choices,
      hPublicCredential,
      nonces,
    );
    return Answer.AnswerH.serialize({
      choices,
      individual_proofs,
      overall_proof,
      blank_proof,
    });
  } else {
    // TODO: Use Ciphertext.combine
    const pSumAlpha = choices.reduce((acc, c) => acc.add(c.pAlpha), zero);
    const pSumBeta = choices.reduce((acc, c) => acc.add(c.pBeta), zero);
    const m = plaintexts.reduce((acc, c) => c + acc, 0);
    const M = Array.from({ length: question.max - question.min + 1 }).map(
      (_, i) => i + question.min,
    );
    const nR = nonces.reduce((acc, r) => mod(acc + r, L), BigInt(0));

    let S = `${Election.fingerprint(state.setup.election)}|${hPublicCredential}|`;
    S += choices
      .map((c) => `${rev(c.pAlpha.toHex())},${rev(c.pBeta.toHex())}`)
      .join(",");
    const overall_proof = iproof(S, pY, pSumAlpha, pSumBeta, nR, m, M);

    return Answer.AnswerH.serialize({
      choices,
      individual_proofs,
      overall_proof,
    });
  }
}

function blankProof(
  election: Election.t,
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

  let S = `${Election.fingerprint(election)}|${hPub}|`;
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
  election: Election.t,
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
  const pY = Point.parse(election.public_key);
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

    let S = `${Election.fingerprint(election)}|${hPub}|`;
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

    let S = `${Election.fingerprint(election)}|${hPub}|`;
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
