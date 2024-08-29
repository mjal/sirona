import sjcl from "sjcl";
import * as Point from "./Point";
import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as Answer from "./Answer";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import * as Election from "./Election";
import * as Setup from "./Setup";
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
  setup: Setup.t,
  sPriv: string,
  choices: Array<Array<number>>,
) {
  const { election } = setup
  if (!checkVotingCode(setup, sPriv)) {
    return null;
  }

  const { hPublicCredential, nPrivateCredential } = Credential.derive(
    election.uuid,
    sPriv,
  );

  let answers: Array<Answer.AnswerH.Serialized.t> = [];
  for (let i = 0; i < choices.length; i++) {
    const question = election.questions[i];
    const answer = generateAnswer(election, question, sPriv, choices[i]);
    answers.push(answer);
  }

  const ballotWithoutSignature = {
    answers,
    credential: hPublicCredential,
    election_hash: Election.fingerprint(election),
    election_uuid: setup.election.uuid,
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
    election,
  );

  const ballot: Ballot.t = {
    ...ballotWithoutSignature,
    signature: signature(nPrivateCredential, hH),
  };

  Ballot.verify(setup, ballot);

  return ballot;
}

function checkVotingCode(setup: Setup.t, sPriv: string) {
  if (
    !/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(sPriv)
  ) {
    throw new Error(
      "Invalid credential format. Should be XXXXX-XXXXXX-XXXXX-XXXXXX.",
    );
  }

  const { hPublicCredential } = Credential.derive(
    setup.election.uuid,
    sPriv,
  );

  const electionPublicCredentials = setup.credentials.map(
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
  election: Election.t,
  question: any,
  sPriv: string,
  plaintexts: Array<number>
): Answer.AnswerH.Serialized.t {
  let nonces: Array<bigint> = [];
  let choices: Array<Ciphertext.t> = [];
  let individual_proofs: Array<Array<Proof.t>> = [];
  const pY = Point.parse(election.public_key);
  const { hPublicCredential } = Credential.derive(
    election.uuid,
    sPriv,
  );

  for (let i = 0; i < plaintexts.length; i++) {
    const r = rand();
    const gPowerM = plaintexts[i] === 0 ? zero : g.multiply(BigInt(plaintexts[i]));
    const alpha = g.multiply(r);
    const beta = pY.multiply(r).add(gPowerM);

    const S = `${Election.fingerprint(election)}|${hPublicCredential}`;
    const proof = iproof(S, pY, alpha, beta, r, plaintexts[i], [0, 1]);

    choices.push({ pAlpha: alpha, pBeta: beta });
    individual_proofs.push(proof);
    nonces.push(r);
  }

  if (question.blank) {
    const egS = Ciphertext.combine(choices.slice(1))
    const eg0 = choices[0];
    const nRS = nonces.slice(1).reduce((acc, r) => mod(acc + r, L), BigInt(0));
    const nR0 = nonces[0];

    const isBlank = (plaintexts[0] === 1);

    const blank_proof = blankProof(
      election,
      hPublicCredential,
      choices,
      isBlank ? eg0 : egS,
      isBlank ? nRS : nR0,
      isBlank,
    );
    let overall_proof = overallProofBlank(
      election,
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

    let S = `${Election.fingerprint(election)}|${hPublicCredential}|`;
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
  choices: Array<Ciphertext.t>,
  eg: Ciphertext.t,
  nR: bigint,
  isBlank: boolean,
): Array<Proof.t> {
  const pY = Point.parse(election.public_key);
  const proofA = { nChallenge: rand(), nResponse: rand() };
  const AS = formula(g, proofA.nResponse, eg.pAlpha, proofA.nChallenge);
  const BS = formula(pY, proofA.nResponse, eg.pBeta, proofA.nChallenge);
  const nW = rand();
  const A0 = g.multiply(nW);
  const B0 = pY.multiply(nW);

  let S = `${Election.fingerprint(election)}|${hPub}|`;
  S += choices.map(Ciphertext.toString).join(",");
  const nH = isBlank
    ? Hbproof0(S, AS, BS, A0, B0)
    : Hbproof0(S, A0, B0, AS, BS);
  const nChallenge = mod(nH - proofA.nChallenge, L);
  const nResponse = mod(nW - nChallenge * nR, L);
  const proofB = { nChallenge, nResponse };

  if (isBlank) {
    return [ proofA, proofB, ];
  } else {
    return [ proofB, proofA, ];
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
    S += aeCiphertexts.map(Ciphertext.toString).join(",");
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
    S += aeCiphertexts.map(Ciphertext.toString).join(",");
    const nH = Hbproof1(S, ...commitments);

    azProofs[0].nChallenge = mod(nH - nChallengeS, L);
    azProofs[0].nResponse = mod(nW - anR[0] * azProofs[0].nChallenge, L);

    return azProofs;
  }
}
