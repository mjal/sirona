import sjcl from "sjcl";
import * as Point from "./Point";
import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as Answer from "./Answer";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import * as Election from "./Election";
import * as Setup from "./Setup";
import * as Z from "./Z";
import { range } from "./utils";
import {
  Hbproof0,
  Hbproof1,
} from "./math";

// TODO: Move to SignatureProof ?
function signature(nPriv: bigint, sHash: string) {
  const w = Z.randL();
  const A = Point.g.multiply(w);

  // TODO: Refactor using Hsignature ?
  // TODO: nChallenge = Hsignature(hash, pA);
  const hashSignature = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${sHash}|${Point.serialize(A)}`),
  );
  const nChallenge = Z.modL(BigInt("0x" + hashSignature));
  const nResponse = Z.mod(w - nPriv * nChallenge, Z.L);

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

function generateAnswer(
  election: Election.t,
  question: any,
  sPriv: string,
  plaintexts: Array<number>
): Answer.AnswerH.Serialized.t {
  let nonces: Array<bigint> = [];
  let choices: Array<Ciphertext.t> = [];
  let individual_proofs: Array<Array<Proof.t>> = [];
  const y = Point.parse(election.public_key);
  const { hPublicCredential } = Credential.derive(
    election.uuid,
    sPriv,
  );

  for (let i = 0; i < plaintexts.length; i++) {
    const r = Z.randL();
    const gPowerM = plaintexts[i] === 0 ? Point.zero : Point.g.multiply(BigInt(plaintexts[i]));
    const pAlpha = Point.g.multiply(r);
    const pBeta = y.multiply(r).add(gPowerM);

    const proof = IndividualProof.generate(election, hPublicCredential, { pAlpha, pBeta }, r, plaintexts[i], [0, 1]);

    choices.push({ pAlpha, pBeta });
    individual_proofs.push(proof);
    nonces.push(r);
  }

  if (question.blank) {
    const egS = Ciphertext.combine(choices.slice(1))
    const eg0 = choices[0];
    const nRS = Z.sumL(nonces.slice(1));
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
    const egS = Ciphertext.combine(choices);
    const m = plaintexts.reduce((acc, c) => c + acc, 0);
    const M = range(question.min, question.max);
    const nR = Z.sumL(nonces);

    let prefix = hPublicCredential + "|" + choices.map(Ciphertext.toString).join(",")
    const overall_proof = IndividualProof.generate(election, prefix, egS, nR, m, M);

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
  const y = Point.parse(election.public_key);
  const nW = Z.randL();
  const proofA = { nChallenge: Z.randL(), nResponse: Z.randL() };
  const A0 = Point.g.multiply(nW);
  const B0 = y.multiply(nW);
  const AS = Point.compute_commitment(Point.g, eg.pAlpha, proofA);
  const BS = Point.compute_commitment(y, eg.pBeta, proofA);

  let S = `${Election.fingerprint(election)}|${hPub}|`;
  S += choices.map(Ciphertext.toString).join(",");
  const nH = isBlank
    ? Hbproof0(S, AS, BS, A0, B0)
    : Hbproof0(S, A0, B0, AS, BS);
  const nChallenge = Z.modL(nH - proofA.nChallenge);
  const nResponse = Z.modL(nW - nChallenge * nR);
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
  const egS = Ciphertext.combine(aeCiphertexts.slice(1));
  const y = Point.parse(election.public_key);
  const mS = anChoices.slice(1).reduce((acc, c) => c + acc, 0);
  const M = range(question.min, question.max);
  const nRS = Z.sumL(anR.slice(1));
  const nW = Z.randL();

  if (anChoices[0] === 0) {
    const proof0 = {
      nChallenge: Z.randL(),
      nResponse: Z.randL()
    };
    const [pA0, pB0] = Point.compute_commitment_pair(
      y,
      aeCiphertexts[0],
      proof0,
      1,
    );

    let azProofs: Array<Proof.t> = [ proof0 ];
    let commitments = [pA0, pB0];
    let nChallengeS = proof0.nChallenge;

    for (let j = 0; j < M.length; j++) {
      // TODO push { 0, 0 } when M[j] === mS so nChallengeS can be computed as a sum of all challenges after the loop (proof0.nChallenge + Z.sum(proofs.map({nChallenge} => nChallenge)))?
      const proof = {
        nChallenge: Z.randL(),
        nResponse: Z.randL()
      };
      azProofs.push(proof);
      if (M[j] === mS) {
        //5. Compute Ai = g^w and Bi = y^w.
        const A = Point.g.multiply(nW);
        const B = y.multiply(nW);
        commitments.push(A, B);
      } else {
        const [A, B] = Point.compute_commitment_pair(
          y,
          egS,
          proof,
          M[j]
        );
        nChallengeS = Z.modL(nChallengeS + proof.nChallenge);
        commitments.push(A, B);
      }
    }

    let S = `${Election.fingerprint(election)}|${hPub}|`;
    S += aeCiphertexts.map(Ciphertext.toString).join(",");
    const nH = Hbproof1(S, ...commitments);

    for (let j = 0; j < M.length; j++) {
      if (M[j] === mS) {
        azProofs[j + 1].nChallenge = Z.modL(nH - nChallengeS);
        azProofs[j + 1].nResponse = Z.modL(
          nW - nRS * azProofs[j + 1].nChallenge
        );
      }
    }

    return azProofs;
  } else {
    // anChoices[0] === 1 (Blank vote)
    console.assert(mS === 0);
    const pA0 = Point.g.multiply(nW);
    const pB0 = y.multiply(nW);
    let commitments = [pA0, pB0];

    let azProofs: Array<Proof.t> = [
      {
        nChallenge: BigInt(0),
        nResponse: BigInt(0),
      },
    ];

    let nChallengeS = BigInt(0);
    for (let j = 0; j < M.length; j++) {
      const nChallenge = Z.randL();
      const nResponse = Z.randL();
      azProofs.push({ nChallenge, nResponse });
      const [pA, pB] = Point.compute_commitment_pair(
        y,
        egS,
        { nChallenge, nResponse },
        M[j],
      );
      nChallengeS = Z.modL(nChallengeS + nChallenge);
      commitments.push(pA, pB);
    }

    let S = `${Election.fingerprint(election)}|${hPub}|`;
    S += aeCiphertexts.map(Ciphertext.toString).join(",");
    const nH = Hbproof1(S, ...commitments);

    azProofs[0].nChallenge = Z.modL(nH - nChallengeS);
    azProofs[0].nResponse = Z.modL(nW - anR[0] * azProofs[0].nChallenge);

    return azProofs;
  }
}
