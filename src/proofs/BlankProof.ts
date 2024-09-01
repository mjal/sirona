import * as Proof from "../Proof";
import * as Question from "../Question";
import * as AnswerH from "../AnswerH";
import * as Election from "../Election";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import * as Z from "../Z";
import H from "../H";
import { range } from "../utils";

export namespace OverallProof {
  export function verify(
    election: Election.t,
    credential: string,
    question: Question.QuestionH.t, // NOTE: Could be replaced by max and min
    answer: AnswerH.t,
  ): boolean {
    let commitments = [];
    const y = Point.parse(election.public_key);
    const sumc = Ciphertext.combine(answer.choices.slice(1));
    const [A, B] = Point.compute_commitment_pair(
      y,
      answer.choices[0],
      answer.overall_proof[0],
      1,
    );
    commitments.push(A, B);
    for (let j = 1; j < question.max - question.min + 2; j++) {
      const [A, B] = Point.compute_commitment_pair(
        y,
        sumc,
        answer.overall_proof[j],
        question.min + j - 1,
      );
      commitments.push(A, B);
    }
    const challengeS = Z.sumL(
      answer.overall_proof.map(({ nChallenge }) => nChallenge),
    );
    let S = `${Election.fingerprint(election)}|${credential}|`;
    S += answer.choices.map(Ciphertext.toString).join(",");

    return Hbproof_1(S, ...commitments) === challengeS;
  }

  export function generate(
    election: Election.t,
    prefix: string,
    question: Question.QuestionH.t, // NOTE: Could be replaced by max and min
    plaintexts: Array<number>,
    ciphertexts: Array<Ciphertext.t>,
    nonces: Array<bigint>,
  ): Array<Proof.t> {
    const egS = Ciphertext.combine(ciphertexts.slice(1));
    const y = Point.parse(election.public_key);
    const mS = plaintexts.slice(1).reduce((acc, c) => c + acc, 0);
    const M = range(question.min, question.max);
    const nRS = Z.sumL(nonces.slice(1));
    const nW = Z.randL();

    if (plaintexts[0] === 0) {
      const proof0 = {
        nChallenge: Z.randL(),
        nResponse: Z.randL(),
      };
      const [pA0, pB0] = Point.compute_commitment_pair(
        y,
        ciphertexts[0],
        proof0,
        1,
      );

      let azProofs: Array<Proof.t> = [proof0];
      let commitments = [pA0, pB0];

      for (let j = 0; j < M.length; j++) {
        const proof = M[j] !== mS ? Proof.rand() : Proof.zero();
        const [A, B] =
          M[j] !== mS
            ? Point.compute_commitment_pair(y, egS, proof, M[j])
            : [Point.g.multiply(nW), y.multiply(nW)];
        commitments.push(A, B);
        azProofs.push(proof);
      }

      const nChallengeS = Z.sumL(azProofs.map(({ nChallenge }) => nChallenge));

      let S = `${Election.fingerprint(election)}|${prefix}|`;
      S += ciphertexts.map(Ciphertext.toString).join(",");
      const nH = Hbproof_1(S, ...commitments);

      for (let j = 0; j < M.length; j++) {
        if (M[j] === mS) {
          azProofs[j + 1].nChallenge = Z.modL(nH - nChallengeS);
          azProofs[j + 1].nResponse = Z.modL(
            nW - nRS * azProofs[j + 1].nChallenge,
          );
        }
      }

      return azProofs;
    } else {
      // plaintexts[0] === 1 (Blank vote)
      console.assert(mS === 0);
      const pA0 = Point.g.multiply(nW);
      const pB0 = y.multiply(nW);
      let commitments = [pA0, pB0];

      let azProofs: Array<Proof.t> = [Proof.zero()];

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

      let S = `${Election.fingerprint(election)}|${prefix}|`;
      S += ciphertexts.map(Ciphertext.toString).join(",");
      const nH = Hbproof_1(S, ...commitments);

      const nChallenge = Z.modL(nH - nChallengeS);
      const nResponse = Z.modL(nW - nonces[0] * nChallenge);
      azProofs[0] = { nChallenge, nResponse };

      return azProofs;
    }
  }
}

export namespace BlankProof {
  export function verify(
    election: Election.t,
    credential: string,
    answer: AnswerH.t,
  ): boolean {
    const y = Point.parse(election.public_key);
    const sumc = Ciphertext.combine(answer.choices.slice(1));
    const challengeS = Z.sumL(
      answer.blank_proof.map(({ nChallenge }) => nChallenge),
    );
    const [pA0, pB0] = Point.compute_commitment_pair(
      y,
      answer.choices[0],
      answer.blank_proof[0],
      0,
    );
    const [pAS, pBS] = Point.compute_commitment_pair(
      y,
      sumc,
      answer.blank_proof[1],
      0,
    );

    let S = `${Election.fingerprint(election)}|${credential}|`;
    S += answer.choices.map(Ciphertext.toString).join(",");
    return Hbproof_0(S, ...[pA0, pB0, pAS, pBS]) === challengeS;
  }

  export function generate(
    election: Election.t,
    hPub: string,
    ciphertexts: Array<Ciphertext.t>, // TODO: Pass as prefix ? (only used in prefix)
    eg: Ciphertext.t,
    nonce: bigint,
    isBlank: boolean,
  ): Array<Proof.t> {
    const y = Point.parse(election.public_key);
    const nW = Z.randL();
    const proofA = Proof.rand();
    const A0 = Point.g.multiply(nW);
    const B0 = y.multiply(nW);
    const AS = Point.compute_commitment(Point.g, eg.pAlpha, proofA);
    const BS = Point.compute_commitment(y, eg.pBeta, proofA);

    let S = `${Election.fingerprint(election)}|${hPub}|`;
    S += ciphertexts.map(Ciphertext.toString).join(",");
    const nH = isBlank
      ? Hbproof_0(S, AS, BS, A0, B0)
      : Hbproof_0(S, A0, B0, AS, BS);
    const nChallenge = Z.modL(nH - proofA.nChallenge);
    const nResponse = Z.modL(nW - nChallenge * nonce);
    const proofB = { nChallenge, nResponse };

    if (isBlank) {
      return [proofA, proofB];
    } else {
      return [proofB, proofA];
    }
  }
}

function Hbproof_0(S: string, ...commitments: Array<Point.t>) {
  return H(`bproof0|${S}`, ...commitments);
}

function Hbproof_1(S: string, ...commitments: Array<Point.t>) {
  return H(`bproof1|${S}`, ...commitments);
}
