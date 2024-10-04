import * as Proof from "../Proof";
import * as Question from "../Question";
import * as AnswerH from "../AnswerH";
import * as Election from "../Election";
import * as Point from "../Point";
import * as ElGamal from "../ElGamal";
import * as Zq from "../Zq";
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
    const y = election.public_key;
    const sumc = ElGamal.combine(answer.choices.slice(1));
    const [A, B] = Point.commit_pair(
      y,
      answer.choices[0],
      answer.overall_proof[0],
      1,
    );
    commitments.push(A, B);
    for (let j = 1; j < question.max - question.min + 2; j++) {
      const [A, B] = Point.commit_pair(
        y,
        sumc,
        answer.overall_proof[j],
        question.min + j - 1,
      );
      commitments.push(A, B);
    }
    const challengeS = Zq.sum(
      answer.overall_proof.map(({ challenge }) => challenge),
    );
    let S = `${Election.fingerprint(election)}|${credential}|`;
    S += answer.choices.map(ElGamal.toString).join(",");

    return Hbproof_1(S, ...commitments) === challengeS;
  }

  export function generate(
    election: Election.t,
    prefix: string,
    question: Question.QuestionH.t, // NOTE: Could be replaced by max and min
    plaintexts: Array<number>,
    ciphertexts: Array<ElGamal.t>,
    nonces: Array<bigint>,
  ): Array<Proof.t> {
    const egS = ElGamal.combine(ciphertexts.slice(1));
    const y = election.public_key;
    const mS = plaintexts.slice(1).reduce((acc, c) => c + acc, 0);
    const M = range(question.min, question.max);
    const nRS = Zq.sum(nonces.slice(1));
    const nW = Zq.rand();

    if (plaintexts[0] === 0) {
      const proof0 = {
        challenge: Zq.rand(),
        response: Zq.rand(),
      };
      const [pA0, pB0] = Point.commit_pair(
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
            ? Point.commit_pair(y, egS, proof, M[j])
            : [Point.g.multiply(nW), y.multiply(nW)];
        commitments.push(A, B);
        azProofs.push(proof);
      }

      const challengeS = Zq.sum(azProofs.map(({ challenge }) => challenge));

      let S = `${Election.fingerprint(election)}|${prefix}|`;
      S += ciphertexts.map(ElGamal.toString).join(",");
      const nH = Hbproof_1(S, ...commitments);

      for (let j = 0; j < M.length; j++) {
        if (M[j] === mS) {
          azProofs[j + 1].challenge = Zq.mod(nH - challengeS);
          azProofs[j + 1].response = Zq.mod(
            nW - nRS * azProofs[j + 1].challenge,
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

      let challengeS = BigInt(0);
      for (let j = 0; j < M.length; j++) {
        const challenge = Zq.rand();
        const response = Zq.rand();
        azProofs.push({ challenge, response });
        const [pA, pB] = Point.commit_pair(
          y,
          egS,
          { challenge, response },
          M[j],
        );
        challengeS = Zq.mod(challengeS + challenge);
        commitments.push(pA, pB);
      }

      let S = `${Election.fingerprint(election)}|${prefix}|`;
      S += ciphertexts.map(ElGamal.toString).join(",");
      const nH = Hbproof_1(S, ...commitments);

      const challenge = Zq.mod(nH - challengeS);
      const response = Zq.mod(nW - nonces[0] * challenge);
      azProofs[0] = { challenge, response };

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
    const y = election.public_key;
    const sumc = ElGamal.combine(answer.choices.slice(1));
    const challengeS = Zq.sum(
      answer.blank_proof.map(({ challenge }) => challenge),
    );
    const [pA0, pB0] = Point.commit_pair(
      y,
      answer.choices[0],
      answer.blank_proof[0],
      0,
    );
    const [pAS, pBS] = Point.commit_pair(
      y,
      sumc,
      answer.blank_proof[1],
      0,
    );

    let S = `${Election.fingerprint(election)}|${credential}|`;
    S += answer.choices.map(ElGamal.toString).join(",");
    return Hbproof_0(S, ...[pA0, pB0, pAS, pBS]) === challengeS;
  }

  export function generate(
    election: Election.t,
    hPub: string,
    ciphertexts: Array<ElGamal.t>, // TODO: Pass as prefix ? (only used in prefix)
    eg: ElGamal.t,
    nonce: bigint,
    isBlank: boolean,
  ): Array<Proof.t> {
    const y = election.public_key;
    const nW = Zq.rand();
    const proofA = Proof.rand();
    const A0 = Point.g.multiply(nW);
    const B0 = y.multiply(nW);
    const AS = Point.commit(Point.g, eg.alpha, proofA);
    const BS = Point.commit(y, eg.beta, proofA);

    let S = `${Election.fingerprint(election)}|${hPub}|`;
    S += ciphertexts.map(ElGamal.toString).join(",");
    const nH = isBlank
      ? Hbproof_0(S, AS, BS, A0, B0)
      : Hbproof_0(S, A0, B0, AS, BS);
    const challenge = Zq.mod(nH - proofA.challenge);
    const response = Zq.mod(nW - challenge * nonce);
    const proofB = { challenge, response };

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
