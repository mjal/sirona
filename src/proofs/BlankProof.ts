import * as Proof from "../Proof";
import * as Question from "../Question";
import * as AnswerH from "../AnswerH";
import * as Election from "../Election";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import * as Z from "../Z";
import { Hbproof0, Hbproof1 } from "../math";
import { range } from "../utils";

export namespace OverallProof {
  export function verify(
    election: Election.t,
    credential: string,
    question: Question.QuestionH.t, // NOTE: Could be replace by max and min
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
    const challengeS = Z.sumL(answer.overall_proof.map(({ nChallenge }) => nChallenge));
    let S = `${Election.fingerprint(election)}|${credential}|`;
    S += answer.choices.map(Ciphertext.toString).join(",");
  
    return Hbproof1(S, ...commitments) === challengeS;
  }

  export function generate(
    // TODO Rename params:
    // election, question, plaintexts, ciphertexts, credential, nonces
    election: Election.t,
    question: Question.QuestionH.t, // NOTE: Could be replace by max and min
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
  
      for (let j = 0; j < M.length; j++) {
        if (M[j] === mS) {
          const proof = Proof.zero();
          const A = Point.g.multiply(nW);
          const B = y.multiply(nW);
          commitments.push(A, B);
          azProofs.push(proof);
        } else {
          const proof = Proof.rand();
          const [A, B] = Point.compute_commitment_pair(
            y,
            egS,
            proof,
            M[j]
          );
          commitments.push(A, B);
          azProofs.push(proof);
        }
      }
  
      const nChallengeS = Z.sumL(azProofs.map(({ nChallenge }) => nChallenge));
  
      let S = `${Election.fingerprint(election)}|${hPub}|`;
      S += aeCiphertexts.map(Ciphertext.toString).join(",");
      const nH = Hbproof1(S, ...commitments);
  
      for (let j = 0; j < M.length; j++) {
        if (M[j] === mS) {
          const nChallenge = Z.modL(nH - nChallengeS);
          const nResponse = Z.modL(nW - nRS * nChallenge);
          azProofs[j + 1] = { nChallenge, nResponse };
        }
      }
  
      return azProofs;
    } else {
      // anChoices[0] === 1 (Blank vote)
      console.assert(mS === 0);
      const pA0 = Point.g.multiply(nW);
      const pB0 = y.multiply(nW);
      let commitments = [pA0, pB0];
  
      let azProofs: Array<Proof.t> = [ Proof.zero() ];
  
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
  
      const nChallenge = Z.modL(nH - nChallengeS);
      const nResponse = Z.modL(nW - anR[0] * nChallenge);
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
    const challengeS = Z.sumL(answer.blank_proof.map(({ nChallenge }) => nChallenge));
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
    return Hbproof0(S, ...[pA0, pB0, pAS, pBS]) === challengeS;
  }
}
