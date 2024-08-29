import * as Question from "../Question";
import * as AnswerH from "../AnswerH";
import * as Election from "../Election";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import { L, mod, formula2, Hbproof0, Hbproof1 } from "../math";

export namespace OverallProof {
  export function verify(
    election: Election.t,
    credential: string,
    question: Question.QuestionH.t,
    answer: AnswerH.t,
  ): boolean {
    const pY = Point.parse(election.public_key);
    const sumc = Ciphertext.combine(answer.choices.slice(1));
  
    let commitments = [];
    const [pA, pB] = formula2(
      pY,
      answer.choices[0].pAlpha,
      answer.choices[0].pBeta,
      answer.overall_proof[0].nChallenge,
      answer.overall_proof[0].nResponse,
      1,
    );
    commitments.push(pA, pB);
    for (let j = 1; j < question.max - question.min + 2; j++) {
      const [pA, pB] = formula2(
        pY,
        sumc.pAlpha,
        sumc.pBeta,
        answer.overall_proof[j].nChallenge,
        answer.overall_proof[j].nResponse,
        question.min + j - 1,
      );
      commitments.push(pA, pB);
    }
  
    const nSumChallenges = answer.overall_proof.reduce(
      (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
      0n,
    );
  
    let S = `${Election.fingerprint(election)}|${credential}|`;
    S += answer.choices.map(Ciphertext.toString).join(",");
  
    return Hbproof1(S, ...commitments) === nSumChallenges;
  }
}

export namespace BlankProof {
  export function verify(
    election: Election.t,
    credential: string,
    answer: AnswerH.t,
  ): boolean {
    const pY = Point.parse(election.public_key);
    const sumc = Ciphertext.combine(answer.choices.slice(1));
    const nSumChallenges = answer.blank_proof.reduce(
      (acc, proof) => mod(acc + BigInt(proof.nChallenge), L),
      0n,
    );
  
    const [pA0, pB0] = formula2(
      pY,
      answer.choices[0].pAlpha,
      answer.choices[0].pBeta,
      answer.blank_proof[0].nChallenge,
      answer.blank_proof[0].nResponse,
      0,
    );
    const [pAS, pBS] = formula2(
      pY,
      sumc.pAlpha,
      sumc.pBeta,
      answer.blank_proof[1].nChallenge,
      answer.blank_proof[1].nResponse,
      0,
    );
  
    let S = `${Election.fingerprint(election)}|${credential}|`;
    S += answer.choices.map(Ciphertext.toString).join(",");
    return Hbproof0(S, ...[pA0, pB0, pAS, pBS]) === nSumChallenges;
  }
}
