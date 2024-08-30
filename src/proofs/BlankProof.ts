import * as Question from "../Question";
import * as AnswerH from "../AnswerH";
import * as Election from "../Election";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import * as Z from "../Z";
import { Hbproof0, Hbproof1 } from "../math";

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
