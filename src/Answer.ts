import * as Election from "./election";
import * as Question from "./question";
import * as Ballot from "./ballot";
import * as AnswerH from "./AnswerH";
import * as AnswerL from "./AnswerL";
import * as AnswerNH from "./AnswerNH";
export { AnswerH, AnswerL, AnswerNH };

// -- Types

export type t = AnswerH.t | AnswerNH.t | AnswerL.t;
export namespace Serialized {
  export type t =
    | AnswerH.Serialized.t
    | AnswerNH.Serialized.t
    | AnswerL.Serialized.t;
}

// -- Check

export function check(
  election: Election.t,
  electionFingerprint: string,
  ballot: Ballot.t,
  question: Question.t,
  answer: Serialized.t,
) {
  let check = null;
  if (
    Serialized.IsAnswerH(answer, question) &&
    Question.IsQuestionH(question)
  ) {
    check = AnswerH.check;
  } else if (
    Serialized.IsAnswerNH(answer, question) &&
    Question.IsQuestionNH(question)
  ) {
    check = AnswerNH.check;
  } else if (
    Serialized.IsAnswerL(answer, question) &&
    Question.IsQuestionL(question)
  ) {
    check = AnswerL.check;
  } else {
    throw new Error("Unknown question type");
  }

  check(election, electionFingerprint, ballot, question, answer);
}

// -- Type guards

export function IsAnswerH(
  answer: t,
  question: Question.t,
): answer is AnswerH.t {
  return Question.IsQuestionH(question);
}
export function IsAnswerNH(
  answer: t,
  question: Question.t,
): answer is AnswerNH.t {
  return Question.IsQuestionNH(question);
}
export function IsAnswerL(
  answer: t,
  question: Question.t,
): answer is AnswerL.t {
  return Question.IsQuestionL(question);
}

export namespace Serialized {
  export function IsAnswerH(
    answer: t,
    question: Question.t,
  ): answer is AnswerH.Serialized.t {
    return Question.IsQuestionH(question);
  }
  export function IsAnswerNH(
    answer: t,
    question: Question.t,
  ): answer is AnswerNH.Serialized.t {
    return Question.IsQuestionNH(question);
  }
  export function IsAnswerL(
    answer: t,
    question: Question.t,
  ): answer is AnswerL.Serialized.t {
    return Question.IsQuestionL(question);
  }
}
