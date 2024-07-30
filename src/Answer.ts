import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as AnswerH from "./AnswerH";
import * as AnswerL from "./AnswerL";
import * as AnswerNH from "./AnswerNH";
export { AnswerH, AnswerL, AnswerNH };

export type t = AnswerH.t | AnswerNH.t | AnswerL.t;

export namespace Serialized {
  export type t =
    | AnswerH.Serialized.t
    | AnswerL.Serialized.t
    | AnswerNH.Serialized.t;
}

export function verify(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.t,
  answer: Serialized.t,
) {
  let verify = null;
  if (
    Serialized.IsAnswerH(answer, question) &&
    Question.IsQuestionH(question)
  ) {
    verify = AnswerH.verify;
  } else if (
    Serialized.IsAnswerNH(answer, question) &&
    Question.IsQuestionNH(question)
  ) {
    verify = AnswerNH.verify;
  } else if (
    Serialized.IsAnswerL(answer, question) &&
    Question.IsQuestionL(question)
  ) {
    verify = AnswerL.verify;
  } else {
    throw new Error("Unknown question type");
  }

  verify(election, ballot, question, answer);
}

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
