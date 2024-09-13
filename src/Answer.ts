import * as Election from "./Election";
import * as Question from "./Question";
import * as Ballot from "./Ballot";
import * as AnswerH from "./AnswerH";
import * as AnswerL from "./AnswerL";
import * as AnswerNH from "./AnswerNH";
export { AnswerH, AnswerL, AnswerNH };

export type t = AnswerH.t | AnswerNH.t | AnswerL.t;

export type serialized_t =
  | AnswerH.serialized_t
  | AnswerL.serialized_t
  | AnswerNH.serialized_t;

export function serialize(answer: t, question: Question.t): serialized_t {
  if (Question.IsQuestionH(question)) {
    return AnswerH.serialize(answer as AnswerH.t);
  } else if (Question.IsQuestionNH(question)) {
    return AnswerNH.serialize(answer as AnswerNH.t);
  } else if (Question.IsQuestionL(question)) {
    return AnswerL.serialize(answer as AnswerL.t);
  } else {
    throw new Error("Unknown answer type");
  }
}

export function parse(answer: serialized_t, question: Question.t): t {
  if (Question.IsQuestionH(question)) {
    return AnswerH.parse(answer as AnswerH.serialized_t);
  } else if (Question.IsQuestionNH(question)) {
    return AnswerNH.parse(answer as AnswerNH.serialized_t);
  } else if (Question.IsQuestionL(question)) {
    return AnswerL.parse(answer as AnswerL.serialized_t);
  } else {
    throw new Error("Unknown answer type");
  }
}

export function verify(
  election: Election.t,
  ballot: Ballot.t,
  question: Question.t,
  answer: serialized_t,
): boolean {
  if (IsH(answer, question) && Question.IsQuestionH(question)) {
    return AnswerH.verify(election, ballot, question, answer);
  } else if (IsNH(answer, question) && Question.IsQuestionNH(question)) {
    return AnswerNH.verify(election, ballot, question, answer);
  } else if (IsL(answer, question) && Question.IsQuestionL(question)) {
    return AnswerL.verify(election, ballot, question, answer);
  } else {
    throw new Error("Unknown question type");
  }
}

export function IsH(
  answer: serialized_t,
  question: Question.t,
): answer is AnswerH.serialized_t {
  return Question.IsQuestionH(question);
}
export function IsNH(
  answer: serialized_t,
  question: Question.t,
): answer is AnswerNH.serialized_t {
  return Question.IsQuestionNH(question);
}
export function IsL(
  answer: serialized_t,
  question: Question.t,
): answer is AnswerL.serialized_t {
  return Question.IsQuestionL(question);
}
