import * as Question from './question';
import * as AnswerH  from './AnswerH';
import * as AnswerL  from './AnswerL';
import * as AnswerNH from './AnswerNH';

export type t = AnswerH.t | AnswerNH.t | AnswerL.t;

export { AnswerH, AnswerL, AnswerNH };

export function IsAnswerH(answer: t, question: Question.t) : answer is AnswerH.t {
  return Question.IsQuestionH(question);
}

export function IsAnswerNH(answer: t, question: Question.t) : answer is AnswerNH.t {
  return Question.IsQuestionNH(question);
}

export function IsAnswerL(answer: t, question: Question.t) : answer is AnswerL.t {
  return Question.IsQuestionL(question);
}

export namespace Serialized {
  export type t = AnswerH.Serialized.t | AnswerNH.Serialized.t | AnswerL.Serialized.t;

  export function IsAnswerH(answer: t, question: Question.t) : answer is AnswerH.Serialized.t {
    return Question.IsQuestionH(question);
  }

  export function IsAnswerNH(answer: t, question: Question.t) : answer is AnswerNH.Serialized.t {
    return Question.IsQuestionNH(question);
  }

  export function IsAnswerL(answer: t, question: Question.t) : answer is AnswerL.Serialized.t {
    return Question.IsQuestionL(question);
  }
}
