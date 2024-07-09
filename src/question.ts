export namespace QuestionH {
  export type t = {
    answers: Array<string>;
    blank?: boolean;
    min: number;
    max: number;
    question: string;
  };
}

export namespace QuestionNH {
  export type t = {
    type: string;
    value: {
      answers: Array<string>;
      question: string;
    };
    extra?: any;
  };
}

export namespace QuestionL {
  export type t = {
    type: string;
    value: {
      answers: Array<Array<string>>;
      question: string;
    };
    extra?: any;
  };
}

export type t = QuestionH.t | QuestionNH.t | QuestionL.t;

export function IsQuestionH(question: any): question is QuestionH.t {
  return question.type === undefined;
}

export function IsQuestionNH(question: any): question is QuestionNH.t {
  return question.type === "NonHomomorphic";
}

export function IsQuestionL(question: any): question is QuestionL.t {
  return question.type === "Lists";
}
