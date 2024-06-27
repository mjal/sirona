import { map2, map3 } from './utils';
import * as Proof from './proof';
import * as NonZeroProof from './nonZeroProof';
import * as Ciphertext from './ciphertext';
import * as Question from './question';

export namespace AnswerH {
  export type t = {
    aeChoices: Array<Ciphertext.t>;
    aazIndividualProofs: Array<Array<Proof.t>>;
    azOverallProof: Array<Proof.t>;
    azBlankProof?: Array<Proof.t>;
  }

  export namespace Serialized {
    export type t = {
      choices: Array<Ciphertext.Serialized.t>;
      individual_proofs: Array<Array<Proof.Serialized.t>>;
      overall_proof: Array<Proof.Serialized.t>;
      blank_proof?: Array<Proof.Serialized.t>;
    };
  }

  export function parse(answer: Serialized.t) : t {
    let obj : t = {
      aeChoices: answer.choices.map(Ciphertext.parse),
      aazIndividualProofs: map2(answer.individual_proofs, Proof.parse),
      azOverallProof: answer.overall_proof.map(Proof.parse),
    };
    if (answer.blank_proof) {
      obj.azBlankProof = answer.blank_proof.map(Proof.parse);
    }
    return obj;
  }

  export function serialize(answer: t) : Serialized.t {
    let obj : Serialized.t = {
      choices: answer.aeChoices.map(Ciphertext.serialize),
      individual_proofs: map2(answer.aazIndividualProofs, Proof.serialize),
      overall_proof: answer.azOverallProof.map(Proof.serialize),
    };
    if (answer.azBlankProof) {
      obj.blank_proof = answer.azBlankProof.map(Proof.serialize);
    }
    return obj;
  }
}

export namespace AnswerNH {
  export type t = {
    choices: Ciphertext.t;
    proof: Proof.t;
  };

  export namespace Serialized {
    export type t = {
      choices: Ciphertext.Serialized.t;
      proof: Proof.Serialized.t;
    };
  }
}

export namespace AnswerL {
  export type t = {
    choices: Array<Array<Ciphertext.t>>;
    individual_proofs: Array<Array<Proof.t>>;
    overall_proof: Proof.t;
    list_proofs: Array<Proof.t>;
    nonzero_proof: NonZeroProof.t;
  };

  export namespace Serialized {
    export type t = {
      choices: Array<Array<Ciphertext.Serialized.t>>;
      individual_proofs: Array<Array<Array<Proof.Serialized.t>>>;
      overall_proof: Proof.Serialized.t;
      list_proofs: Array<Array<Proof.Serialized.t>>;
      nonzero_proof: NonZeroProof.Serialized.t;
    };
  }

  export function parse(answer: Serialized.t) : t {
    return {
      choices: map2(answer.choices, Ciphertext.parse),
      individual_proofs: map3(answer.individual_proofs, Proof.parse),
      overall_proof: Proof.parse(answer.overall_proof),
      list_proofs: map2(answer.list_proofs, Proof.parse),
      nonzero_proof: NonZeroProof.parse(answer.nonzero_proof)
    }
  }
}


export type t = AnswerH.t | AnswerNH.t | AnswerL.t;

export namespace Serialized {
  export type t = AnswerH.Serialized.t | AnswerNH.Serialized.t | AnswerL.Serialized.t;

  export function IsAnswerH(answer: any, question: any) : answer is AnswerH.Serialized.t {
    return Question.IsQuestionH(question);
  }
  
  export function IsAnswerNH(answer: any, question: any) : answer is AnswerNH.Serialized.t {
    return Question.IsQuestionNH(question);
  }
  
  export function IsAnswerL(answer: any, question: any) : answer is AnswerL.Serialized.t {
    return Question.IsQuestionL(question);
  }
}
