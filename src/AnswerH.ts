import { map2 } from './utils';
import * as Proof from './proof';
import * as Ciphertext from './ciphertext';

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
