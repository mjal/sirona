import * as Proof from './proof';
import * as Ciphertext from './ciphertext';

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
