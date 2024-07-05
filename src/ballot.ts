import * as Proof from './proof';
import * as Answer from './Answer';

export type t = {
  election_uuid: string,
  election_hash: string,
  credential: string,
  answers: Array<Answer.Serialized.t>,
  signature: {
    hash: string,
    proof: Proof.Serialized.t
  }
};
