import * as Point from './point';

export type t = {
  pCommitment: Point.t;
  nChallenge: bigint;
  nResponse: [bigint, bigint];
}

export namespace Serialized {
  export type t = {
    commitment: string;
    challenge: string;
    response: [string, string];
  }
}
