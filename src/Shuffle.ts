import * as Event from "./event";
import * as Point from "./point";
import * as Ciphertext from "./ciphertext";
import * as Question from "./question";

// -- Types

export type shuffle_commitment_rand = [
  Point.t,
  Point.t,
  Point.t,
  [Point.t, Point.t],
  Array<Point.t>
];

export type shuffle_response = [
  bigint,
  bigint,
  bigint,
  bigint,
  Array<bigint>,
  Array<bigint>
];

export type shuffle_commitment_perm = Array<Point.t>;

export type shuffle_chained_challenges = Array<Point.t>;

export type shuffle_proof = [
  shuffle_commitment_rand,
  shuffle_response,
  shuffle_commitment_perm,
  shuffle_chained_challenges
];

export type t = {
  owner: number;
  payload: {
    ciphertexts: Array<Array<Ciphertext.t>>;
    proofs: Array<shuffle_proof>;
  }
};

// -- Parse

export function parse(o: any): t {
  let res : any = {};
  res.owner = o.owner;
  res.payload = {};
  res.payload.ciphertexts = o.payload.ciphertexts
    .map((c: Array<Ciphertext.Serialized.t>) => c.map(Ciphertext.parse));
  let proofs = o.payload.proofs.map((p: any) => {
    let [t, s, c, c_hat] = o.payload.proofs[0];
    let commitment_rand = [
      Point.parse(t[0]),
      Point.parse(t[1]),
      Point.parse(t[2]),
      [Point.parse(t[3][0]), Point.parse(t[3][1])],
      t[4].map(Point.parse)
    ]
    let response = [
      BigInt(s[0]),
      BigInt(s[1]),
      BigInt(s[2]),
      BigInt(s[3]),
      s[4].map(BigInt),
      s[5].map(BigInt)
    ]
    let commitment_perm = c.map(Point.parse);
    let chained_challenges = c_hat.map(Point.parse);
    return [commitment_rand, response, commitment_perm, chained_challenges];
  });
  res.payload.proofs = proofs;
  return res;
}

// -- Check

export function check(state: any, ballotEvent: Event.t<t>) {
  const shuffle = parse(ballotEvent.payload);
  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (Question.IsQuestionNH(question)) {
      CheckShuffleProof(shuffle.payload.proofs[i]);
      throw new Error("Unsupported event type (Shuffle)");
    }
  }
  throw new Error("Unsupported event type (Shuffle)");
}

function CheckShuffleProof(proof: shuffle_proof) {
  const [t, s, c, c_hat] = proof;
  const [t1, t2, t3, [t4_1, t4_2], t_hat] = t;
  const [s1, s2, s3, s4, s_hat, s_prime] = s
}
