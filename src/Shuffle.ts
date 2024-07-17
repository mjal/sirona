import * as Event from "./event";
import * as Ballot from "./ballot";
import * as Point from "./point";
import * as Ciphertext from "./ciphertext";
import * as Question from "./question";
import sjcl from "sjcl";
import { ed25519 } from "@noble/curves/ed25519";
import { q, mod, L, rev } from "./math";

// -- Types

export type shuffle_commitment_rand = [
  Point.t,
  Point.t,
  Point.t,
  [Point.t, Point.t],
  Array<Point.t>,
];

export type shuffle_response = [
  bigint,
  bigint,
  bigint,
  bigint,
  Array<bigint>,
  Array<bigint>,
];

export type shuffle_proof = [
  shuffle_commitment_rand,
  shuffle_response,
  Array<Point.t>,
  Array<Point.t>,
];

export type t = {
  owner: number;
  payload: {
    ciphertexts: Array<Array<Ciphertext.t>>;
    proofs: Array<shuffle_proof>;
  };
};

// -- Parse

export function parse(o: any): t {
  let res: any = {};
  res.owner = o.owner;
  res.payload = {};
  res.payload.ciphertexts = o.payload.ciphertexts.map(
    (c: Array<Ciphertext.Serialized.t>) => c.map(Ciphertext.parse),
  );
  let proofs = o.payload.proofs.map((p: any) => {
    let [t, s, c, c_hat] = o.payload.proofs[0];
    let commitment_rand = [
      Point.parse(t[0]),
      Point.parse(t[1]),
      Point.parse(t[2]),
      [Point.parse(t[3][0]), Point.parse(t[3][1])],
      t[4].map(Point.parse),
    ];
    let response = [
      BigInt(s[0]),
      BigInt(s[1]),
      BigInt(s[2]),
      BigInt(s[3]),
      s[4].map(BigInt),
      s[5].map(BigInt),
    ];
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
  const y = Point.parse(state.setup.payload.election.public_key);
  for (let i = 0; i < state.setup.payload.election.questions.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (Question.IsQuestionNH(question)) {
      const choices: Array<Ciphertext.Serialized.t> =
        state.encryptedTally.payload.encrypted_tally[i];

      CheckShuffleProof(
        y,
        state.electionFingerprint,
        choices,
        shuffle.payload.ciphertexts[i],
        shuffle.payload.proofs[i],
      );

      throw new Error("Unsupported event type (Shuffle)");
    }
  }
  throw new Error("Unsupported event type (Shuffle)");
}

function hasDuplicates(array: any) {
  return new Set(array).size !== array.length;
}

function CheckShuffleProof(
  y: Point.t,
  electionFingerprint: string,
  input: Array<Ciphertext.Serialized.t>,
  output: Array<Ciphertext.t>,
  proof: shuffle_proof,
) {
  const [t, s, cc, cc_hat] = proof;
  const [t1, t2, t3, [t4_1, t4_2], t_hat] = t;
  const [s1, s2, s3, s4, s_hat, s_prime] = s;

  if (
    cc.length !== input.length ||
    cc_hat.length !== input.length ||
    t_hat.length !== input.length ||
    s_hat.length !== input.length ||
    s_prime.length !== input.length
  ) {
    throw new Error("Invalid proof length");
  }

  const h = GetSecondaryGenerator();
  const hh = GetGenerators(input.length);
  if (hasDuplicates(hh.map(Point.serialize).concat([Point.serialize(h)]))) {
    throw new Error("Generators collision");
  }

  //console.log("ee", input.map(Ciphertext.Serialized.toString).join(','));
  //console.log("ee_prime", output.map(Ciphertext.toString).join(','));
  //console.log("c", c.map(Point.serialize).join(','));

  const str_c =
    "" +
    input.map(Ciphertext.Serialized.toString).join(",") +
    "," +
    output.map(Ciphertext.toString).join(",") +
    "," +
    cc.map(Point.serialize).join(",") +
    ",";

  const uu = GetNIZKPChallenges(
    input.length,
    `shuffle-challenges|${electionFingerprint}|${str_c}`,
  );

  const str_t =
    [t1, t2, t3, t4_1, t4_2].concat(t_hat).map(Point.serialize).join(",") + ",";

  const str_y =
    "" +
    str_c +
    cc_hat.map(Point.serialize).join(",") +
    "," +
    Point.serialize(y);

  const c = GetNIZKPChallenge(
    `shuffle-challenge|${electionFingerprint}|${str_t}${str_y}`,
  );

  const c_bar = Point.combine(cc).add(Point.combine(hh).negate());
  console.log("c_bar", Point.serialize(c_bar));

  const u = uu.reduce((acc, ui) => mod(acc * ui, L), 1n);
  console.log("u", u);

  const c0_hat = h;
  const c_hat = cc_hat[cc_hat.length - 1].add(h.multiply(u).negate());
  const c_tilde = Point.combine(cc.map((ci, i) => ci.multiply(uu[i])));

  console.log("c_tilde", Point.serialize(c_hat));

  //console.log(str_c);
}

function getNextPoint(b: bigint): Point.t {
  let h = null;
  while (1) {
    try {
      h = Point.parse(b.toString(16).padStart(64, "0"));
      return h;
    } catch (e) {
      b = b + 1n;
    }
  }
}

function GetGenerator(i: number) {
  const str = `ggen|${i}`;
  const hash = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(str));
  const b = BigInt("0x" + hash) >> BigInt(2);
  const h = getNextPoint(b).multiply(8n);
  return h;
}

function GetSecondaryGenerator(): Point.t {
  return GetGenerator(-1);
}

function GetGenerators(N: number): Array<Point.t> {
  return [...Array(N).keys()].map(GetGenerator);
}

function GetNIZKPChallenge(S: string) {
  const r = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(S));
  return mod(BigInt("0x" + r), L);
}

function GetNIZKPChallenges(N: number, S: string) {
  const H = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(S));
  return [...Array(N).keys()].map((i) => {
    const Hi = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(`${i}`));
    const r = sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(H + Hi));
    return mod(BigInt("0x" + r), L);
  });
}
