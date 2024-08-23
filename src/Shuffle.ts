import * as Point from "./Point";
import * as Question from "./Question";
import * as Election from "./Election";
import * as Ciphertext from "./Ciphertext";
import sjcl from "sjcl";
import { g, mod, L } from "./math";

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

// -- Verify

export function verify(
  state: any,
  shuffle: t,
  tally: Array<Array<Ciphertext.t>>,
): boolean {
  const election = state.setup.election;
  const y = Point.parse(election.public_key);
  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    if (Question.IsQuestionNH(question)) {
      if (
        !CheckShuffleProof(
          election,
          tally[i],
          shuffle.payload.ciphertexts[i],
          shuffle.payload.proofs[i],
        )
      ) {
        throw new Error("Invalid shuffle proof");
      }
    }
  }
  return true;
}

function hasDuplicates(array: any) {
  return new Set(array).size !== array.length;
}

function CheckShuffleProof(
  election: Election.t,
  input: Array<Ciphertext.t>,
  output: Array<Ciphertext.t>,
  proof: shuffle_proof,
) {
  const y = Point.parse(election.public_key);
  const [t, s, cc, cc_hat] = proof;
  const [t1, t2, t3, [t41, t42], t_hat] = t;
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

  const str_c =
    "" +
    input.map(Ciphertext.toString).join(",") +
    "," +
    output.map(Ciphertext.toString).join(",") +
    "," +
    cc.map(Point.serialize).join(",") +
    ",";

  const uu = GetNIZKPChallenges(
    input.length,
    `shuffle-challenges|${Election.fingerprint(election)}|${str_c}`,
  );

  const str_t =
    [t1, t2, t3, t41, t42].concat(t_hat).map(Point.serialize).join(",") + ",";

  const str_y =
    "" +
    str_c +
    cc_hat.map(Point.serialize).join(",") +
    "," +
    Point.serialize(y);

  const c = GetNIZKPChallenge(
    `shuffle-challenge|${Election.fingerprint(election)}|${str_t}${str_y}`,
  );

  const c_bar = Point.combine(cc).add(Point.combine(hh).negate());
  const u = uu.reduce((acc, ui) => mod(acc * ui, L), 1n);
  const c_hat = cc_hat[cc_hat.length - 1].add(h.multiply(u).negate());
  const c_tilde = Point.combine(cc.map((ci, i) => ci.multiply(uu[i])));

  const alpha_prime = Point.combine(
    input.map((ei, i) => ei.pAlpha.multiply(uu[i])),
  );
  const beta_prime = Point.combine(
    input.map((ei, i) => ei.pBeta.multiply(uu[i])),
  );

  const t1_prime = c_bar.multiply(c).negate().add(g.multiply(s1));
  const t2_prime = c_hat.multiply(c).negate().add(g.multiply(s2));
  const t3_prime = c_tilde
    .multiply(c)
    .negate()
    .add(g.multiply(s3))
    .add(Point.combine(hh.map((hi, i) => hi.multiply(s_prime[i]))));

  const t41_prime = beta_prime
    .multiply(c)
    .negate()
    .add(y.multiply(s4).negate())
    .add(Point.combine(output.map((ei, i) => ei.pBeta.multiply(s_prime[i]))));

  const t42_prime = alpha_prime
    .multiply(c)
    .negate()
    .add(g.multiply(s4).negate())
    .add(Point.combine(output.map((ei, i) => ei.pAlpha.multiply(s_prime[i]))));

  const tt_prime_hat = [...Array(input.length).keys()].map((i) => {
    return cc_hat[i]
      .multiply(c)
      .negate()
      .add(g.multiply(s_hat[i]))
      .add((i == 0 ? h : cc_hat[i - 1]).multiply(s_prime[i]));
  });

  if (
    !(
      Point.isEqual(t1, t1_prime) &&
      Point.isEqual(t2, t2_prime) &&
      Point.isEqual(t3, t3_prime) &&
      Point.isEqual(t41, t41_prime) &&
      Point.isEqual(t42, t42_prime) &&
      t_hat.map(Point.serialize).join(",") ==
        tt_prime_hat.map(Point.serialize).join(",")
    )
  ) {
    throw new Error("Invalid shuffle proof");
  }

  return true;
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
