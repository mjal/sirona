import sjcl from "sjcl";

export const q = 2n ** 255n - 19n;
export const L = BigInt(
  "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
);

export const mod = (a: bigint, b: bigint) => {
  let remainder = a % b;
  if (remainder < 0) {
    remainder += b;
  }
  return remainder;
};
export const modQ = (a: bigint) => {
  return mod(a, q);
};
export const modL = (a: bigint) => {
  return mod(a, L);
};

function egcd(a: bigint, b: bigint): [bigint, bigint, bigint] {
  if (b === 0n) {
    return [a, 1n, 0n];
  }
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

export function modInverse(a: bigint, m: bigint): bigint {
  const [g, x, _] = egcd(a, m);
  if (g !== 1n) {
    throw new Error(`${a} n'a pas d'inverse modulaire sous ${m}`);
  }
  return ((x % m) + m) % m;
}

export function rand(max: bigint): bigint {
  const bitArray = sjcl.random.randomWords(8);
  const hNumber = sjcl.codec.hex.fromBits(bitArray);
  return mod(BigInt("0x" + hNumber), max);
}
export const randL = () => rand(L);

export const sumL = (numbers: bigint[]) => {
  return numbers.reduce((acc: bigint, n: bigint) => {
    return modL(acc + n);
  }, 0n);
};
