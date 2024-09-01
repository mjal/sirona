import { mod, rand } from "./math"

export const q = 2n ** 255n - 19n; // TODO: Remove

export const L = BigInt(
  "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
);

// TODO: Only keep mod
export const modQ = (a: bigint) => {
  return mod(a, q);
};
export const modL = (a: bigint) => {
  return mod(a, L);
};

// TODO: Rename rand
export const randL = () => rand(L);

// TODO: Rename sum
export const sumL = (numbers: bigint[]) => {
  return numbers.reduce((acc: bigint, n: bigint) => {
    return modL(acc + n);
  }, 0n);
};
