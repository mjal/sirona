import { mod as _mod, rand as _rand } from "./math";

export const L = BigInt(
  "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
);

export const mod = (a: bigint) => {
  return _mod(a, L);
};

export const rand = () => _rand(L);

export const sum = (numbers: bigint[]) => {
  return numbers.reduce((acc: bigint, n: bigint) => {
    return mod(acc + n);
  }, 0n);
};
