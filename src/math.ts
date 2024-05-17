import { ed25519 } from "@noble/curves/ed25519";

export const g = ed25519.ExtendedPoint.BASE;
export const one = ed25519.ExtendedPoint.fromHex(
  "0100000000000000000000000000000000000000000000000000000000000000",
);

export const q = 2n ** 255n - 19n;
export const L = BigInt(
  "0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed",
);

export const rev = (hexStr: string) : string => {
  const match = hexStr.match(/.{1,2}/g)
  if (match !== null) {
    return match.reverse().join("");
  } else {
    return "";
  }
};

export const mod = (a : bigint, b : bigint) => {
  let remainder = a % b;
  if (remainder < 0) {
    remainder += b;
  }
  return remainder;
};

export const isValidPoint = (point) => {
  try {
    point.assertValidity();
  } catch (e) {
    return false;
  }
  return true;
};

export const parsePoint = (str: string) => {
  return ed25519.ExtendedPoint.fromHex(rev(str));
};
