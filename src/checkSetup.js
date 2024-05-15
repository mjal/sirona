import { assert, check } from "./utils.js";
import { g, l, rev, erem, one } from "./math.js";
import { ed25519 } from "@noble/curves/ed25519";
import sjcl from "sjcl";

export default function (state) {
  // TODO: Handle Pedersen trustees

  let joint_public_key = one;

  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    const trustee = state.setup.payload.trustees[i];
    assert(trustee[0] === "Single",
      "Trustee is Single (Pedersen not implemented yet)");
    if (trustee[0] === "Pedersen")
      continue;
    const X = ed25519.ExtendedPoint.fromHex(rev(trustee[1].public_key));
    const challenge = BigInt(trustee[1].pok.challenge);
    const response = BigInt(trustee[1].pok.response);

    const A = g.multiply(response).add(X.multiply(challenge));

    let hashedStr = `pok|${state.setup.payload.election.group}|`;
    hashedStr += `${trustee[1].public_key}|`;
    hashedStr += `${rev(A.toHex())}`;

    const verificationHash = sjcl.codec.hex.fromBits(
      sjcl.hash.sha256.hash(hashedStr),
    );
    const hexReducedVerificationHash = erem(
      BigInt("0x" + verificationHash),
      l,
    ).toString(16);

    check(
      "setup",
      `Trustee ${i} POK is valid`,
      challenge.toString(16) === hexReducedVerificationHash,
    );

    joint_public_key = joint_public_key.add(X);
  }

  console.log(rev(joint_public_key.toHex()));
  console.log(state.setup.payload.election.public_key);

  check(
    "setup",
    "Election Public Key correspond to trustees",
    rev(joint_public_key.toHex()) ===
      state.setup.payload.election.public_key,
  );
}
