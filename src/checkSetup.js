import { assert, check } from "./utils.js";
import { g, l, rev, erem } from "./math.js";
import { ed25519 } from "@noble/curves/ed25519";
import sjcl from "sjcl";

export default function (state) {
  // TODO: Handle more than one trustee
  // TODO: Handle pedersen trustees
  check(
    "setup",
    "Election Public Key correspond to trustees",
    state.setup.payload.trustees[0][1].public_key ===
      state.setup.payload.election.public_key,
  );

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
  }

  check(
    "setup",
    "Election Public Key correspond to trustees",
    state.setup.payload.trustees[0][1].public_key ===
      state.setup.payload.election.public_key,
  );
}
