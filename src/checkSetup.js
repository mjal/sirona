import { assert, check } from "./utils.js";
import { g, L, rev, mod, one, isValidPoint, parsePoint } from "./math";
import sjcl from "sjcl";

export default function (state) {
  // TODO: Handle Pedersen trustees

  let pJointPublicKey = one;

  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    const trustee = state.setup.payload.trustees[i];
    assert(
      trustee[0] === "Single",
      "Trustee is Single (Pedersen not implemented yet)",
    );
    if (trustee[0] === "Pedersen") continue;
    const pX = parsePoint(trustee[1].public_key);

    check(
      "setup",
      `Trustee ${i} public key is a valid curve point`,
      isValidPoint(pX),
    );

    const nChallenge = BigInt(trustee[1].pok.challenge);
    const nResponse = BigInt(trustee[1].pok.response);

    const pA = g.multiply(nResponse).add(pX.multiply(nChallenge));

    let hashedStr = `pok|${state.setup.payload.election.group}|`;
    hashedStr += `${trustee[1].public_key}|`;
    hashedStr += `${rev(pA.toHex())}`;

    const verificationHash = sjcl.codec.hex.fromBits(
      sjcl.hash.sha256.hash(hashedStr),
    );
    const hexReducedVerificationHash = mod(
      BigInt("0x" + verificationHash),
      L,
    ).toString(16);

    check(
      "setup",
      `Trustee ${i} POK is valid`,
      nChallenge.toString(16) === hexReducedVerificationHash,
    );

    pJointPublicKey = pJointPublicKey.add(pX);
  }

  check(
    "setup",
    "Election Public Key correspond to trustees",
    rev(pJointPublicKey.toHex()) === state.setup.payload.election.public_key,
  );

  const pElectionPublicKey = parsePoint(state.setup.payload.election.public_key);
  check(
    "setup",
    `Election Public Key is a valid curve point`,
    pElectionPublicKey,
  );
}
