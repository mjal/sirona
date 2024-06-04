import sjcl from "sjcl";
import { g, L, rev, mod, isValidPoint, parsePoint, zero } from "./math";

export default function (state) {}

export function checkVotingCode(state, credential) {
  if (!/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(credential)) {
    alert("Invalid credential format");
    return ;
  }

  const prefix = `derive_credential|${state.setup.payload.election.uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${credential}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${credential}`),
  );

  const x = mod(BigInt("0x" + x0 + x1), L);
  const publicCredential = g.multiply(x);
  const hPublicCredential = rev(publicCredential.toHex());
  const electionPublicCredentials =
    state.credentialsWeights.map((c) => c.credential);

  if (electionPublicCredentials.includes(hPublicCredential)) {
    alert("Correct voting code");
  } else {
    alert("Incorrect voting code");
  }
}
