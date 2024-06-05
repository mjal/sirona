import sjcl from "sjcl";
import { g, L, rev, mod, rand } from "./math";

export default function (state, credential, choices) {

  if (!checkVotingCode(state, credential)) {
    return false;
  }

  const { nPrivateCredential } = deriveCredential(state, credential);

  const H = "AlZ/yv4k5MY0H9VlAi+zQ1iWRlATlt+FWOEmrBMxnfU"
  console.log(signature(nPrivateCredential, H));
}

export function signature(nPrivateCredential, hash) {
  const w = rand();
  const pA = g.multiply(w);

  const hashSignature = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${hash}|${rev(pA.toHex())}`),
  );
  const nChallenge = mod(
    BigInt("0x" + hashSignature),
    L,
  );
  const nResponse = mod(w - nPrivateCredential * nChallenge, L);

  return {
    hash: hash,
    proof: {
      challenge: nChallenge.toString(),
      response: nResponse.toString()
    }
  };
}

export function deriveCredential(state, credential) {
  const prefix = `derive_credential|${state.setup.payload.election.uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${credential}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${credential}`),
  );

  const nPrivateCredential = mod(BigInt("0x" + x0 + x1), L);
  const pPublicCredential = g.multiply(nPrivateCredential);
  const hPublicCredential = rev(pPublicCredential.toHex());

  return {
    nPrivateCredential,
    hPublicCredential
  };
}

export function checkVotingCode(state, credential) {
  if (!/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(credential)) {
    alert("Invalid credential format");
    return false;
  }

  const { hPublicCredential } = deriveCredential(state, credential);

  const electionPublicCredentials =
    state.credentialsWeights.map((c) => c.credential);

  if (electionPublicCredentials.includes(hPublicCredential)) {
    return true;
  } else {
    alert("Incorrect voting code");
    return false;
  }
}
