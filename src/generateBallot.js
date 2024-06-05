import sjcl from "sjcl";
import { g, L, rev, mod, isValidPoint, parsePoint, zero } from "./math";

export default function (state, credential, choices) {

  if (!checkVotingCode(state, credential)) {
    return false;
  }

  const { nPrivateCredential } = deriveCredential(state, credential);

  const H = "AlZ/yv4k5MY0H9VlAi+zQ1iWRlATlt+FWOEmrBMxnfU"

  // TODO: Use random from math.ts
  const w = BigInt("0x"+ sjcl.codec.hex.fromBits(sjcl.random.randomWords(8)));
  const pA = g.multiply(w);

  const hashSignature = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${H}|${rev(pA.toHex())}`),
  );
  const nChallenge = mod(
    BigInt("0x" + hashSignature),
    L,
  );
  const nResponse = mod(w - nPrivateCredential * nChallenge, L);

  console.log(nPrivateCredential);
  console.log(nChallenge);
  console.log(nResponse);
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


  //w = 5767426717320278105808180679191610987036363809609081470436789699505614842079
  //commitment = 0c55ad407fa71d15d99dd5dd3fcd925626bc4198fa12e4aa15ce310ffe2d710d
  //prefix = w2c7YUcZPGFr49kk4Rjcl9IInG2C9Wasc5XJQVTN/7M
  //challenge = 1453655888106430541245856700560483286523540041418339004856777176507583806003
  //response = 6788297434139194963839331309087347281187156414064677162784244285442555274408
