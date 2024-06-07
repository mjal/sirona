import sjcl from "sjcl";
import { g, L, rev, mod, rand, formula2, parsePoint, Hiprove, zero } from "./math";
import { hashWithoutSignature } from "./checkBallot";
import { canonicalSerialization } from "./serializeBallot";

export default function (state, sPriv, choices) {

  if (!checkVotingCode(state, sPriv)) {
    return false;
  }

  const {
    hPublicCredential,
    nPrivateCredential
  } = deriveCredential(state, sPriv);

  let answers = [];
  for (let i = 0; i < choices.length; i++) {
    const question = state.setup.payload.election.questions[i];
    answers.push(generateAnswer(state, question, sPriv, choices[i]));
  }

  const ballotWithoutSignature = {
    answers,
    credential: hPublicCredential,
    election_hash: state.setup.fingerprint,
    election_uuid: state.setup.payload.election.uuid,
  };

  const hH = hashWithoutSignature(ballotWithoutSignature);

  const ballot = {
    ...ballotWithoutSignature,
    signature: signature(nPrivateCredential, hH),
  };

  console.log("Ballot");
  console.log(ballot);
  console.log(canonicalSerialization(ballot));
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

function iproof(prefix, pY, pAlpha, pBeta, r, m, M) {
  const w = rand();
  let commitments = [];
  let proofs = [];

  for (let i = 0; i < M.length; i++) {
    if (m !== M[i]) {
      const nChallenge = rand();
      const nResponse  = rand();
      proofs.push({ nChallenge, nResponse });
      const [pA, pB] = formula2(pY, pAlpha, pBeta, nChallenge, nResponse, M[i]);
      commitments.push(pA, pB);
    } else { // m === M[i]
      proofs.push({ nChallenge: BigInt(0), nResponse: BigInt(0) });
      const pA = g.multiply(w);
      const pB = pY.multiply(w);
      commitments.push(pA, pB);
    }
  }

  const nH = Hiprove(prefix, pAlpha, pBeta, ...commitments);

  const nSumChallenge = proofs.reduce((acc, proof) => {
    return mod(acc + proof.nChallenge, L);
  }, BigInt(0));

  for (let i = 0; i < M.length; i++) {
    if (m === M[i]) {
      proofs[i].nChallenge = mod(nH - nSumChallenge, L);
      proofs[i].nResponse = mod(w - r * proofs[i].nChallenge, L);
    }
  }

  return proofs.map((proof) => {
    return {
      challenge: proof.nChallenge.toString(),
      response: proof.nResponse.toString(),
    };
  });
}

function generateAnswer(state, question, nPrivateCredential, choices) {
  const pY = parsePoint(state.setup.payload.election.public_key);
  const { hPublicCredential } = deriveCredential(state, nPrivateCredential);

  let anR = [];
  let aCiphertexts = [];
  let aIndividualProofs = [];

  for (let i = 0; i < choices.length; i++) {
    const nR = rand();
    const gPowerM = (choices[i] === 0)
      ? zero
      : g.multiply(BigInt(choices[i]));
    const pAlpha = g.multiply(nR);
    const pBeta = pY.multiply(nR).add(gPowerM);

    const S = `${state.setup.fingerprint}|${hPublicCredential}`;
    const proof = iproof(S, pY, pAlpha, pBeta, nR, choices[i], [0, 1]);

    aCiphertexts.push({ pAlpha, pBeta, });
    aIndividualProofs.push(proof);
    anR.push(nR);
  }

  const pSumAlpha = aCiphertexts.reduce((acc, c) => acc.add(c.pAlpha), zero);
  const pSumBeta = aCiphertexts.reduce((acc, c) => acc.add(c.pBeta), zero);
  const m = choices.reduce((acc, c) => c + acc, 0);
  const M = Array.from({ length: question.max - question.min + 1 })
    .map((_, i) => i + question.min);
  const nR = anR.reduce((acc, r) => mod(acc + r, L), BigInt(0));

  let S = `${state.setup.fingerprint}|${hPublicCredential}|`;
  S += aCiphertexts.map((c) => `${rev(c.pAlpha.toHex())},${rev(c.pBeta.toHex())}`).join(",");
  const overallProof = iproof(S, pY, pSumAlpha, pSumBeta, nR, m, M);

  return {
    choices: aCiphertexts.map((c) => {
      return {
        alpha: rev(c.pAlpha.toHex()),
        beta: rev(c.pBeta.toHex()),
      };
    }),
    individual_proofs: aIndividualProofs,
    overall_proof: overallProof,
  };
}

function signature(nPrivateCredential, hash) {
  const w = rand();
  const pA = g.multiply(w);

  // TODO: Refactor using Hsignature
  // TODO: nChallenge = Hsignature(hash, pA);
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

function deriveCredential(state, sPriv) {
  const prefix = `derive_credential|${state.setup.payload.election.uuid}`;

  const x0 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|0|${sPriv}`),
  );

  const x1 = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`${prefix}|1|${sPriv}`),
  );

  const nPrivateCredential = mod(BigInt("0x" + x0 + x1), L);
  const pPublicCredential = g.multiply(nPrivateCredential);
  const hPublicCredential = rev(pPublicCredential.toHex());

  return {
    nPrivateCredential,
    hPublicCredential
  };
}

