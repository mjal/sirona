import sjcl from "sjcl";
import * as Point from "./Point";
import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as BlankProof from "./proofs/BlankProof";
import * as Answer from "./Answer";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import * as Election from "./Election";
import * as Setup from "./Setup";
import * as Z from "./Z";
import { range } from "./utils";

// TODO: Move to SignatureProof ?
function signature(nPriv: bigint, sHash: string) {
  const w = Z.randL();
  const A = Point.g.multiply(w);

  // TODO: Refactor using Hsignature ?
  // TODO: nChallenge = Hsignature(hash, pA);
  const hashSignature = sjcl.codec.hex.fromBits(
    sjcl.hash.sha256.hash(`sig|${sHash}|${Point.serialize(A)}`),
  );
  const nChallenge = Z.modL(BigInt("0x" + hashSignature));
  const nResponse = Z.mod(w - nPriv * nChallenge, Z.L);

  return {
    hash: sHash,
    proof: Proof.serialize({ nChallenge, nResponse }),
  };
}

export default function (
  setup: Setup.t,
  sPriv: string,
  choices: Array<Array<number>>,
) {
  const { election } = setup
  if (!checkVotingCode(setup, sPriv)) {
    return null;
  }

  const { hPublicCredential, nPrivateCredential } = Credential.derive(
    election.uuid,
    sPriv,
  );

  let answers: Array<Answer.AnswerH.Serialized.t> = [];
  for (let i = 0; i < choices.length; i++) {
    const question = election.questions[i];
    const answer = generateAnswer(election, question, sPriv, choices[i]);
    answers.push(answer);
  }

  const ballotWithoutSignature = {
    answers,
    credential: hPublicCredential,
    election_hash: Election.fingerprint(election),
    election_uuid: setup.election.uuid,
    signature: {
      hash: null,
      proof: {
        challenge: null,
        response: null,
      },
    },
  };

  const hH = Ballot.b64hashWithoutSignature(
    ballotWithoutSignature,
    election,
  );

  const ballot: Ballot.t = {
    ...ballotWithoutSignature,
    signature: signature(nPrivateCredential, hH),
  };

  Ballot.verify(setup, ballot);

  return ballot;
}

function checkVotingCode(setup: Setup.t, sPriv: string) {
  if (
    !/[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}-[a-zA-Z0-9]{5}-[a-zA-Z0-9]{6}/.test(sPriv)
  ) {
    throw new Error(
      "Invalid credential format. Should be XXXXX-XXXXXX-XXXXX-XXXXXX.",
    );
  }

  const { hPublicCredential } = Credential.derive(
    setup.election.uuid,
    sPriv,
  );

  const electionPublicCredentials = setup.credentials.map(
    (line: string) => line.split(",")[0],
  );

  if (!electionPublicCredentials.includes(hPublicCredential)) {
    throw "Invalid credential.";
  }

  return true;
}

function generateAnswer(
  election: Election.t,
  question: any,
  sPriv: string,
  plaintexts: Array<number>
): Answer.AnswerH.Serialized.t {
  let nonces: Array<bigint> = [];
  let ciphertexts: Array<Ciphertext.t> = [];
  let individual_proofs: Array<Array<Proof.t>> = [];
  const y = Point.parse(election.public_key);
  const { hPublicCredential } = Credential.derive(
    election.uuid,
    sPriv,
  );

  for (let i = 0; i < plaintexts.length; i++) {
    const r = Z.randL();
    // TODO: Ciphertext.encrypt(y, nonce, plaintext)
    const gPowerM = plaintexts[i] === 0 ? Point.zero : Point.g.multiply(BigInt(plaintexts[i]));
    const pAlpha = Point.g.multiply(r);
    const pBeta = y.multiply(r).add(gPowerM);

    const proof = IndividualProof.generate(election, hPublicCredential, { pAlpha, pBeta }, r, plaintexts[i], [0, 1]);

    ciphertexts.push({ pAlpha, pBeta });
    individual_proofs.push(proof);
    nonces.push(r);
  }

  if (question.blank) {
    const egS = Ciphertext.combine(ciphertexts.slice(1))
    const eg0 = ciphertexts[0];
    const nRS = Z.sumL(nonces.slice(1));
    const nR0 = nonces[0];

    const isBlank = (plaintexts[0] === 1);

    let overall_proof = BlankProof.OverallProof.generate(
      election,
      hPublicCredential,
      question,
      plaintexts,
      ciphertexts,
      nonces,
    );
    const blank_proof = BlankProof.BlankProof.generate(
      election,
      hPublicCredential,
      ciphertexts,
      isBlank ? eg0 : egS,
      isBlank ? nRS : nR0,
      isBlank,
    );
    return Answer.AnswerH.serialize({
      choices: ciphertexts,
      individual_proofs,
      overall_proof,
      blank_proof,
    });
  } else {
    const egS = Ciphertext.combine(ciphertexts);
    const m = plaintexts.reduce((acc, c) => c + acc, 0);
    const M = range(question.min, question.max);
    const nR = Z.sumL(nonces);

    let prefix = hPublicCredential + "|" + ciphertexts.map(Ciphertext.toString).join(",")
    const overall_proof = IndividualProof.generate(election, prefix, egS, nR, m, M);

    return Answer.AnswerH.serialize({
      choices: ciphertexts,
      individual_proofs,
      overall_proof,
    });
  }
}
