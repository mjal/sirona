import * as Point from "./Point";
import * as Ciphertext from "./Ciphertext";
import * as Proof from "./Proof";
import * as SchnorrProof from "./proofs/SchnorrProof";
import * as IndividualProof from "./proofs/IndividualProof";
import * as BlankProof from "./proofs/BlankProof";
import * as Answer from "./Answer";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import * as Election from "./Election";
import * as Setup from "./Setup";
import * as Z from "./Z";
import { range } from "./utils";

export default function (
  setup: Setup.t,
  sPriv: string,
  choices: Array<Array<number>>, // TODO: Rename plaintexts
) {
  const { election } = setup

  const { hPublicCredential } = Credential.derive(
    setup.election.uuid,
    sPriv,
  );

  if (!Credential.checkSeedFormat(sPriv)) {
    throw new Error(
      "Credential format should be be XXXXX-XXXXXX-XXXXX-XXXXXX.",
    );
  }

  if (!Credential.find(setup.credentials, hPublicCredential)) {
    throw "Invalid credential.";
  }

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

  const hash = Ballot.b64hashWithoutSignature(
    ballotWithoutSignature,
    election,
  );

  const proof = SchnorrProof.generate(hash, nPrivateCredential);
  const ballot: Ballot.t = {
    ...ballotWithoutSignature,
    signature: {
      hash: hash,
      proof: Proof.serialize(proof)
    }
  };

  Ballot.verify(setup, ballot);

  return ballot;
}

function checkVotingCode(setup: Setup.t, sPriv: string) {
  if (!Credential.checkFormat(sPriv)) {
    throw new Error(
      "Credential format should be be XXXXX-XXXXXX-XXXXX-XXXXXX.",
    );
  }

  const { hPublicCredential } = Credential.derive(
    setup.election.uuid,
    sPriv,
  );

  if (!Credential.find(setup.credentials, hPublicCredential)) {
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
    const { pAlpha, pBeta } = Ciphertext.encrypt(y, r, plaintexts[i]);

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
