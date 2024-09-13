import sjcl from "sjcl";
import * as Credential from "./Credential";
import * as Proof from "./Proof";
import * as SchnorrProof from "./proofs/SchnorrProof";
import * as Point from "./Point";
import * as Answer from "./Answer";
import * as Election from "./Election";
import * as Setup from "./Setup";
import * as Question from "./Question";

export type t = {
  election_uuid: string;
  election_hash: string;
  credential: string;
  answers: Array<Answer.serialized_t>;
  signature: {
    hash: string;
    proof: Proof.serialized_t;
  };
};

export function toJSON(ballot: t, election: Election.t): t {
  // JSON.stringify key order will be the order of insertion
  return {
    election_uuid: ballot.election_uuid,
    election_hash: ballot.election_hash,
    credential: ballot.credential,
    answers: election.questions.map((question, i) => {
      const answer = ballot.answers[i];
      return Answer.serialize(Answer.parse(answer, question), question);
    }),
    signature: ballot.signature
      ? {
          hash: ballot.signature.hash,
          proof: Proof.serialize(Proof.parse(ballot.signature.proof)),
        }
      : null,
  };
}

export function verify(setup: Setup.t, ballot: t) {
  const { election, credentials } = setup;

  if (election.uuid !== ballot.election_uuid) {
    throw new Error("election_uuid is incorrect");
  }

  if (Election.fingerprint(election) !== ballot.election_hash) {
    throw new Error("election_hash is incorrect");
  }

  if (!Credential.find(credentials, ballot.credential)) {
    throw new Error("Credential not found");
  }

  const recomputedHash = b64hashWithoutSignature(ballot, election);
  if (ballot.signature.hash !== recomputedHash) {
    throw new Error("Ballot recomputed hash is incorrect");
  }

  const public_key = Point.parse(ballot.credential);
  const proof = Proof.parse(ballot.signature.proof);
  if (!SchnorrProof.verify(ballot.signature.hash, public_key, proof)) {
    throw new Error("Invalid signature");
  }

  for (let i = 0; i < election.questions.length; i++) {
    Answer.verify(election, ballot, election.questions[i], ballot.answers[i]);
  }
}

export function generate(
  setup: Setup.t,
  sPriv: string,
  plaintexts: number[][],
) {
  const { election } = setup;

  const { hPublicCredential, nPrivateCredential } = Credential.derive(
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

  const answers = election.questions.map((question, i) => {
    if (Question.IsQuestionH(question)) {
      return Answer.AnswerH.generate(election, question, sPriv, plaintexts[i]);
    } else if (Question.IsQuestionL(question)) {
      throw new Error("Unsupported question type");
    } else if (Question.IsQuestionNH(question)) {
      throw new Error("Unsupported question type");
    } else {
      throw new Error("Unknown question type");
    }
  });

  let ballot: t = {
    answers,
    credential: hPublicCredential,
    election_hash: Election.fingerprint(election),
    election_uuid: setup.election.uuid,
    signature: null,
  };

  const hash = b64hashWithoutSignature(ballot, election);
  const proof = SchnorrProof.generate(hash, nPrivateCredential);
  ballot.signature = {
    hash: hash,
    proof: Proof.serialize(proof),
  };

  // TODO: Remove ?
  verify(setup, ballot);

  return ballot;
}

export function hash(ballot: t) {
  return sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(JSON.stringify(ballot)));
}

export function b64hash(ballot: t) {
  return sjcl.codec.base64
    .fromBits(sjcl.hash.sha256.hash(JSON.stringify(ballot)))
    .replace(/=+$/, "");
}

export function b64hashWithoutSignature(ballot: t, election: Election.t) {
  const copy = Object.assign({}, toJSON(ballot, election));
  delete copy.signature;
  return b64hash(copy);
}
