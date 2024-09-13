import * as Proof from "./Proof";
import * as SchnorrProof from "./proofs/SchnorrProof";
import * as Ballot from "./Ballot";
import * as Credential from "./Credential";
import * as Election from "./Election";
import * as Setup from "./Setup";
import * as Question from "./Question";
import * as AnswerH from "./AnswerH";

export default function (
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
      return AnswerH.generate(election, question, sPriv, plaintexts[i]);
    } else if (Question.IsQuestionL(question)) {
      throw new Error("Unsupported question type");
    } else if (Question.IsQuestionNH(question)) {
      throw new Error("Unsupported question type");
    } else {
      throw new Error("Unknown question type");
    }
  });

  let ballot: Ballot.t = {
    answers,
    credential: hPublicCredential,
    election_hash: Election.fingerprint(election),
    election_uuid: setup.election.uuid,
    signature: null,
  };

  const hash = Ballot.b64hashWithoutSignature(ballot, election);
  const proof = SchnorrProof.generate(hash, nPrivateCredential);
  ballot.signature = {
    hash: hash,
    proof: Proof.serialize(proof),
  };

  Ballot.verify(setup, ballot);

  return ballot;
}
