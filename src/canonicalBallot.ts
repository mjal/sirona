import { map2, map3 } from "./utils";
import * as Proof from "./Proof";
import * as ProofNonZero from "./ProofNonZero";
import * as Ciphertext from "./Ciphertext";
import * as Answer from "./Answer";
import * as Election from "./Election";
import * as Ballot from "./Ballot";

function canonicalCiphertext(
  ciphertext: Ciphertext.Serialized.t,
): Ciphertext.Serialized.t {
  return Ciphertext.serialize(Ciphertext.parse(ciphertext));
}

function canonicalProof(proof: Proof.Serialized.t): Proof.Serialized.t {
  return Proof.serialize(Proof.parse(proof));
}

function canonicalNonZeroProof(
  proof: ProofNonZero.Serialized.t,
): ProofNonZero.Serialized.t {
  return ProofNonZero.serialize(ProofNonZero.parse(proof));
}

function canonicalAnswerH(
  answer: Answer.AnswerH.Serialized.t,
): Answer.AnswerH.Serialized.t {
  let obj: Answer.AnswerH.Serialized.t = {
    choices: answer.choices.map(canonicalCiphertext),
    individual_proofs: map2(answer.individual_proofs, canonicalProof),
    overall_proof: answer.overall_proof.map(canonicalProof),
  };
  if (answer.blank_proof) {
    obj.blank_proof = answer.blank_proof.map(canonicalProof);
  }
  return obj;
}

function canonicalAnswerNH(
  answer: Answer.AnswerNH.Serialized.t,
): Answer.AnswerNH.Serialized.t {
  return {
    choices: canonicalCiphertext(answer.choices),
    proof: canonicalProof(answer.proof),
  };
}

function canonicalAnswerL(
  answer: Answer.AnswerL.Serialized.t,
): Answer.AnswerL.Serialized.t {
  return {
    choices: map2(answer.choices, canonicalCiphertext),
    individual_proofs: map3(answer.individual_proofs, canonicalProof),
    overall_proof: canonicalProof(answer.overall_proof),
    list_proofs: map2(answer.list_proofs, canonicalProof),
    nonzero_proof: canonicalNonZeroProof(answer.nonzero_proof),
  };
}

export default function (ballot: Ballot.t, election: Election.t): Ballot.t {
  // The order of the fields in the JSON.stringify serialization
  // correspond to the order of insertion.
  // This is not guaranteed by but is the case in every tested js engines.
  let obj = {
    election_uuid: ballot.election_uuid,
    election_hash: ballot.election_hash,
    credential: ballot.credential,
    answers: [],
    signature: { hash: "", proof: { challenge: "", response: "" } },
  };

  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    const answer = ballot.answers[i];
    if (Answer.Serialized.IsAnswerH(answer, question)) {
      obj.answers.push(canonicalAnswerH(answer));
    } else if (Answer.Serialized.IsAnswerNH(answer, question)) {
      obj.answers.push(canonicalAnswerNH(answer));
    } else if (Answer.Serialized.IsAnswerL(answer, question)) {
      obj.answers.push(canonicalAnswerL(answer));
    } else {
      throw new Error("Unknown answer type");
    }
  }

  if (ballot.signature.hash) {
    obj["signature"] = {
      hash: ballot.signature.hash,
      proof: canonicalProof(ballot.signature.proof),
    };
  }

  return obj;
}
