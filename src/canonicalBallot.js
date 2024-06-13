function copyCiphertext(ciphertext) {
  return {
    alpha: ciphertext.alpha,
    beta: ciphertext.beta,
  };
}

function copyProof(proof) {
  return {
    challenge: proof.challenge,
    response: proof.response,
  };
}

export default function (ballot) {
  // The order of the fields in the JSON.stringify serialization
  // correspond to the order of insertion.
  // This is not guaranteed by but is the case in every tested js engines.
  const obj = {
    election_uuid: ballot.election_uuid,
    election_hash: ballot.election_hash,
    credential: ballot.credential,
    answers: ballot.answers.map((answer) => {
      let obj = {};
      if (Array.isArray(answer.choices)) {
        obj.choices = answer.choices.map(copyCiphertext);
      } else {
        obj.choices = copyCiphertext(answer.choices);
      }
      if (answer.proof) {
        obj.proof = copyProof(answer.proof);
      }
      if (answer.individual_proofs) {
        obj.individual_proofs = answer.individual_proofs.map((iproof) => {
          return iproof.map(copyProof);
        });
      }
      if (answer.overall_proof) {
        if (Array.isArray(answer.overall_proof)) {
          obj.overall_proof = answer.overall_proof.map(copyProof);
        } else {
          obj.overall_proof = copyProof(answer.overall_proof);
        }
      }
      if (answer.blank_proof !== undefined) {
        obj.blank_proof = answer.blank_proof.map(copyProof);
      }
      return obj;
    }),
    signature: {
      hash: ballot.signature.hash,
      proof: copyProof(ballot.signature.proof)
    }
  };
  return obj;
}
