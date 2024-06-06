export function canonicalSerialization(ballot) {
  // On most implementations, the order of the fields in the
  // serialization correspond to the order of insertion. This
  // is not guaranteed by the JSON standard, but it is guaranteed
  // by JSON.stringify in most implementations.
  const obj = {
    election_uuid: ballot.election_uuid,
    election_hash: ballot.election_hash,
    credential: ballot.credential,
    answers: ballot.answers.map((answer) => {
      let obj = {};
      if (Array.isArray(answer.choices)) {
        obj.choices = answer.choices.map((choice) => {
          return {
            alpha: choice.alpha,
            beta: choice.beta,
          };
        });
      } else {
        obj.choices = {
          alpha: answer.choices.alpha,
          beta: answer.choices.beta,
        };
      }
      if (answer.proof) {
        obj.proof = {
          challenge: answer.proof.challenge,
          response: answer.proof.response,
        };
      }
      if (answer.individual_proofs) {
        obj.individual_proofs = answer.individual_proofs.map((iproof) => {
          return iproof.map((proof) => {
            return {
              challenge: proof.challenge,
              response: proof.response,
            };
          });
        });
      }
      if (answer.overall_proof) {
        if (Array.isArray(answer.overall_proof)) {
          obj.overall_proof = answer.overall_proof.map((proof) => {
            return {
              challenge: proof.challenge,
              response: proof.response,
            };
          });
        } else {
          obj.overall_proof = {
            challenge: answer.overall_proof.challenge,
            response: answer.overall_proof.response,
          };
        }
      }
      if (answer.blank_proof !== undefined) {
        obj.blank_proof = answer.blank_proof.map((proof) => {
          return {
            challenge: proof.challenge,
            response: proof.response,
          };
        });
      }
      return obj;
    }),
    signature: ballot.signature,
  };
  return JSON.stringify(obj);
}
