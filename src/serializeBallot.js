export function canonicalSerialization(ballot) {
  // On most implementations, the order of the fields in the
  // serialization correspond to the order of insertion. This
  // is not guaranteed by the JSON standard, but it is guaranteed
  // by JSON.stringify in most implementations.
  const obj = {
    election_uuid: ballot.payload.election_uuid,
    election_hash: ballot.payload.election_hash,
    credential: ballot.payload.credential,
    answers: ballot.payload.answers.map((answer) => {
      let obj = {};
      if (answer.choices.length === undefined) {
        obj.choices = {
          alpha: answer.choices.alpha,
          beta: answer.choices.beta,
        };
      } else {
        obj.choices = answer.choices.map((choice) => {
          return {
            alpha: choice.alpha,
            beta: choice.beta,
          };
        });
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
        obj.overall_proof = answer.overall_proof.map((proof) => {
          return {
            challenge: proof.challenge,
            response: proof.response,
          };
        });
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
    signature: ballot.payload.signature,
  };
  return JSON.stringify(obj);
}
