import { Serialized } from './types';

// NOTE: Instead of canonical* could also use serialize(parse()) when we have all serialize/parse functions and serialize function are all canonicals

function canonicalCiphertext(ciphertext: Serialized.Ciphertext) {
  return {
    alpha: ciphertext.alpha,
    beta: ciphertext.beta,
  };
}

function canonicalProof(proof: Serialized.Proof) {
  return {
    challenge: proof.challenge,
    response: proof.response,
  };
}

function canonicalNonZeroProof(proof: Serialized.NonZeroProof) {
  return {
    commitment: proof.commitment,
    challenge: proof.challenge,
    response: proof.response,
  };
}


function canonicalAnswerH(answer: Serialized.AnswerH): Serialized.AnswerH {
  return {
    choices: answer.choices.map(canonicalCiphertext),
    individual_proofs: answer.individual_proofs.map((iproof) => {
      return iproof.map(canonicalProof);
    }),
    overall_proof: answer.overall_proof.map(canonicalProof)
  }
}

function canonicalAnswerNH(answer: Serialized.AnswerNH): Serialized.AnswerNH {
  return {
    choices: canonicalCiphertext(answer.choices),
    proof: canonicalProof(answer.proof)
  }
}

function canonicalAnswerL(answer: Serialized.AnswerL): Serialized.AnswerL {
  return {
    choices: answer.choices.map((choices) => {
      return choices.map(canonicalCiphertext);
    }),
    individual_proofs: answer.individual_proofs.map((iproofs) => {
      return iproofs.map((iproof) => iproof.map(canonicalProof));
    }),
    overall_proof: canonicalProof(answer.overall_proof),
    list_proofs: answer.list_proofs.map((proofs) => proofs.map(canonicalProof)),
    nonzero_proof: canonicalNonZeroProof(answer.nonzero_proof)
  }
}

export default function (ballot: any, election: any) {
  // The order of the fields in the JSON.stringify serialization
  // correspond to the order of insertion.
  // This is not guaranteed by but is the case in every tested js engines.
  let obj = {
    election_uuid: ballot.election_uuid,
    election_hash: ballot.election_hash,
    credential: ballot.credential,
    answers: []
  };

  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    if (Serialized.IsAnswerH(ballot.answers[i], question)) {
      obj.answers.push(canonicalAnswerH(ballot.answers[i]));
    } else if (Serialized.IsAnswerNH(ballot.answers[i], question)) {
      obj.answers.push(canonicalAnswerNH(ballot.answers[i]));
    } else if (Serialized.IsAnswerL(ballot.answers[i], question)) {
      obj.answers.push(canonicalAnswerL(ballot.answers[i]));
    } else {
      throw new Error('Unknown answer type');
    }
  }

  obj['signature'] = {
    hash: ballot.signature.hash,
    proof: canonicalProof(ballot.signature.proof)
  };

  console.log(obj);
  console.log(ballot);

  return obj;
}
