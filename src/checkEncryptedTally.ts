import * as Question from "./Question";
import * as Ciphertext from "./Ciphertext";

export default function (state: any): boolean {
  const election = state.setup.payload.election;
  const ballots = state.ballots.filter((ballot: any) => ballot.accepted);
  const encryptedTally = [];
  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    let row = null;
    if (Question.IsQuestionH(question)) {
      const size = question.answers.length + (question.blank ? 1 : 0);
      row = [...Array(size).keys()].map(() => Ciphertext.zero);
    } else if (Question.IsQuestionL(question)) {
      row = [...Array(question.value.answers.length).keys()].map((_, i) => {
        return [...Array(question.value.answers[i].length).keys()].map(
          () => Ciphertext.zero,
        );
      });
    } else if (Question.IsQuestionNH(question)) {
      throw new Error("Unimplemented");
    } else {
      throw new Error("Unsupported question type");
    }
    encryptedTally.push(row);
  }

  for (let n = 0; n < ballots.length; n++) {
    for (let j = 0; j < election.questions.length; j++) {
      const question = election.questions[j];
      if (Question.IsQuestionH(question)) {
        const answer = ballots[n].payload.answers[j];
        for (let k = 0; k < encryptedTally[j].length; k++) {
          const ct = Ciphertext.parse(answer.choices[k]);
          const weight = state.credentialsWeights.find(
            (line) => line.credential === ballots[n].payload.credential,
          ).weight;
          encryptedTally[j][k] = {
            pAlpha: encryptedTally[j][k].pAlpha.add(
              ct.pAlpha.multiply(BigInt(weight)),
            ),
            pBeta: encryptedTally[j][k].pBeta.add(
              ct.pBeta.multiply(BigInt(weight)),
            ),
          };
        }
      } else if (Question.IsQuestionL(question)) {
        const answer = ballots[n].payload.answers[j];
        for (let k = 0; k < encryptedTally[j].length; k++) {
          for (let l = 0; l < encryptedTally[j][k].length; l++) {
            const ct = Ciphertext.parse(answer.choices[k][l]);
            const weight = state.credentialsWeights.find(
              (line) => line.credential === ballots[n].payload.credential,
            ).weight;
            encryptedTally[j][k][l] = {
              pAlpha: encryptedTally[j][k][l].pAlpha.add(
                ct.pAlpha.multiply(BigInt(weight)),
              ),
              pBeta: encryptedTally[j][k][l].pBeta.add(
                ct.pBeta.multiply(BigInt(weight)),
              ),
            };
          }
        }
      } else if (Question.IsQuestionNH(question)) {
        throw new Error("Unimplemented");
      } else {
        throw new Error("Unsupported question type");
      }
    }
  }

  const et = state.encryptedTally.payload.encrypted_tally;
  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    if (Question.IsQuestionH(question)) {
      for (let j = 0; j < et[i].length; j++) {
        if (
          Ciphertext.Serialized.toString(et[i][j]) !==
          Ciphertext.toString(encryptedTally[i][j])
        ) {
          throw new Error(
            "Encrypted tally microballot does not correspond to the weighted sum of all ballots",
          );
        }
      }
    } else if (Question.IsQuestionL(question)) {
      for (let j = 0; j < et[i].length; j++) {
        for (let k = 0; k < et[i][j].length; k++) {
          if (
            Ciphertext.Serialized.toString(et[i][j][k]) !==
            Ciphertext.toString(encryptedTally[i][j][k])
          ) {
            throw new Error(
              "Encrypted tally microballot does not correspond to the weighted sum of all ballots",
            );
          }
        }
      }
    } else if (Question.IsQuestionNH(question)) {
      throw new Error("Unimplemented");
    } else {
      throw new Error("Unsupported question type");
    }
  }

  const total_weight = ballots.reduce((acc, ballot) => {
    const weight = state.credentialsWeights.find(
      (line) => line.credential === ballot.payload.credential,
    ).weight;
    return weight + acc;
  }, 0);

  if (total_weight !== Number(state.encryptedTally.payload.total_weight)) {
    throw new Error("total_weight is incorrect");
  }
  if (ballots.length !== state.encryptedTally.payload.num_tallied) {
    throw new Error("num_tallied is incorrect");
  }

  return true;
}
