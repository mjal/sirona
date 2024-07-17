import { rev, zero, parsePoint } from "./math";

export default function (state): boolean {
  const ballots = state.ballots.filter((ballot) => ballot.accepted);

  const questions = state.setup.payload.election.questions;
  const encryptedTally = [];
  for (let i = 0; i < questions.length; i++) {
    if (questions[i].type === undefined) {
      // question_h
      const row = questions[i].answers.map((_) => {
        return { alpha: zero, beta: zero };
      });
      if (questions[i].blank) {
        row.push({ alpha: zero, beta: zero });
      }
      encryptedTally.push(row);
    } else if (questions[i].type === "Lists") {
      const matrix = questions[i].value.answers.map((l) => {
        return l.map((_) => {
          return { alpha: zero, beta: zero };
        });
      });
      encryptedTally.push(matrix);
    } else if (questions[i].type === "NonHomomorphic") {
      // Skip
    } else {
      throw new Error("Unsupported question type");
    }
  }

  for (let i = 0; i < ballots.length; i++) {
    for (let j = 0; j < questions.length; j++) {
      if (questions[j].type === undefined) {
        // question_h
        const answer = ballots[i].payload.answers[j];
        for (let k = 0; k < encryptedTally[j].length; k++) {
          const pAlpha = parsePoint(answer.choices[k].alpha);
          const pBeta = parsePoint(answer.choices[k].beta);
          const weight = state.credentialsWeights.find(
            (line) => line.credential === ballots[i].payload.credential,
          ).weight;
          encryptedTally[j][k].alpha = encryptedTally[j][k].alpha.add(
            pAlpha.multiply(BigInt(weight)),
          );
          encryptedTally[j][k].beta = encryptedTally[j][k].beta.add(
            pBeta.multiply(BigInt(weight)),
          );
        }
      } else if (questions[j].type === "Lists") {
        const answer = ballots[i].payload.answers[j];
        for (let k = 0; k < encryptedTally[j].length; k++) {
          for (let l = 0; l < encryptedTally[j][k].length; l++) {
            const pAlpha = parsePoint(answer.choices[k][l].alpha);
            const pBeta = parsePoint(answer.choices[k][l].beta);
            const weight = state.credentialsWeights.find(
              (line) => line.credential === ballots[i].payload.credential,
            ).weight;
            encryptedTally[j][k][l].alpha = encryptedTally[j][k][l].alpha.add(
              pAlpha.multiply(BigInt(weight)),
            );
            encryptedTally[j][k][l].beta = encryptedTally[j][k][l].beta.add(
              pBeta.multiply(BigInt(weight)),
            );
          }
        }
      } else if (questions[j].type === "NonHomomorphic") {
        // Skip
      } else {
        throw new Error("Unsupported question type");
      }
    }
  }

  const et = state.encryptedTally.payload.encrypted_tally;
  for (let i = 0; i < et.length; i++) {
    if (questions[i].type === undefined) {
      // question_h
      for (let j = 0; j < et[i].length; j++) {
        if (
          !(
            et[i][j].alpha === rev(encryptedTally[i][j].alpha.toHex()) &&
            et[i][j].beta === rev(encryptedTally[i][j].beta.toHex())
          )
        ) {
          throw new Error(
            "Encrypted tally microballot does not correspond to the weighted sum of all ballots",
          );
        }
      }
    } else if (questions[i].type === "Lists") {
      for (let j = 0; j < et[i].length; j++) {
        for (let k = 0; k < et[i][j].length; k++) {
          if (
            !(
              et[i][j][k].alpha ===
                rev(encryptedTally[i][j][k].alpha.toHex()) &&
              et[i][j][k].beta === rev(encryptedTally[i][j][k].beta.toHex())
            )
          ) {
            throw new Error(
              "Encrypted tally microballot does not correspond to the weighted sum of all ballots",
            );
          }
        }
      }
    } else if (questions[i].type === "NonHomomorphic") {
      // Skip
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
