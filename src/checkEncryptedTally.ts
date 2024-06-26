import { log } from "./logger";
import { rev, zero, parsePoint } from "./math";

export default function (state) {
  const ballots = state.ballots.filter((ballot) => ballot.accepted);

  const questions = state.setup.payload.election.questions;
  const encryptedTally = [];
  for (let i = 0; i < questions.length; i++) {
    if (questions[i].type === undefined) { // question_h
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
    } else {
      log("encryptedTally", false, "Unsupported question type");
      encryptedTally.push([]);
    }
  }

  for (let i = 0; i < ballots.length; i++) {
    for (let j = 0; j < questions.length; j++) {
      if (questions[j].type === undefined) { // question_h
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
      } else {
        log("encryptedTally", false, "Unsupported question type");
      }
    }
  }

  const et = state.encryptedTally.payload.encrypted_tally;
  for (let i = 0; i < et.length; i++) {
    if (questions[i].type === undefined) { // question_h
      for (let j = 0; j < et[i].length; j++) {
        log("encryptedTally",
          et[i][j].alpha === rev(encryptedTally[i][j].alpha.toHex()) &&
            et[i][j].beta === rev(encryptedTally[i][j].beta.toHex()),
          "Encrypted tally microballot correspond to the weighted sum of all ballots",
        );
      }
    } else if (questions[i].type === "Lists") {
      for (let j = 0; j < et[i].length; j++) {
        for (let k = 0; k < et[i][j].length; k++) {
          log("encryptedTally",
            et[i][j][k].alpha === rev(encryptedTally[i][j][k].alpha.toHex()) &&
              et[i][j][k].beta === rev(encryptedTally[i][j][k].beta.toHex()),
            "Encrypted tally microballot correspond to the weighted sum of all ballots",
          );
        }
      }
    } else {
      log("encryptedTally", false, "Unsupported question type");
      continue; // TODO
    }
  }

  const total_weight = ballots.reduce((acc, ballot) => {
    const weight = state.credentialsWeights.find(
      (line) => line.credential === ballot.payload.credential,
    ).weight;
    return weight + acc;
  }, 0);


  log("encryptedTally",
    total_weight === Number(state.encryptedTally.payload.total_weight),
    "total_weight is correct",
  );

  log("encryptedTally",
    ballots.length === state.encryptedTally.payload.num_tallied,
    "num_tallied is correct",
  );
}
