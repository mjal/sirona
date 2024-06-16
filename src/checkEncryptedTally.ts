import { log } from "./logger";
import { rev, zero, parsePoint } from "./math";

export default function (state) {
  const ballots = state.ballots.filter((ballot) => ballot.accepted);

  const questions = state.setup.payload.election.questions;
  const encryptedTally = [];
  for (let i = 0; i < questions.length; i++) {
    const answers = questions[i].answers || [];
    const row = answers.map((_answer) => {
      return { alpha: zero, beta: zero };
    });
    if (questions[i].blank) {
      row.push({ alpha: zero, beta: zero });
    }
    encryptedTally.push(row);
  }

  for (let i = 0; i < ballots.length; i++) {
    for (let j = 0; j < encryptedTally.length; j++) {
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
