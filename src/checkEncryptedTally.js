import { check } from "./utils.js";
import { rev, zero, parsePoint } from "./math";

export default function (state) {
  const ballots = keepLastBallotByCredentials(state.ballots);

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
    if (questions[i].type === "NonHomomorphic") {
      continue;
    }
    for (let j = 0; j < et[i].length; j++) {
      check(
        "encryptedTally",
        "Encrypted tally microballot correspond to the weighted sum of all ballots",
        et[i][j].alpha === rev(encryptedTally[i][j].alpha.toHex()) &&
          et[i][j].beta === rev(encryptedTally[i][j].beta.toHex()),
      );
    }
  }

  const total_weight = ballots.reduce((acc, ballot) => {
    const weight = state.credentialsWeights.find(
      (line) => line.credential === ballot.payload.credential,
    ).weight;
    return weight + acc;
  }, 0);

  check(
    "encryptedTally",
    "total_weight is correct",
    total_weight === state.encryptedTally.payload.total_weight
  );

  check(
    "encryptedTally",
    "num_tallied is correct",
    ballots.length === state.encryptedTally.payload.num_tallied
  );
}

function keepLastBallotByCredentials(ballots) {
  const ballotsByCredential = {};
  for (let i = 0; i < ballots.length; i++) {
    ballotsByCredential[ballots[i].payload.credential] = ballots[i];
  }
  return Object.values(ballotsByCredential);
}
