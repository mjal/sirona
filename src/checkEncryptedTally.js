import { check } from "./utils.js";
import { rev, one } from "./math.js";
import { ed25519 } from "@noble/curves/ed25519";

export default function (state) {
  const ballots = keepLastBallotByCredentials(state.ballots);

  const questions = state.setup.payload.election.questions;
  const encryptedTally = questions.map((question) => {
    return question.answers.map((answer) => {
      return {
        alpha: one,
        beta: one,
      };
    });
  });

  for (let i = 0; i < ballots.length; i++) {
    for (let j = 0; j < encryptedTally.length; j++) {
      const answer = ballots[i].payload.answers[j];
      for (let k = 0; k < encryptedTally[j].length; k++) {
        const alpha = ed25519.ExtendedPoint.fromHex(
          rev(answer.choices[k].alpha),
        );
        const beta = ed25519.ExtendedPoint.fromHex(rev(answer.choices[k].beta));

        // TODO: Use weight
        encryptedTally[j][k].alpha = encryptedTally[j][k].alpha.add(alpha);
        encryptedTally[j][k].beta = encryptedTally[j][k].beta.add(beta);
      }
    }
  }

  const et = state.encryptedTally.payload.encrypted_tally;
  for (let i = 0; i < et.length; i++) {
    for (let j = 0; j < et[i].length; j++) {
      check(
        "encryptedTally",
        "Encrypted tally microballot correspond to the weighted sum of all ballots",
        et[i][j].alpha === rev(encryptedTally[i][j].alpha.toHex()) &&
          et[i][j].beta === rev(encryptedTally[i][j].beta.toHex()),
      );
    }
  }

  // TODO: Check total weight and total count
}

function keepLastBallotByCredentials(ballots) {
  const ballotsByCredential = {};
  for (let i = 0; i < ballots.length; i++) {
    ballotsByCredential[ballots[i].payload.credential] = ballots[i];
  }
  return Object.values(ballotsByCredential);
}
