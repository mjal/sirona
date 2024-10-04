// @ts-nocheck
import * as ElGamal from "./ElGamal";
import * as Question from "./Question";
import * as Election from "./Election";
import * as Ballot from "./Ballot";
import * as Event from "./Event";
import * as Setup from "./Setup";

export type t = {
  num_tallied: number;
  total_weight: number;
  encrypted_tally: Array<ElGamal.serialized_t[] | ElGamal.serialized_t[][]>;
};

export function verify(setup: Setup.t, encryptedTally: t, ballots: Ballot.t[]) {
  const { election, credentials } = setup;
  let talliedBallots = keepLastBallots(ballots);
  const recomputedEncryptedTally = compute(
    election,
    talliedBallots,
    credentials,
  );

  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    if (Question.IsQuestionH(question)) {
      for (let j = 0; j < encryptedTally.encrypted_tally[i].length; j++) {
        if (
          ElGamal.toStringS(encryptedTally.encrypted_tally[i][j]) !==
          ElGamal.toString(recomputedEncryptedTally.encrypted_tally[i][j])
        ) {
          throw new Error("Encrypted tally is incorrect");
        }
      }
    } else if (Question.IsQuestionL(question)) {
      for (let j = 0; j < encryptedTally.encrypted_tally[i].length; j++) {
        for (let k = 0; k < encryptedTally.encrypted_tally[i][j].length; k++) {
          if (
            ElGamal.toStringS(encryptedTally.encrypted_tally[i][j][k]) !==
            ElGamal.toString(recomputedEncryptedTally.encrypted_tally[i][j][k])
          ) {
            throw new Error("Encrypted tally is incorrect");
          }
        }
      }
    } else if (Question.IsQuestionNH(question)) {
      const a = encryptedTally.encrypted_tally[i]
        .slice()
        .sort((e1, e2) => e1.alpha > e2.alpha);
      const b = recomputedEncryptedTally.encrypted_tally[i]
        .slice()
        .sort((e1, e2) => e1.alpha > e2.alpha);
      if (a.length !== b.length) {
        throw new Error("Encrypted tally is incorrect");
      }
      for (let j = 0; j < a.length; j++) {
        if (a.alpha !== b.alpha || a.beta !== b.beta) {
          throw new Error("Encrypted tally is incorrect");
        }
      }
    } else {
      throw new Error("Unsupported question type");
    }
  }

  if (
    recomputedEncryptedTally.total_weight !==
    Number(encryptedTally.total_weight)
  ) {
    throw new Error("total_weight is incorrect");
  }
  if (recomputedEncryptedTally.num_tallied !== encryptedTally.num_tallied) {
    throw new Error("num_tallied is incorrect");
  }

  return true;
}

export function keepLastBallots(ballots: Event.t<Ballot.t>[]) {
  let ret = [];
  let ballotByCredential = {};
  for (let i = ballots.length - 1; i >= 0; i--) {
    if (!ballotByCredential[ballots[i].credential]) {
      ret.push(ballots[i]);
      ballotByCredential[ballots[i].credential] = true;
    }
  }
  return ret.reverse();
}

export function compute(
  election: Election.t,
  ballots: Ballot.t[],
  credentials: string[],
) {
  let encryptedTally: t = {
    encrypted_tally: [],
    num_tallied: ballots.length,
    total_weight: 0,
  };

  encryptedTally.total_weight = ballots.reduce((acc, ballot) => {
    const credential = credentials.find(
      (line) => line.split(",")[0] === ballot.credential,
    );
    const weight = credential.includes(",")
      ? Number(credential.split(",")[1])
      : 1;
    return weight + acc;
  }, 0);

  for (let i = 0; i < election.questions.length; i++) {
    const question = election.questions[i];
    let row = null;
    if (Question.IsQuestionH(question)) {
      const size = question.answers.length + (question.blank ? 1 : 0);
      row = [...Array(size).keys()].map(() => ElGamal.zero);
    } else if (Question.IsQuestionL(question)) {
      row = [...Array(question.value.answers.length).keys()].map((_, i) => {
        return [...Array(question.value.answers[i].length).keys()].map(
          () => ElGamal.zero,
        );
      });
    } else if (Question.IsQuestionNH(question)) {
      row = [];
    } else {
      throw new Error("Unsupported question type");
    }
    encryptedTally.encrypted_tally.push(row);
  }

  for (let n = 0; n < ballots.length; n++) {
    const credential = credentials.find(
      (line) => line.split(",")[0] === ballots[n].credential,
    );
    const weight = credential.includes(",")
      ? Number(credential.split(",")[1])
      : 1;
    for (let j = 0; j < election.questions.length; j++) {
      const question = election.questions[j];
      const answer = ballots[n].answers[j];
      if (Question.IsQuestionH(question)) {
        for (let k = 0; k < encryptedTally.encrypted_tally[j].length; k++) {
          const ct = ElGamal.parse(answer.choices[k]);
          encryptedTally.encrypted_tally[j][k] = {
            alpha: encryptedTally.encrypted_tally[j][k].alpha.add(
              ct.alpha.multiply(BigInt(weight)),
            ),
            beta: encryptedTally.encrypted_tally[j][k].beta.add(
              ct.beta.multiply(BigInt(weight)),
            ),
          };
        }
      } else if (Question.IsQuestionL(question)) {
        for (let k = 0; k < encryptedTally.encrypted_tally[j].length; k++) {
          for (
            let l = 0;
            l < encryptedTally.encrypted_tally[j][k].length;
            l++
          ) {
            const ct = ElGamal.parse(answer.choices[k][l]);
            encryptedTally.encrypted_tally[j][k][l] = {
              alpha: encryptedTally.encrypted_tally[j][k][l].alpha.add(
                ct.alpha.multiply(BigInt(weight)),
              ),
              beta: encryptedTally.encrypted_tally[j][k][l].beta.add(
                ct.beta.multiply(BigInt(weight)),
              ),
            };
          }
        }
      } else if (Question.IsQuestionNH(question)) {
        if (weight !== 1) {
          throw new Error("Non-homomorphic questions must have weight 1");
        }
        encryptedTally.encrypted_tally[j].push(answer.choices);
      } else {
        throw new Error("Unsupported question type");
      }
    }
  }

  return encryptedTally;
}
