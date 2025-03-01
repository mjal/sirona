import * as Zq from "./Zq";
import { range } from "./utils";
import { modInverse } from "./math";
import * as Trustee from "./Trustee";
import * as Point from "./Point";
import * as Question from "./Question";
import * as ElGamal from "./ElGamal";
import * as EncryptedTally from "./EncryptedTally";
import * as Setup from "./Setup";
import * as Election from "./Election";
import * as PartialDecryption from "./PartialDecryption";
import * as Shuffle from "./Shuffle";

export type t = {
  result: number[][];
};

export function verify(
  result: t,
  setup: Setup.t,
  encryptedTally: EncryptedTally.t,
  partialDecryptions: PartialDecryption.t[],
  shuffles: Shuffle.t[],
): boolean {
  const election = setup.election;
  const et = encryptedTally.encrypted_tally;
  const res = result.result;
  const df = getDecryptionFactors(setup, encryptedTally, partialDecryptions);
  for (let i = 0; i < election.questions.length; i++) {
    let question = election.questions[i];
    if (Question.IsQuestionH(question)) {
      for (let j = 0; j < question.answers.length; j++) {
        if (!verifyOne(et[i][j], df[i][j], res[i][j])) {
          throw new Error("Invalid result");
        }
      }
    } else if (Question.IsQuestionL(question)) {
      for (let j = 0; j < res[i].length; j++) {
        // @ts-ignore
        for (let k = 0; k < res[i][j].length; k++) {
          if (!verifyOne(et[i][j][k], df[i][j][k], res[i][j][k])) {
            throw new Error("Invalid result");
          }
        }
      }
    } else if (Question.IsQuestionNH(question)) {
      if (shuffles.length === 0) {
        throw "No shuffles found !";
      } else {
        const answers = shuffles[shuffles.length - 1].payload.ciphertexts;
        for (let j = 0; j < res[i].length; j++) {
          // @ts-ignore
          const encodedRes = Point.of_ints(res[i][j]);
          if (!verifyNH(answers[i][j], df[i][j], encodedRes)) {
            throw new Error("Invalid result");
          }
        }
      }
    } else {
      throw new Error("Unknown question type");
    }
  }

  return true;
}

function verifyOne(et: any, df: any, res: any) {
  const beta = Point.parse(et.beta);
  const pResult = beta.add(df.negate());
  const nAnswer = BigInt(res);
  return (
    (res === 0 && Point.isEqual(pResult, Point.zero)) ||
    (res !== 0 && Point.isEqual(pResult, Point.g.multiply(nAnswer)))
  );
}

function verifyNH(et: ElGamal.t, df: Point.t, encodedRes: any) {
  let pResult = et.beta.add(df.negate());
  return Point.isEqual(pResult, encodedRes);
}

function getDecryptionFactors(
  setup: Setup.t,
  encryptedTally,
  partialDecryptions
) {
  const election: Election.t = setup.election;
  let df = [];
  for (let i = 0; i < election.questions.length; i++) {
    let question = election.questions[i];
    let row = [];
    if (Question.IsQuestionH(question)) {
      row = range(question.answers.length).map(() => Point.zero);
    } else if (Question.IsQuestionL(question)) {
      row = range(question.value.answers.length).map((i) => {
        return range(question.value.answers[i].length).map(() => {
          return Point.zero;
        });
      });
    } else if (Question.IsQuestionNH(question)) {
      row = range(encryptedTally.num_tallied).map(() => Point.zero);
    } else {
      throw new Error("Unknown question type");
    }
    df.push(row);
  }

  const ownerToTrusteeIndex = Trustee.ownerIndexToTrusteeIndex(setup.trustees);
  for (let i = 0; i < setup.trustees.length; i++) {
    const [type, content] = setup.trustees[i];
    if (type === "Single") {
      let partialDecryption = null;
      for (let j = 0; j < partialDecryptions.length; j++) {
        const [_type, trusteeIdx, subIdx] =
          ownerToTrusteeIndex[partialDecryptions[j].owner];
        if (trusteeIdx === i && subIdx === -1) {
          partialDecryption = partialDecryptions[j];
        }
      }
      if (partialDecryption === null) {
        throw new Error(`No partial decryption found for trustee ${i}`);
      }
      df = multiplyDfPow(df, parseDf(partialDecryption), 1);
    } else {
      // Pedersen
      let pds = partialDecryptions.filter((pd) => {
        return ownerToTrusteeIndex[pd.owner][1] === i;
      });
      pds = [...new Map(pds.map((item) => [item.owner, item])).values()]; // Unique by owner
      pds = pds.slice(0, content.threshold); // Remove useless shares
      if (pds.length !== content.threshold) {
        throw new Error(
          `Not enough partial decryptions for Pedersen trustee ${i}`,
        );
      }

      // INIT PERDERSON DF
      let res = [];
      for (let i = 0; i < election.questions.length; i++) {
        let question = election.questions[i];
        let row = [];
        if (Question.IsQuestionH(question)) {
          row = [...Array(question.answers.length).keys()].map(
            () => Point.zero,
          );
        } else if (Question.IsQuestionL(question)) {
          row = [...Array(question.value.answers.length).keys()].map((_, i) => {
            return [...Array(question.value.answers[i].length).keys()].map(
              () => Point.zero,
            );
          });
        } else if (Question.IsQuestionNH(question)) {
          throw new Error("Not Implemented");
        } else {
          throw new Error("Unknown question type");
        }
        res.push(row);
      }

      // AGGREGATE PEDERSON DF
      for (let j = 0; j < pds.length; j++) {
        const [_type, trusteeIdx, subIdx] = ownerToTrusteeIndex[pds[j].owner];
        let indexes = pds.map((pd) => {
          const [_type, _trusteeIdx, subIdx] = ownerToTrusteeIndex[pd.owner];
          // @ts-ignore
          return subIdx + 1;
        });
        res = multiplyDfPow(
          res,
          parseDf(pds[j]),
          // @ts-ignore
          lagrange(subIdx + 1, indexes),
        );
      }

      // ADD PEDERSON DF TO GLOBAL DF
      df = multiplyDfPow(df, res, 1);
    }
  }

  return df;
}

function lagrange(n, indexes) {
  let result = 1n;
  for (let i = 0; i < indexes.length; i++) {
    if (n !== indexes[i]) {
      let denominator = Zq.mod(BigInt(indexes[i] - n));
      result = Zq.mod(
        result * BigInt(indexes[i]) * modInverse(denominator, Zq.L),
      );
    }
  }
  return result;
}

function parseDf(df) {
  let m = df.payload.decryption_factors;
  let res = [];
  for (let i = 0; i < m.length; i++) {
    let row = [];
    for (let j = 0; j < m[i].length; j++) {
      if (Array.isArray(m[i][j])) {
        row.push(m[i][j].map(Point.parse));
      } else {
        row.push(Point.parse(m[i][j]));
      }
    }
    res.push(row);
  }
  return res;
}

function multiplyDfPow(df, df2, exp) {
  for (let i = 0; i < df.length; i++) {
    for (let j = 0; j < df[i].length; j++) {
      if (df2[i][j].length) {
        for (let k = 0; k < df[i][j].length; k++) {
          df[i][j][k] = df[i][j][k].add(df2[i][j][k].multiply(BigInt(exp)));
        }
      } else {
        df[i][j] = df[i][j].add(df2[i][j].multiply(BigInt(exp)));
      }
    }
  }
  return df;
}

export function generate(
  setup: Setup.t,
  encryptedTally: EncryptedTally.t,
  partialDecryptions: PartialDecryption.t[],
  shuffles: Shuffle.t[]
): t {
  const election = setup.election;
  const et = encryptedTally.encrypted_tally;
  const df = getDecryptionFactors(setup, encryptedTally, partialDecryptions);
  let total = []
  for (let i = 0; i < election.questions.length; i++) {
    let question = election.questions[i];
    if (Question.IsQuestionH(question)) {
      let tmp = []
      for (let j = 0; j < question.answers.length; j++) {
        for (let k = 0; k < 1000; k++) { // FIX: Go above 1000
          // @ts-ignore
          if (verifyOne(ElGamal.serialize(et[i][j]), df[i][j], k)) {
            tmp.push(k);
            break;
          }
          if (k == 999) {
            throw new Error("Result out-of-bound");
          }
        }
      }
      total.push(tmp)
    } else {
      throw new Error("Unsupported question type");
    }
  }

  return { result: total };
}

