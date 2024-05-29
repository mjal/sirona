import { check } from "./utils.js";
import { g, L, zero, mod, modInverse, parsePoint } from "./math";

export default function (state) {
  const et = state.encryptedTally.payload.encrypted_tally;
  const res = state.result.payload.result;
  const df = getDecryptionFactors(state);
  for (let i = 0; i < res.length; i++) {
    const question = state.setup.payload.election.questions[i];
    if (question.type === undefined) {
      for (let j = 0; j < res[i].length; j++) {
        const pBeta = parsePoint(et[i][j].beta);
        const pResult = pBeta.add(df[i][j].negate());
        const nAnswer = BigInt(res[i][j]);

        check(
          "result",
          `Result ${i},${j} correspond to the log of the sum of partial decryptions`,
          (res[i][j] === 0 && pResult.toHex() === zero.toHex()) ||
            (res[i][j] !== 0 &&
              pResult.toHex() === g.multiply(nAnswer).toHex()),
          true,
        );
      }
    } else {
      continue; // TODO
    }
  }
}

function getDecryptionFactors(state) {
  const et = state.encryptedTally.payload.encrypted_tally;
  let df = [];
  for (let i = 0; i < et.length; i++) {
    let row = [];
    for (let j = 0; j < et[i].length; j++) {
      row.push(zero);
    }
    df.push(row);
  }

  for (let i = 0; i < state.setup.payload.trustees.length; i++) {
    const [type, content] = state.setup.payload.trustees[i];
    if (type === "Single") {
      let partialDecryption = null;
      for (let j = 0; j < state.partialDecryptions.length; j++) {
        const [_type, trusteeIdx, subIdx] =
          state.ownerToTrusteeIndex[state.partialDecryptions[j].payload.owner];
        if (trusteeIdx === i && subIdx === -1) {
          partialDecryption = state.partialDecryptions[j];
        }
      }
      check(
        "result",
        `Partial decryption found for trustee ${i}`,
        partialDecryption !== null,
        true,
      );
      df = multiplyDfPow(df, parseDf(partialDecryption), 1);
    } else {
      //  "Pedersen"

      let pds = state.partialDecryptions.filter((pd) => {
        return state.ownerToTrusteeIndex[pd.payload.owner][1] === i;
      });
      pds = [
        ...new Map(pds.map((item) => [item.payload.owner, item])).values(),
      ]; // Unique by owner
      pds = pds.slice(0, content.threshold); // Remove useless shares

      check(
        "result",
        `Enough partial decryptions for Pedersen trustee ${i}`,
        pds.length === content.threshold,
        true,
      );

      // INIT PERDERSON DF
      let res = [];
      for (let i = 0; i < et.length; i++) {
        let row = [];
        for (let j = 0; j < et[i].length; j++) {
          row.push(zero);
        }
        res.push(row);
      }

      // AGGREGATE PEDERSON DF
      for (let j = 0; j < pds.length; j++) {
        const [_type, trusteeIdx, subIdx] =
          state.ownerToTrusteeIndex[pds[j].payload.owner];
        let indexes = pds.map((pd) => {
          const [_type, _trusteeIdx, subIdx] =
            state.ownerToTrusteeIndex[pd.payload.owner];
          return subIdx + 1;
        });
        res = multiplyDfPow(
          res,
          parseDf(pds[j]),
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
  let result = BigInt(1);
  for (let i = 0; i < indexes.length; i++) {
    if (n !== indexes[i]) {
      let denominator = mod(BigInt(indexes[i] - n), L);
      result = mod(result * BigInt(indexes[i]) * modInverse(denominator, L), L);
    }
    //let kj = k - j in
    //if kj = 0 then accu else G.Zq.(accu * of_int k * invert (of_int kj)))
  }
  return result;
}

function parseDf(df) {
  let m = df.payload.payload.decryption_factors;
  let res = [];
  for (let i = 0; i < m.length; i++) {
    let row = [];
    for (let j = 0; j < m[i].length; j++) {
      if (Array.isArray(m[i][j])) {
        console.log(m[i][j]);
        row.push(m[i][j].map(parsePoint));
      } else {
        row.push(parsePoint(m[i][j]));
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
