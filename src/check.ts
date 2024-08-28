import { _async } from "./utils";
import load from "./load";
import * as EncryptedTally from "./EncryptedTally";
import * as Setup from "./Setup";
import * as Ballot from "./Ballot";
import * as Shuffle from "./Shuffle";
import * as PartialDecryption from "./PartialDecryption";
import * as Result from "./Result";
import * as Ciphertext from "./Ciphertext";

export default async function (fileEntries) {
  let state: any = load(fileEntries);

  const {
    setup,
    ballots,
    encryptedTally,
    shuffles,
    partialDecryptions,
    result,
  } = state;

  await _async(Setup.verify, setup);

  for (let i = 0; i < ballots.length; i++) {
    await _async(Ballot.verify, setup, ballots[i]);
  }

  if (!encryptedTally) {
    // No EncryptedTally: Stop here
    return state;
  }

  await _async(EncryptedTally.verify, setup, encryptedTally, ballots);

  // TODO: Move to a function ?
  let tally = encryptedTally.encrypted_tally.map((xs) => {
    return xs.map((x) => {
      if (x.length) {
        return x.map(Ciphertext.parse);
      } else {
        return Ciphertext.parse(x);
      }
    });
  });

  for (let i = 0; i < shuffles.length; i++) {
    await _async(Shuffle.verify, shuffles[i], setup.election, tally);
    tally = shuffles[i].payload.ciphertexts;
  }

  for (let i = 0; i < partialDecryptions.length; i++) {
    await _async(
      PartialDecryption.verify,
      partialDecryptions[i],
      setup,
      encryptedTally,
    );
  }

  if (!result) {
    // No Result: Stop here
    return state;
  }

  await _async(
    Result.verify,
    result,
    setup,
    encryptedTally,
    partialDecryptions,
    shuffles,
  );

  return state;
}
