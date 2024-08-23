import { log } from "./logger";
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
  try {
    let state: any = load(fileEntries);

    const {
      setup,
      ballots,
      encryptedTally,
      shuffles,
      partialDecryptions,
      result
    } = state;

    await _async(Setup.verify, setup);

    for (let i = 0; i < ballots.length; i++) {
      await _async(Ballot.verify, state, ballots[i]);
    }

    if (!encryptedTally) return state;

    await _async(
      EncryptedTally.verify,
      setup.election,
      encryptedTally,
      ballots,
      setup.credentials,
    );

    let tally = state.encryptedTally.encrypted_tally.map((xs) => {
      return xs.map((x) => {
        if (x.length) {
          return x.map(Ciphertext.parse);
        } else {
          return Ciphertext.parse(x);
        }
      });
    });

    for (let i = 0; i < shuffles.length; i++) {
      await _async(Shuffle.verify, state, shuffles[i], tally);
      tally = shuffles[i].payload.ciphertexts;
    }

    for (let i = 0; i < state.partialDecryptions.length; i++) {
      await _async(
        PartialDecryption.verify,
        state,
        partialDecryptions[i],
      );
    }

    if (state.result) {
      await _async(Result.verify, result, setup, encryptedTally, partialDecryptions, shuffles);
    }

    log("top", true, "Verification done.");
    return state;
  } catch (e) {
    log("top", false, "Something wrong happened.");
    console.error(e);
  }
  return null;
}
