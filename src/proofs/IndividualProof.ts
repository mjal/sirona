import * as Election from "../Election";
import * as Proof from "../Proof";
import * as Point from "../Point";
import * as Ciphertext from "../Ciphertext";
import { L, mod, formula2, formula, Hiprove, Hdecrypt } from "../math";

export function verify(
  election: Election.t,
  credential: string,
  zIndividualProof: Array<Proof.t>,
  eCiphertext: Ciphertext.t,
) {
  const pY = Point.parse(election.public_key);
  const S = `${Election.fingerprint(election)}|${credential}`;
  const nSumChallenges = mod(
    zIndividualProof[0].nChallenge + zIndividualProof[1].nChallenge,
    L,
  );
  const [pA0, pB0] = formula2(
    pY,
    eCiphertext.pAlpha,
    eCiphertext.pBeta,
    zIndividualProof[0].nChallenge,
    zIndividualProof[0].nResponse,
    0,
  );
  const [pA1, pB1] = formula2(
    pY,
    eCiphertext.pAlpha,
    eCiphertext.pBeta,
    zIndividualProof[1].nChallenge,
    zIndividualProof[1].nResponse,
    1,
  );
  const nH = Hiprove(
    S,
    eCiphertext.pAlpha,
    eCiphertext.pBeta,
    pA0,
    pB0,
    pA1,
    pB1,
  );
  return nSumChallenges === nH;
}

