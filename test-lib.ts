import * as Trustee from "./src/Trustee";
import { QuestionH } from "./src/Question";
import * as Election from "./src/Election";
import * as Ballot from "./src/Ballot";
import * as Credential from "./src/Credential";
import * as EncryptedTally from "./src/EncryptedTally";
import * as PartialDecryption from "./src/PartialDecryption";
import * as Setup from "./src/Setup";
import * as Result from "./src/Result";

let title = "My title"
let description = "My description"

let question : QuestionH.t =  {
  question: "Question",
  answers: ["Yes", "Yes Yes", "No"],
  min: 1,
  max: 1
}
let questions = [question]

let [x, serializedTrustee] = Trustee.generate()
let trustee = Trustee.parse(serializedTrustee)
let trustees = [trustee]

let election = Election.create(title, description, trustees, questions)

let priv1 = Credential.generatePriv()
let cred1 = Credential.derive(election.uuid, priv1)
let priv2 = Credential.generatePriv()
let cred2 = Credential.derive(election.uuid, priv2)
let priv3 = Credential.generatePriv()
let cred3 = Credential.derive(election.uuid, priv3)

let credentials = [
  cred1.hPublicCredential,
  cred2.hPublicCredential,
  cred3.hPublicCredential
]

let setup : Setup.t = {
  election,
  credentials,
  trustees
}
console.log(setup)

let ballots : Ballot.t[] = []
ballots.push(Ballot.generate(setup, priv1, [[0,0,1]]))
ballots.push(Ballot.generate(setup, priv2, [[0,0,1]]))
ballots.push(Ballot.generate(setup, priv3, [[1,0,0]]))
console.log(ballots)

console.log(ballots[0].answers[0].choices)

let et = EncryptedTally.generate(setup, ballots)
console.log(et)

let pd = PartialDecryption.generate(setup, et, 1, x)
console.log(pd)
console.log(pd.payload.decryption_factors)
console.log(pd.payload.decryption_proofs)

let res = Result.generate(setup, et, [pd],  [])
console.log(res)
// {result: [[0,2,0]]}, 
