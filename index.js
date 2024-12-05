import * as Trustee from "./dist/Trustee.js";
import * as Election from "./dist/Election.js";
import * as Ballot from "./dist/Ballot.js";
import * as Credential from "./dist/Credential.js";
import sjcl from "sjcl";

// TODO: Only keep the export format used by scrutin
export { Trustee, Election, Ballot, Credential };
export default {
  Trustee,
  Election,
  Ballot,
  Credential,
  sjcl
};
