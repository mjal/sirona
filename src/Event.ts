export type t<T> = {
  parent: string;
  height: number;
  type: event_type;
  payload: T;
  payloadHash: string;
  tracker: string;
  accepted: boolean;
};

type event_type =
  | "Setup"
  | "Ballot"
  | "EncryptedTally"
  | "PartialDecryption"
  | "Result";
