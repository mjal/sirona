import * as Question from './question';

export type t = {
  version: number;
  description: string;
  name: string;
  group: string;
  public_key: string;
  questions: Array<Question.t>;
  uuid: string;
  administrator?: string;
  credential_authority?: string;
};
