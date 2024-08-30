import * as Point from "./Point";
import * as Proof from "./Proof";
import * as Election from "./Election";
import { Hpok } from "./math";
import * as Z from "./Z";

export type t = Single.t | Pedersen.t;

export function toJSON(trustee: t) {
  if (trustee[0] === "Single") {
    return Single.toJSON(trustee);
  } else if (trustee[0] === "Pedersen") {
    return Pedersen.toJSON(trustee);
  }
}

export function fromJSON(trustee: any) {
  if (trustee[0] === "Single") {
    return Single.fromJSON(trustee);
  } else if (trustee[0] === "Pedersen") {
    return Pedersen.fromJSON(trustee);
  }
}

namespace Single {
  export type t = ["Single", PublicKey.t];
  export namespace Serialized {
    export type t = ["Single", PublicKey.Serialized.t];
  }
  export function toJSON(trustee: Single.t): Single.Serialized.t {
    return ["Single", PublicKey.toJSON(trustee[1])];
  }
  export function fromJSON(trustee: Single.Serialized.t): Single.t {
    return ["Single", PublicKey.fromJSON(trustee[1])];
  }
}

namespace Pedersen {
  export type t = [
    "Pedersen",
    {
      threshold: number;
      certs: Array<Message.t>;
      coefexps: Array<Message.t>;
      verification_keys: Array<PublicKey.t>;
    },
  ];
  export namespace Serialized {
    export type t = [
      "Pedersen",
      {
        threshold: number;
        certs: Array<Message.Serialized.t>;
        coefexps: Array<Message.Serialized.t>;
        verification_keys: Array<PublicKey.Serialized.t>;
      },
    ];
  }
  export function toJSON(trustee: Pedersen.t): Pedersen.Serialized.t {
    return [
      "Pedersen",
      {
        threshold: trustee[1].threshold,
        certs: trustee[1].certs.map(Message.toJSON),
        coefexps: trustee[1].coefexps.map(Message.toJSON),
        verification_keys: trustee[1].verification_keys.map(PublicKey.toJSON),
      },
    ];
  }
  export function fromJSON(trustee: Pedersen.Serialized.t): Pedersen.t {
    return [
      "Pedersen",
      {
        threshold: trustee[1].threshold,
        certs: trustee[1].certs.map(Message.fromJSON),
        coefexps: trustee[1].coefexps.map(Message.fromJSON),
        verification_keys: trustee[1].verification_keys.map(PublicKey.fromJSON),
      },
    ];
  }
}

export namespace PublicKey {
  export type t = {
    pok: Proof.t;
    public_key: Point.t;
  };
  export namespace Serialized {
    export type t = {
      pok: Proof.Serialized.t;
      public_key: Point.Serialized.t;
    };
  }
  export function toJSON(o: t): Serialized.t {
    return {
      pok: Proof.serialize(o.pok),
      public_key: Point.serialize(o.public_key),
    };
  }
  export function fromJSON(o: Serialized.t): t {
    return {
      pok: Proof.parse(o.pok),
      public_key: Point.parse(o.public_key),
    };
  }
}

export namespace Message {
  export type t = {
    message: string;
    signature: Proof.t;
  };
  export namespace Serialized {
    export type t = {
      message: string;
      signature: Proof.Serialized.t;
    };
  }
  export function toJSON(o: t): Serialized.t {
    return {
      message: o.message,
      signature: Proof.serialize(o.signature),
    };
  }
  export function fromJSON(o: Serialized.t): t {
    return {
      message: o.message,
      signature: Proof.parse(o.signature),
    };
  }
}

export function verify(election: Election.t, trustee: t) {
  if (trustee[0] === "Single") {
    if (!verifyPublicKey(election, trustee[1])) {
      return false;
    }
  } else {
    // "Pedersen"
    for (let j = 0; j < trustee[1].verification_keys.length; j++) {
      if (verifyPublicKey(election, trustee[1].verification_keys[j])) {
        return false;
      }
    }
  }
  return true;
}

function verifyPublicKey(election: Election.t, trustee: PublicKey.t) {
  if (!Point.isValid(trustee.public_key)) {
    throw new Error("Invalid curve point");
  }

  const pA = Point.g
    .multiply(trustee.pok.nResponse)
    .add(trustee.public_key.multiply(trustee.pok.nChallenge));

  const S = `${election.group}|${Point.serialize(trustee.public_key)}`;

  if (Hpok(S, pA) !== trustee.pok.nChallenge) {
    throw new Error("Trustee POK is invalid");
  }
  return true;
}

export function getPublicKeyByOwnerIndex(trustees: t[], index: number) {
  let n = 0;
  for (let i = 0; i < trustees.length; i++) {
    let trustee = trustees[i];
    if (trustee[0] == "Single") {
      if (n === index) {
        return trustee[1].public_key;
      }
      n++;
    } else {
      // Pedersen
      for (let j = 0; j < trustee[1].verification_keys.length; j++) {
        if (n === index) {
          return trustee[1].verification_keys[j].public_key;
        }
        n++;
      }
    }
  }

  return null;
}

export function ownerIndexToTrusteeIndex(trustees: t[]) {
  const ret = [
    ["Unused", -1, -1], // owners indexes start at 1, not 0
  ];
  for (let i = 0; i < trustees.length; i++) {
    const [type, content] = trustees[i];
    if (type === "Single") {
      ret.push(["Single", i, -1]);
    } else {
      for (let j = 0; j < content.coefexps.length; j++) {
        ret.push(["Pedersen", i, j]);
      }
    }
  }
  return ret;
}

export function generate(): [bigint, Single.Serialized.t] {
  const x = Z.randL();
  const w = Z.randL();
  const X = Point.g.multiply(x);
  const A = Point.g.multiply(w);

  const S = `Ed25519|${Point.serialize(X)}`;

  const nChallenge = Hpok(S, A);
  const nResponse = Z.modL(w - x * nChallenge);

  const publicKey: PublicKey.t = {
    pok: {
      nChallenge,
      nResponse,
    },
    public_key: X,
  };

  return [x, Single.toJSON(["Single", publicKey])];
}

export function combine_keys(trustees: t[]) {
  let pJointPublicKey = Point.zero;

  for (let i = 0; i < trustees.length; i++) {
    const trustee = trustees[i];
    if (trustee[0] === "Single") {
      pJointPublicKey = pJointPublicKey.add(trustee[1].public_key);
    } else {
      // "Pedersen"
      const coefexps = trustee[1].coefexps.map((o) => {
        return JSON.parse(o.message).coefexps[0];
      });
      let sum = Point.zero;
      for (let j = 0; j < coefexps.length; j++) {
        sum = sum.add(Point.parse(coefexps[j]));
      }
      pJointPublicKey = pJointPublicKey.add(sum);
    }
  }

  return pJointPublicKey;
}
