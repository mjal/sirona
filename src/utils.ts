export const assert = console.assert;

export const map2 = (a: any, fn: any) => a.map((b: any) => b.map(fn));
export const map3 = (a: any, fn: any) => a.map((b: any) => map2(b, fn));

export async function _async(f: any, ...args: any) {
  return new Promise((resolve, _reject) => {
    setTimeout(() => {
      const res = f(...args);
      resolve(res);
    }, 0);
  });
}

export function error(str: string) {
  throw new Error(str);
}

export function readStdin() {
  return new Promise((resolve, reject) => {
    let data = "";

    process.stdin.on("data", (chunk) => {
      data += chunk;
    });

    process.stdin.on("end", () => {
      resolve(data);
    });

    process.stdin.on("error", (err) => {
      reject(err);
    });
  });
}
