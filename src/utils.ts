export const assert = console.assert;
export const range = (min: number, max?: number) : number[] => {
  if (max === undefined) {
    max = min - 1;
    min = 0;
  }
  return Array.from({ length: max - min + 1 }).map(
    (_, i) => i + min,
  );
}

export const map2 = (a: any, fn: any) => a.map((b: any) => b.map(fn));
export const map3 = (a: any, fn: any) => a.map((b: any) => map2(b, fn));

export async function _async(f: any, ...args: any) {
  return new Promise((resolve, reject) => {
    setTimeout(() => {
      try {
        const res = f(...args);
        resolve(res);
      } catch (e) {
        reject(e);
      }
    }, 0);
  });
}

export function error(str: string) {
  throw new Error(str);
}

export function readStdin(): Promise<string> {
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

export const b58chars = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
