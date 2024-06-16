export const assert = console.assert;

export const map2 = (a, fn) => a.map(b => b.map(fn));
export const map3 = (a, fn) => a.map(b => map2(b, fn));

export async function _async(f, ...args) {
  return new Promise((resolve, _reject) => {
    setTimeout(() => {
      const res = f(...args);
      resolve(res);
    }, 0);
  });
}
