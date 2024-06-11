export const assert = console.assert;

export async function _async(f, ...args) {
  return new Promise((resolve, _reject) => {
    requestAnimationFrame(() => {
      const res = f(...args);
      resolve(res);
    });
  });
}
