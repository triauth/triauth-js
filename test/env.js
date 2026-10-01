// Runtime-lane helpers shared by the test files.
export const isNode = typeof window === 'undefined';
export const itNode = isNode ? it : it.skip;
export const describeNode = isNode ? describe : describe.skip;
