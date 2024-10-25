import { greet } from '../src/index';

describe('Greet Function', () => {
  it('should greet the person with the provided name', () => {
    expect(greet('World')).toBe('Hello, World!');
  });
});
