import { describe, it, expect } from 'vitest';
import { sortRules, filterRules, Rule } from './rules';

describe('sortRules', () => {
  const rules: Rule[] = [
    { id: '1', app: 'Firefox', action: 'allow', remote: '1.1.1.1' },
    { id: '2', app: 'Chrome', action: 'deny', remote: '8.8.8.8' },
  ];

  it('sorts ascending', () => {
    const sorted = sortRules(rules, 'app', true);
    expect(sorted[0].app).toBe('Chrome');
  });

  it('sorts descending', () => {
    const sorted = sortRules(rules, 'app', false);
    expect(sorted[0].app).toBe('Firefox');
  });
});

describe('filterRules', () => {
  const rules: Rule[] = [
    { id: '1', app: 'Firefox', action: 'allow', remote: '1.1.1.1' },
    { id: '2', app: 'Chrome', action: 'deny', remote: '8.8.8.8' },
  ];

  it('filters by app', () => {
    const filtered = filterRules(rules, 'fire');
    expect(filtered.length).toBe(1);
    expect(filtered[0].app).toBe('Firefox');
  });

  it('filters by remote', () => {
    const filtered = filterRules(rules, '8.8');
    expect(filtered.length).toBe(1);
    expect(filtered[0].app).toBe('Chrome');
  });
});
