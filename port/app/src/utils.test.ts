import { describe, it, expect } from 'vitest';
import { formatBytes, formatRate, formatDuration } from './utils';

describe('formatBytes', () => {
  it('formats zero correctly', () => expect(formatBytes(0)).toBe('0 B'));
  it('formats bytes correctly', () => expect(formatBytes(500)).toBe('500 B'));
  it('formats kilobytes correctly', () => expect(formatBytes(1536)).toBe('1.5 KB'));
  it('formats megabytes correctly', () => expect(formatBytes(1572864)).toBe('1.5 MB'));
});

describe('formatRate', () => {
  it('adds /s to formatted bytes', () => expect(formatRate(1536)).toBe('1.5 KB/s'));
});

describe('formatDuration', () => {
  it('formats milliseconds', () => expect(formatDuration(500)).toBe('500ms'));
  it('formats seconds', () => expect(formatDuration(1500)).toBe('1s'));
  it('formats minutes', () => expect(formatDuration(125000)).toBe('2m'));
});
