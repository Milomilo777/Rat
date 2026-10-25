// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import { esc, h, raw } from './escape';

const EVIL = '<img src=x onerror=alert(1)>';

describe('esc', () => {
    it('escapes the five HTML metacharacters and backtick', () => {
        expect(esc(`<>&"'\``)).toBe('&lt;&gt;&amp;&quot;&#39;&#96;');
    });
    it('turns null and undefined into an empty string', () => {
        expect(esc(null)).toBe('');
        expect(esc(undefined)).toBe('');
    });
    it('does not double-escape on a single pass', () => {
        expect(esc('&lt;')).toBe('&amp;lt;');
    });
});

describe('h', () => {
    it('escapes interpolated values but not the template literal', () => {
        expect(h`<b>${EVIL}</b>`.html).toBe('<b>&lt;img src=x onerror=alert(1)&gt;</b>');
    });
    it('keeps nested h fragments and arrays of them', () => {
        const items = ['a', EVIL].map((x) => h`<li>${x}</li>`);
        expect(h`<ul>${items}</ul>`.html).toBe(
            '<ul><li>a</li><li>&lt;img src=x onerror=alert(1)&gt;</li></ul>',
        );
    });
    it('escapes plain strings inside arrays', () => {
        expect(h`${[EVIL]}`.html).not.toContain('<img');
    });
    it('raw() is the only way to pass markup through', () => {
        expect(h`${raw('<i>x</i>')}`.html).toBe('<i>x</i>');
    });
    it('an attribute value cannot break out of its quotes', () => {
        const html = h`<div aria-label="${'x" onmouseover="alert(1)'}"></div>`.html;
        const div = document.createElement('div');
        div.innerHTML = html;
        const el = div.firstElementChild as HTMLElement;
        expect(el.getAttribute('aria-label')).toBe('x" onmouseover="alert(1)');
        expect(el.hasAttribute('onmouseover')).toBe(false);
    });
});
