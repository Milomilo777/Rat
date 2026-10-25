/**
 * HTML escaping for everything that reaches the DOM.
 *
 * Daemon data (process names, paths, host names, rule fields) is untrusted:
 * a process can be called `<img src=x onerror=alert(1)>`. The `h` template
 * tag escapes every interpolated value unless it is a `Safe` fragment that
 * came out of another `h` template (or `raw`, for static markup written in
 * this code base). So a value can never turn into markup by accident.
 */

export class Safe {
    constructor(readonly html: string) {}
    toString(): string {
        return this.html;
    }
}

const ESCAPES: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;',
    '`': '&#96;',
};

/** Escape text for use in element content or a quoted attribute value. */
export function esc(value: unknown): string {
    return String(value ?? '').replace(/[&<>"'`]/g, (c) => ESCAPES[c]);
}

/** Mark static markup as already safe. Never pass daemon data to this. */
export function raw(html: string): Safe {
    return new Safe(html);
}

function part(v: unknown): string {
    if (v instanceof Safe) return v.html;
    if (Array.isArray(v)) return v.map(part).join('');
    return esc(v);
}

/** Tagged template: literal parts are markup, interpolations are escaped. */
export function h(strings: TemplateStringsArray, ...values: unknown[]): Safe {
    let out = strings[0];
    for (let i = 0; i < values.length; i++) {
        out += part(values[i]) + strings[i + 1];
    }
    return new Safe(out);
}
