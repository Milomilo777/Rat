// @vitest-environment jsdom
import { describe, it, expect } from 'vitest';
import {
    renderMonitor,
    renderRules,
    renderSettings,
    renderAlert,
    renderBanner,
    renderShell,
    fmt,
    ConnectionView,
    AlertData,
} from './views';
import { raw } from './escape';
import { t } from './i18n';

const EVIL = '<img src=x onerror=alert(1)>';

function mount(html: string): HTMLElement {
    const root = document.createElement('div');
    root.innerHTML = html;
    return root;
}

/** No element created from data: no <img>, <script>, no on* attribute anywhere. */
function expectNoInjectedMarkup(root: HTMLElement): void {
    expect(root.querySelector('img')).toBeNull();
    expect(root.querySelector('script')).toBeNull();
    for (const el of Array.from(root.querySelectorAll('*'))) {
        for (const attr of Array.from(el.attributes)) {
            expect(attr.name.startsWith('on')).toBe(false);
        }
    }
}

const evilConn: ConnectionView = {
    conn: {
        process: { pid: 7, exe: EVIL, name: EVIL, user: EVIL },
        protocol: 'Tcp',
        local: EVIL,
        remote: EVIL,
        bytes_in: 1,
        bytes_out: 2,
    },
    process_behind: EVIL,
    network_owner: EVIL,
    vpn_mark: EVIL,
    proxy_mark: EVIL,
    service_name: EVIL,
};

describe('daemon-provided strings are rendered as text', () => {
    it('a process named like an <img> tag is text in the Monitor tab', () => {
        const root = mount(renderMonitor([evilConn], false).html);
        expectNoInjectedMarkup(root);
        // The literal text is visible to the user, in the sidebar and the card.
        expect(root.textContent).toContain(EVIL);
        expect(root.querySelector('.conn-card')?.textContent).toContain(EVIL);
        // The aria-label attribute carries it as an attribute value, not markup.
        expect(root.querySelector('.conn-card')?.getAttribute('aria-label')).toBe(
            `Connection from ${EVIL}`,
        );
    });

    it('rule fields are text in the Rules tab, and the delete button id is inert', () => {
        const evilId = '"><img src=x onerror=alert(1)>';
        const root = mount(
            renderRules([{ id: evilId, app: EVIL, action: 'deny', remote: EVIL }], true).html,
        );
        expectNoInjectedMarkup(root);
        expect(root.querySelector('.rules-table')?.textContent).toContain(EVIL);
        const del = root.querySelector<HTMLElement>('[data-action="delete-rule"]');
        expect(del?.dataset.id).toBe(evilId);
    });

    it('alert fields are text in the alert window', () => {
        const data: AlertData = {
            id: 1,
            alert: { app: EVIL, app_name: EVIL, host: EVIL, remote: '203.0.113.9:443', proto: 'Tcp' },
        };
        const root = mount(renderAlert(data).html);
        expectNoInjectedMarkup(root);
        expect(root.textContent).toContain(EVIL);
        // Static, translated markup of the template itself still works.
        expect(root.querySelector('strong')).not.toBeNull();
        expect(root.querySelectorAll('[data-action="answer"]').length).toBe(2);
    });

    it('status detail text from the OS or daemon is text in the banner', () => {
        const root = mount(
            renderBanner({ code: 'failed', detail: EVIL, demo: false }).html,
        );
        expectNoInjectedMarkup(root);
        expect(root.textContent).toContain(EVIL);
    });

    it('GeoIP database names are text in Settings', () => {
        const root = mount(renderSettings([EVIL]).html);
        expectNoInjectedMarkup(root);
        expect(root.querySelector('option')?.textContent).toBe(EVIL);
    });

    it('the whole shell with all data stays free of injected elements', () => {
        const root = mount(
            renderShell('monitor', renderMonitor([evilConn], true), {
                code: 'connected',
                detail: EVIL,
                demo: false,
            }).html,
        );
        expectNoInjectedMarkup(root);
    });

    it('no view uses inline event handlers or style attributes (strict CSP)', () => {
        const all = [
            renderShell('monitor', renderMonitor([evilConn], true), null).html,
            renderRules([{ id: '1', app: 'a', action: 'allow', remote: '*' }], true).html,
            renderSettings(['db']).html,
            renderAlert({
                id: 1,
                alert: { app: 'a', app_name: 'a', host: 'h', remote: '1.1.1.1:1', proto: 'Tcp' },
            }).html,
        ].join('');
        const root = mount(all);
        expect(root.querySelector('[style]')).toBeNull();
        expect(root.querySelector('[onclick]')).toBeNull();
    });
});

describe('fmt', () => {
    it('escapes text args, keeps Safe args and unknown placeholders', () => {
        const out = fmt('alert_wants_to_connect', {
            app: raw('<strong>X</strong>'),
            ip: EVIL,
        });
        const root = mount(out.html);
        expect(root.querySelector('strong')?.textContent).toBe('X');
        expect(root.querySelector('img')).toBeNull();
        expect(root.textContent).toContain(EVIL);
        // {port} was not given: stays visible as written.
        expect(root.textContent).toContain('{port}');
    });
});

describe('t() with special replacement patterns', () => {
    it('keeps "$&" and friends literal', () => {
        expect(t('alert_wants_to_connect', { app: '$&', ip: "$'", port: '$1' })).toContain("$& wants to connect to $' on port $1");
    });
});
