// @vitest-environment jsdom
// Browser-mode smoke test of the real entry point (mock data, no Tauri): the
// selectors the Playwright specs wait for must exist, and tab switching works
// through event delegation (there are no inline handlers any more).
import { describe, it, expect, beforeAll } from 'vitest';

async function settle(): Promise<void> {
    for (let i = 0; i < 5; i++) await new Promise((r) => setTimeout(r, 0));
}

describe('main.ts in browser mode', () => {
    beforeAll(async () => {
        document.body.innerHTML = '<div id="app"></div>';
        await import('./main');
        await settle();
    });

    it('renders the Monitor tab with the sidebar', () => {
        expect(document.querySelector('.sidebar')).not.toBeNull();
        expect(document.getElementById('tab-btn-monitor')?.getAttribute('aria-selected')).toBe('true');
        expect(document.querySelectorAll('.conn-card').length).toBe(2);
    });

    it('switches to Rules and back to Settings by click', async () => {
        (document.getElementById('tab-btn-rules') as HTMLElement).click();
        await settle();
        expect(document.querySelector('.rules-table')).not.toBeNull();
        expect(document.querySelectorAll('.rules-table tbody tr').length).toBe(2);

        (document.getElementById('tab-btn-settings') as HTMLElement).click();
        await settle();
        expect(document.querySelector('.settings-section')).not.toBeNull();
    });

    it('adds and deletes a rule from the Rules tab', async () => {
        (document.getElementById('tab-btn-rules') as HTMLElement).click();
        await settle();
        const app = document.getElementById('rule-app') as HTMLInputElement;
        app.value = '<img src=x onerror=alert(1)>';
        (document.getElementById('rule-form') as HTMLFormElement).requestSubmit();
        await settle();
        expect(document.querySelectorAll('.rules-table tbody tr').length).toBe(3);
        expect(document.querySelector('.rules-table img')).toBeNull();
        expect(document.querySelector('.rules-table')?.textContent).toContain('<img src=x onerror=alert(1)>');

        (document.querySelector('[data-action="delete-rule"]') as HTMLElement).click();
        await settle();
        expect(document.querySelectorAll('.rules-table tbody tr').length).toBe(2);
    });
});
