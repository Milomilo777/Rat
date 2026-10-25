import { invoke, isTauri } from '@tauri-apps/api/core';
import { t, setLocale, getLocale } from './i18n';
import { AlertData, renderAlert } from './views';

const POLL_MS = 1000;
/** Polls with no pending alert before the window closes itself. */
const EMPTY_POLLS_BEFORE_CLOSE = 3;

const inTauri = (): boolean => {
    try {
        return isTauri();
    } catch {
        return false;
    }
};

const MOCK_ALERT: AlertData = {
    id: 0,
    alert: { app: '/usr/bin/firefox', app_name: 'Firefox', host: '1.1.1.1', remote: '1.1.1.1:443', proto: 'Tcp' },
};

const lang = new URLSearchParams(window.location.search).get('lang');
if (lang) {
    setLocale(lang);
}
const isRtl = getLocale() === 'ar-PSEUDO';
document.documentElement.dir = isRtl ? 'rtl' : 'ltr';
document.documentElement.lang = isRtl ? 'ar' : 'en';
document.title = t('alert_title');

const app = document.getElementById('app') as HTMLElement;
let shownId: number | null = null;
let emptyPolls = 0;

function show(data: AlertData | null): void {
    // Re-render only when the alert changed, so the user's choices in the
    // dropdowns survive the poll.
    const id = data ? data.id : null;
    if (id === shownId && app.innerHTML !== '') return;
    shownId = id;
    app.innerHTML = renderAlert(data).html;
}

async function poll(): Promise<void> {
    try {
        const data = inTauri() ? await invoke<AlertData | null>('get_pending_alert') : MOCK_ALERT;
        show(data);
        emptyPolls = data ? 0 : emptyPolls + 1;
        if (inTauri() && emptyPolls >= EMPTY_POLLS_BEFORE_CLOSE) {
            await invoke('close_alert');
        }
    } catch (e) {
        console.error(e);
    }
}

function showError(message: string): void {
    let el = document.getElementById('alert-error');
    if (!el) {
        el = document.createElement('p');
        el.id = 'alert-error';
        el.className = 'error';
        el.setAttribute('role', 'alert');
        app.appendChild(el);
    }
    el.textContent = message;
}

async function answer(verdict: string): Promise<void> {
    if (shownId === null) return;
    const scope = (document.getElementById('scope') as HTMLSelectElement).value;
    const lifetime = (document.getElementById('timeout') as HTMLSelectElement).value;
    try {
        if (inTauri()) {
            // Rust closes this window once the daemon accepted the answer.
            await invoke('answer_alert', { id: shownId, verdict, scope, lifetime });
        } else {
            window.close();
        }
    } catch (e) {
        showError(`${t('alert_answer_failed')} ${String(e)}`);
    }
}

document.addEventListener('click', (ev) => {
    const target = (ev.target as Element | null)?.closest<HTMLElement>('[data-action="answer"]');
    if (target) void answer(target.dataset.verdict ?? 'deny');
});

document.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const active = document.activeElement as HTMLElement | null;
    if (!active || ['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'A'].includes(active.tagName)) return;
    if (typeof active.click === 'function') active.click();
});

void poll();
if (inTauri()) {
    window.setInterval(() => void poll(), POLL_MS);
}
