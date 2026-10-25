import { invoke, isTauri } from '@tauri-apps/api/core';
import { Rule, getMockRules } from './rules';
import { t, setLocale, getLocale } from './i18n';
import {
    ConnectionView,
    DaemonStatus,
    Tab,
    renderBanner,
    renderError,
    renderMonitor,
    renderRules,
    renderSettings,
    renderShell,
} from './views';

const POLL_MS = 2000;

let currentTab: Tab = 'monitor';
let connectionsData: ConnectionView[] = [];
let rulesData: Rule[] = [];
let dbData: string[] = [];
let statusData: DaemonStatus | null = null;
let lastSignature = '';

const inTauri = (): boolean => {
    try {
        return isTauri();
    } catch {
        return false;
    }
};

const MOCK_CONNECTIONS: ConnectionView[] = [
    {
        conn: {
            process: { pid: 1234, exe: '/usr/bin/firefox', name: 'firefox' },
            protocol: 'Tcp', local: '127.0.0.1:54321', remote: '1.1.1.1:443', bytes_in: 1024, bytes_out: 2048,
        },
        process_behind: 'via helper-process',
        network_owner: 'Cloudflare, Inc. (ASN 13335)',
        vpn_mark: 'WireGuard',
        service_name: 'https',
    },
    {
        conn: {
            process: { pid: 5678, exe: '/usr/bin/curl', name: 'curl' },
            protocol: 'Tcp', local: '192.168.1.5:12345', remote: '8.8.8.8:53', bytes_in: 512, bytes_out: 512,
        },
        network_owner: 'Google LLC',
        proxy_mark: 'SOCKS5 Proxy',
        service_name: 'domain',
    },
];

/** Fetch everything the views need. Browser (no Tauri) shows static mock data. */
async function loadData(): Promise<void> {
    if (inTauri()) {
        const [conns, rules, dbs, status] = await Promise.all([
            invoke<ConnectionView[]>('get_connections'),
            invoke<Rule[]>('get_rules').catch((e) => {
                console.error('get_rules failed:', e);
                return rulesData;
            }),
            invoke<string[]>('get_geoip_databases'),
            invoke<DaemonStatus>('get_status'),
        ]);
        connectionsData = conns;
        rulesData = rules;
        dbData = dbs;
        statusData = status;
    } else if (lastSignature === '') {
        connectionsData = MOCK_CONNECTIONS;
        rulesData = getMockRules();
        dbData = ['dbip-asn-lite.mmdb'];
        statusData = null;
    }
}

function showSimulate(): boolean {
    return !inTauri() || statusData?.demo === true;
}

function viewHtml() {
    switch (currentTab) {
        case 'rules':
            return renderRules(rulesData, true);
        case 'settings':
            return renderSettings(dbData);
        default:
            return renderMonitor(connectionsData, showSimulate());
    }
}

/** Is the user typing in the rule form? Then a poll must not wipe it. */
function editing(): boolean {
    const form = document.getElementById('rule-form');
    return !!form && form.contains(document.activeElement);
}

function renderAll(): void {
    const app = document.getElementById('app');
    if (!app) return;
    app.innerHTML = renderShell(currentTab, viewHtml(), statusData).html;
}

/** Re-render only the parts that changed (keeps focus and scroll otherwise). */
function refreshView(): void {
    const signature = JSON.stringify([connectionsData, rulesData, dbData, statusData, currentTab]);
    if (signature === lastSignature) return;
    lastSignature = signature;
    const slot = document.getElementById('banner-slot');
    const main = document.getElementById('main-view');
    if (!slot || !main) {
        renderAll();
        return;
    }
    slot.innerHTML = renderBanner(statusData).html;
    if (!editing()) main.innerHTML = viewHtml().html;
}

async function poll(): Promise<void> {
    try {
        await loadData();
        refreshView();
    } catch (e) {
        console.error(e);
        const app = document.getElementById('app');
        if (app) app.innerHTML = renderError(e).html;
        lastSignature = '';
    }
}

async function renderApp(): Promise<void> {
    const lang = new URLSearchParams(window.location.search).get('lang');
    if (lang) {
        setLocale(lang);
    }
    document.documentElement.dir = getLocale() === 'ar-PSEUDO' ? 'rtl' : 'ltr';

    try {
        await loadData();
        lastSignature = '';
        renderAll();
        lastSignature = JSON.stringify([connectionsData, rulesData, dbData, statusData, currentTab]);
    } catch (e) {
        console.error(e);
        const app = document.getElementById('app');
        if (app) app.innerHTML = renderError(e).html;
    }
    setupEvents();
    if (inTauri()) {
        window.setInterval(() => void poll(), POLL_MS);
    }
}

function switchTab(tab: Tab): void {
    currentTab = tab;
    lastSignature = '';
    renderAll();
    lastSignature = JSON.stringify([connectionsData, rulesData, dbData, statusData, currentTab]);
}

async function simulateAlert(): Promise<void> {
    try {
        if (inTauri()) {
            await invoke('simulate_alert');
        } else {
            window.open('src/alert.html?lang=' + getLocale(), '_blank', 'width=450,height=250');
        }
    } catch (e) {
        console.error('Failed to simulate alert:', e);
    }
}

async function deleteRule(id: string): Promise<void> {
    try {
        if (inTauri()) {
            rulesData = await invoke<Rule[]>('delete_rule', { id });
        } else {
            rulesData = rulesData.filter((r) => r.id !== id);
        }
        lastSignature = '';
        refreshView();
    } catch (e) {
        window.alert(`${t('rule_failed')} ${String(e)}`);
    }
}

async function addRule(form: HTMLFormElement): Promise<void> {
    const data = new FormData(form);
    const rule = {
        app: String(data.get('app') ?? '').trim(),
        action: String(data.get('action') ?? 'allow'),
        remote: String(data.get('remote') ?? '').trim(),
    };
    try {
        if (inTauri()) {
            rulesData = await invoke<Rule[]>('add_rule', { rule });
        } else {
            rulesData = [
                ...rulesData,
                { id: String(Date.now()), app: rule.app, action: rule.action as Rule['action'], remote: rule.remote || '*' },
            ];
        }
        form.reset();
        lastSignature = '';
        refreshView();
    } catch (e) {
        window.alert(`${t('rule_failed')} ${String(e)}`);
    }
}

function setupEvents(): void {
    document.addEventListener('click', (ev) => {
        const target = (ev.target as Element | null)?.closest<HTMLElement>('[data-action]');
        if (!target) return;
        switch (target.dataset.action) {
            case 'switch-tab':
                switchTab((target.dataset.tab as Tab) ?? 'monitor');
                break;
            case 'simulate-alert':
                void simulateAlert();
                break;
            case 'delete-rule':
                void deleteRule(target.dataset.id ?? '');
                break;
            case 'update-db':
                window.alert(t('update_database'));
                break;
            case 'choose-file':
                window.alert(t('choose_file'));
                break;
        }
    });

    document.addEventListener('submit', (ev) => {
        const form = ev.target as HTMLFormElement | null;
        if (form?.id === 'rule-form') {
            ev.preventDefault();
            void addRule(form);
        }
    });

    // Enter activates focusable non-form elements (list items, cards). Native
    // buttons, links and fields already handle Enter: clicking them again
    // would run their action twice.
    document.addEventListener('keydown', (e) => {
        if (e.key !== 'Enter') return;
        const active = document.activeElement as HTMLElement | null;
        if (!active || ['BUTTON', 'INPUT', 'SELECT', 'TEXTAREA', 'A'].includes(active.tagName)) return;
        if (typeof active.click === 'function') active.click();
    });
}

renderApp().catch((err) => {
    console.error('Initialization failed:', err);
});
