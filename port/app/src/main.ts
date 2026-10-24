import { invoke } from '@tauri-apps/api/core';
import { formatBytes } from './utils';
import { Rule, getMockRules } from './rules';
import { t, setLocale, getLocale } from './i18n';

let currentTab = 'monitor';
let connectionsData: any[] = [];
let rulesData: Rule[] = [];
let dbData: string[] = [];

async function renderApp(): Promise<void> {
    const urlParams = new URLSearchParams(window.location.search);
    const lang = urlParams.get('lang');
    if (lang) {
        setLocale(lang);
    }

    if (getLocale() === 'ar-PSEUDO') {
        document.documentElement.dir = 'rtl';
    } else {
        document.documentElement.dir = 'ltr';
    }

    try {
        if (window.__TAURI__) {
            connectionsData = await invoke('get_connections');
            rulesData = await invoke('get_rules');
            dbData = await invoke('get_geoip_databases');
        } else {
            connectionsData = [
                {
                    conn: {
                        process: { pid: 1234, exe: '/usr/bin/firefox', name: 'firefox' },
                        protocol: 'Tcp', local: '127.0.0.1:54321', remote: '1.1.1.1:443', bytes_in: 1024, bytes_out: 2048
                    },
                    process_behind: 'via helper-process',
                    network_owner: 'Cloudflare, Inc. (ASN 13335)',
                    vpn_mark: 'WireGuard',
                    service_name: 'https'
                },
                {
                    conn: {
                        process: { pid: 5678, exe: '/usr/bin/curl', name: 'curl' },
                        protocol: 'Tcp', local: '192.168.1.5:12345', remote: '8.8.8.8:53', bytes_in: 512, bytes_out: 512
                    },
                    network_owner: 'Google LLC',
                    proxy_mark: 'SOCKS5 Proxy',
                    service_name: 'domain'
                }
            ];
            rulesData = getMockRules();
            dbData = ['dbip-asn-lite.mmdb'];
        }

        updateUI();
        setupKeyboardNavigation();
    } catch (e) {
        console.error(e);
        const app = document.getElementById('app');
        if (app) {
            app.innerHTML = `<div>${t('error_loading')} ${e}</div>`;
        }
    }
}

function updateUI() {
    const app = document.getElementById('app');
    if (!app) return;

    const groupedConns = connectionsData.reduce((acc, curr) => {
        const svc = curr.service_name || t('unknown');
        if (!acc[svc]) acc[svc] = [];
        acc[svc].push(curr);
        return acc;
    }, {} as Record<string, any[]>);

    const monitorHtml = `
        <div class="sidebar">
            <h2 id="apps-heading">${t('apps_by_service')}</h2>
            <ul aria-labelledby="apps-heading">
                ${Object.keys(groupedConns).map(svc => `
                    <li tabindex="0" style="background: var(--bg-color); cursor: default; border-bottom: 1px solid var(--border-color); font-weight: bold;">${svc.toUpperCase()}</li>
                    ${groupedConns[svc].map((c: any) => `<li tabindex="0" style="padding-inline-start: 20px;">${c.conn.process.name} - <bdi>${formatBytes(c.conn.bytes_in || 0)}</bdi> ${t('in')} / <bdi>${formatBytes(c.conn.bytes_out || 0)}</bdi> ${t('out')}</li>`).join('')}
                `).join('')}
            </ul>
        </div>
        <main class="main-content" aria-label="Monitor Content">
            <h2>${t('inspector')}</h2>
            <div id="inspector">
                ${connectionsData.map(c => `
                    <div class="conn-card" tabindex="0" aria-label="Connection from ${c.conn.process.name}">
                        <p><strong>${t('app')}:</strong> ${c.conn.process.name} (${t('pid')}: <bdi>${c.conn.process.pid}</bdi>)</p>
                        ${c.process_behind ? `<p><strong>${t('via')}:</strong> ${c.process_behind}</p>` : ''}
                        <p><strong>${t('local')}:</strong> <bdi>${c.conn.local}</bdi></p>
                        <p><strong>${t('remote')}:</strong> <bdi>${c.conn.remote || t('none')}</bdi></p>
                        ${c.network_owner ? `<p><strong>${t('network_owner')}:</strong> ${c.network_owner}</p>` : ''}
                        ${c.vpn_mark ? `<p><strong>${t('vpn')}:</strong> ${c.vpn_mark}</p>` : ''}
                        ${c.proxy_mark ? `<p><strong>${t('proxy')}:</strong> ${c.proxy_mark}</p>` : ''}
                        ${c.service_name ? `<p><strong>${t('service')}:</strong> ${c.service_name}</p>` : ''}
                    </div>
                `).join('')}
            </div>

            <h2>${t('world_map')}</h2>
            <svg role="img" aria-label="${t('world_map_svg')}" width="100%" height="300" tabindex="0" style="background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 4px;">
                <rect width="100%" height="100%" fill="var(--bg-color)" />
                <path d="M50 150 Q 150 50 300 150 T 550 150" fill="none" stroke="var(--accent-color)" stroke-width="2" />
                <circle cx="50" cy="150" r="4" fill="var(--btn-bg)" />
                <circle cx="300" cy="150" r="4" fill="var(--btn-bg)" />
                <circle cx="550" cy="150" r="4" fill="var(--btn-bg)" />
                <text x="50%" y="50%" text-anchor="middle" fill="var(--text-color)" font-size="12">${t('world_map_svg')}</text>
            </svg>

            <div style="margin-top: 20px;">
                <button aria-label="Simulate Alert Window" tabindex="0" onclick="window.simulateAlert()" style="padding: 8px 16px; background: var(--btn-bg); color: var(--btn-text); border: none; border-radius: 4px; cursor: pointer;">${t('simulate_alert')}</button>
            </div>
        </main>
    `;

    const rulesHtml = `
        <div class="sidebar">
            <h2 id="profiles-heading">${t('profiles')}</h2>
            <ul aria-labelledby="profiles-heading">
                <li tabindex="0">${t('default_profile')}</li>
            </ul>
        </div>
        <main class="main-content" aria-label="Rules Content">
            <h2>${t('rules_table')}</h2>
            <div style="overflow-x: auto;">
                <table class="rules-table" tabindex="0" aria-label="${t('rules_table')}">
                    <thead>
                        <tr>
                            <th scope="col">${t('app')}</th>
                            <th scope="col">${t('action')}</th>
                            <th scope="col">${t('remote')}</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${rulesData.map(r => `
                            <tr tabindex="0">
                                <td>${r.app}</td>
                                <td class="${r.action === 'allow' ? 'text-green' : 'text-red'}">${r.action === 'allow' ? t('allow') : t('deny')}</td>
                                <td><bdi>${r.remote}</bdi></td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            </div>
        </main>
    `;

    const settingsHtml = `
        <main class="main-content" aria-label="Settings Content">
            <h2>${t('settings')}</h2>
            <div class="settings-section">
                <h2 id="geoip-heading">${t('geoip_databases')}</h2>
                <div style="display: flex; gap: 10px; margin-bottom: 10px; flex-wrap: wrap;">
                    <label for="db-select" class="sr-only" style="display:none;">GeoIP Database Selection</label>
                    <select id="db-select" aria-label="GeoIP Database Selection" tabindex="0" style="padding: 5px; background: var(--input-bg); color: var(--text-color); border: 1px solid var(--border-color);">
                        ${dbData.map(db => `<option value="${db}">${db}</option>`).join('')}
                    </select>
                    <button tabindex="0" onclick="alert('${t('update_database')}')" style="padding: 5px 10px; background: var(--input-bg); color: var(--text-color); border: 1px solid var(--border-color); cursor: pointer;">${t('update_database')}</button>
                    <button tabindex="0" onclick="alert('${t('choose_file')}')" style="padding: 5px 10px; background: var(--input-bg); color: var(--text-color); border: 1px solid var(--border-color); cursor: pointer;">${t('choose_file')}</button>
                </div>
                <ul aria-labelledby="geoip-heading">
                    ${dbData.map(db => `<li tabindex="0">${db}</li>`).join('')}
                </ul>
            </div>
            <div class="settings-section" tabindex="0">
                <h2>${t('general')}</h2>
                <p>${t('general_desc')}</p>
            </div>
        </main>
    `;

    app.innerHTML = `
        <div class="app-container">
            <header class="header">
                <h1>${t('app_title')}</h1>
                <nav class="tabs" aria-label="Primary Navigation" role="tablist">
                    <button id="tab-btn-monitor" aria-controls="main-view" aria-selected="${currentTab === 'monitor'}" role="tab" tabindex="0" class="${currentTab === 'monitor' ? 'active' : ''}" onclick="window.switchTab('monitor')">${t('monitor')}</button>
                    <button id="tab-btn-rules" aria-controls="main-view" aria-selected="${currentTab === 'rules'}" role="tab" tabindex="0" class="${currentTab === 'rules' ? 'active' : ''}" onclick="window.switchTab('rules')">${t('rules')}</button>
                    <button id="tab-btn-settings" aria-controls="main-view" aria-selected="${currentTab === 'settings'}" role="tab" tabindex="0" class="${currentTab === 'settings' ? 'active' : ''}" onclick="window.switchTab('settings')">${t('settings')}</button>
                </nav>
            </header>
            <div id="main-view" class="content-area">
                ${currentTab === 'monitor' ? monitorHtml : ''}
                ${currentTab === 'rules' ? rulesHtml : ''}
                ${currentTab === 'settings' ? settingsHtml : ''}
            </div>
        </div>
    `;
}

function setupKeyboardNavigation() {
    document.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const active = document.activeElement as HTMLElement;
            if (active && typeof active.click === 'function') {
                active.click();
            }
        }
    });
}

(window as any).switchTab = (tab: string) => {
    currentTab = tab;
    updateUI();
};

(window as any).simulateAlert = async () => {
    try {
        if (window.__TAURI__) {
            await invoke('simulate_alert');
        } else {
            window.open('src/alert.html?lang=' + getLocale(), '_blank', 'width=450,height=250');
        }
    } catch (e) {
        console.error("Failed to simulate alert:", e);
    }
};

declare global {
    interface Window {
        __TAURI__: any;
    }
}

renderApp().catch((err) => {
    console.error('Initialization failed:', err);
});
