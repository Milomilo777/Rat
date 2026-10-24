import { invoke } from '@tauri-apps/api/core';
import { formatBytes } from './utils';
import { Rule } from './rules';

let currentTab = 'monitor';
let connectionsData: any[] = [];
let rulesData: Rule[] = [];
let dbData: string[] = [];

async function renderApp() {
    try {
        // Run in browser with mock data if not in Tauri
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
            rulesData = [
                { id: '1', app: 'firefox', action: 'allow', remote: '1.1.1.1' },
                { id: '2', app: 'curl', action: 'deny', remote: '8.8.8.8' }
            ];
            dbData = ['dbip-asn-lite.mmdb'];
        }

        updateUI();
        setupKeyboardNavigation();
    } catch (e) {
        console.error(e);
        const app = document.getElementById('app');
        if (app) {
            app.innerHTML = `<div>Error loading app data: ${e}</div>`;
        }
    }
}

function updateUI() {
    const app = document.getElementById('app');
    if (!app) return;

    // Group connections by service
    const groupedConns = connectionsData.reduce((acc, curr) => {
        const svc = curr.service_name || 'unknown';
        if (!acc[svc]) acc[svc] = [];
        acc[svc].push(curr);
        return acc;
    }, {} as Record<string, any[]>);

    const monitorHtml = `
        <div class="sidebar">
            <h3>Apps (by Service)</h3>
            <ul>
                ${Object.keys(groupedConns).map(svc => `
                    <li tabindex="0" style="background: var(--bg-color); cursor: default; border-bottom: 1px solid var(--border-color); font-weight: bold;">${svc.toUpperCase()}</li>
                    ${groupedConns[svc].map((c: any) => `<li tabindex="0" style="padding-left: 20px;">${c.conn.process.name} - ${formatBytes(c.conn.bytes_in || 0)} in / ${formatBytes(c.conn.bytes_out || 0)} out</li>`).join('')}
                `).join('')}
            </ul>
        </div>
        <div class="main-content">
            <h3>Inspector</h3>
            <div id="inspector">
                ${connectionsData.map(c => `
                    <div class="conn-card" tabindex="0">
                        <p><strong>App:</strong> ${c.conn.process.name} (PID: ${c.conn.process.pid})</p>
                        ${c.process_behind ? `<p><strong>Via:</strong> ${c.process_behind}</p>` : ''}
                        <p><strong>Local:</strong> ${c.conn.local}</p>
                        <p><strong>Remote:</strong> ${c.conn.remote || 'None'}</p>
                        ${c.network_owner ? `<p><strong>Network Owner:</strong> ${c.network_owner}</p>` : ''}
                        ${c.vpn_mark ? `<p><strong>VPN:</strong> ${c.vpn_mark}</p>` : ''}
                        ${c.proxy_mark ? `<p><strong>Proxy:</strong> ${c.proxy_mark}</p>` : ''}
                        ${c.service_name ? `<p><strong>Service:</strong> ${c.service_name}</p>` : ''}
                    </div>
                `).join('')}
            </div>

            <h3>World Map</h3>
            <!-- Offline SVG Map Placeholder -->
            <svg width="600" height="300" tabindex="0" style="background: var(--bg-color); border: 1px solid var(--border-color); border-radius: 4px;">
                <rect width="100%" height="100%" fill="var(--bg-color)" />
                <path d="M50 150 Q 150 50 300 150 T 550 150" fill="none" stroke="var(--accent-color)" stroke-width="2" />
                <circle cx="50" cy="150" r="4" fill="var(--btn-bg)" />
                <circle cx="300" cy="150" r="4" fill="var(--btn-bg)" />
                <circle cx="550" cy="150" r="4" fill="var(--btn-bg)" />
                <text x="300" y="140" text-anchor="middle" fill="var(--text-color)" font-size="12">World Map (Offline SVG)</text>
            </svg>

            <div style="margin-top: 20px;">
                <button tabindex="0" onclick="window.simulateAlert()" style="padding: 8px 16px; background: var(--btn-bg); color: var(--btn-text); border: none; border-radius: 4px; cursor: pointer;">Simulate Connection Alert Window</button>
            </div>
        </div>
    `;

    const rulesHtml = `
        <div class="sidebar">
            <h3>Profiles</h3>
            <ul>
                <li tabindex="0">Default Profile</li>
            </ul>
        </div>
        <div class="main-content">
            <h3>Rules Table</h3>
            <table class="rules-table" tabindex="0">
                <thead>
                    <tr>
                        <th>App</th>
                        <th>Action</th>
                        <th>Remote</th>
                    </tr>
                </thead>
                <tbody>
                    ${rulesData.map(r => `
                        <tr tabindex="0">
                            <td>${r.app}</td>
                            <td class="${r.action === 'allow' ? 'text-green' : 'text-red'}">${r.action.toUpperCase()}</td>
                            <td>${r.remote}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;

    const settingsHtml = `
        <div class="main-content">
            <h3>Settings</h3>
            <div class="settings-section">
                <h4>GeoIP Databases</h4>
                <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                    <select id="db-select" tabindex="0" style="padding: 5px; background: var(--input-bg); color: var(--text-color); border: 1px solid var(--border-color);">
                        ${dbData.map(db => `<option value="${db}">${db}</option>`).join('')}
                    </select>
                    <button tabindex="0" onclick="alert('Update Database trigger')" style="padding: 5px 10px; background: var(--input-bg); color: var(--text-color); border: 1px solid var(--border-color); cursor: pointer;">Update Database</button>
                    <button tabindex="0" onclick="alert('Choose File trigger')" style="padding: 5px 10px; background: var(--input-bg); color: var(--text-color); border: 1px solid var(--border-color); cursor: pointer;">Choose File...</button>
                </div>
                <ul>
                    ${dbData.map(db => `<li tabindex="0">${db}</li>`).join('')}
                </ul>
            </div>
            <div class="settings-section" tabindex="0">
                <h4>General</h4>
                <p>Monitor network traffic and manage connection rules.</p>
            </div>
        </div>
    `;

    app.innerHTML = `
        <div class="app-container">
            <div class="header">
                <h1>Rat Network Monitor</h1>
                <div class="tabs" role="tablist">
                    <button id="tab-btn-monitor" role="tab" tabindex="0" class="${currentTab === 'monitor' ? 'active' : ''}" onclick="window.switchTab('monitor')">Monitor</button>
                    <button id="tab-btn-rules" role="tab" tabindex="0" class="${currentTab === 'rules' ? 'active' : ''}" onclick="window.switchTab('rules')">Rules</button>
                    <button id="tab-btn-settings" role="tab" tabindex="0" class="${currentTab === 'settings' ? 'active' : ''}" onclick="window.switchTab('settings')">Settings</button>
                </div>
            </div>
            <div class="content-area">
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
            window.open('src/alert.html', '_blank', 'width=450,height=250');
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

// Fix SonarCloud: encapsulate in async IIFE
(async () => {
    await renderApp();
})();
