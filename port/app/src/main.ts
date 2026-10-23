import { invoke } from '@tauri-apps/api/core';
import { formatBytes } from './utils';
import { Rule } from './rules';

let currentTab = 'monitor';
let connectionsData: any[] = [];
let rulesData: Rule[] = [];
let dbData: string[] = [];

async function renderApp() {
    try {
        connectionsData = await invoke('get_connections');
        rulesData = await invoke('get_rules');
        dbData = await invoke('get_geoip_databases');

        updateUI();
    } catch (e) {
        console.error(e);
        document.getElementById('app')!.innerHTML = `<div>Error loading app data: ${e}</div>`;
    }
}

function updateUI() {
    const app = document.getElementById('app')!;

    // Group connections by service
    const groupedConns = connectionsData.reduce((acc, curr) => {
        const svc = curr.service_name || 'unknown';
        if (!acc[svc]) acc[svc] = [];
        acc[svc].push(curr);
        return acc;
    }, {} as Record<string, any[]>);

    let monitorHtml = `
        <div class="sidebar">
            <h3>Apps (by Service)</h3>
            <ul>
                ${Object.keys(groupedConns).map(svc => `
                    <li style="background: #1a1a1a; cursor: default; border-bottom: 1px solid #333; font-weight: bold;">${svc.toUpperCase()}</li>
                    ${groupedConns[svc].map((c: any) => `<li style="padding-left: 20px;">${c.conn.process.name} - ${formatBytes(c.conn.bytes_in || 0)} in / ${formatBytes(c.conn.bytes_out || 0)} out</li>`).join('')}
                `).join('')}
            </ul>
        </div>
        <div class="main-content">
            <h3>Inspector</h3>
            <div id="inspector">
                ${connectionsData.map(c => `
                    <div class="conn-card">
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
            <svg width="600" height="300" style="background: #242424; border: 1px solid #444; border-radius: 4px;">
                <rect width="100%" height="100%" fill="#1e1e1e" />
                <path d="M50 150 Q 150 50 300 150 T 550 150" fill="none" stroke="#4ade80" stroke-width="2" />
                <circle cx="50" cy="150" r="4" fill="#f87171" />
                <circle cx="300" cy="150" r="4" fill="#f87171" />
                <circle cx="550" cy="150" r="4" fill="#f87171" />
                <text x="300" y="140" text-anchor="middle" fill="#ccc" font-size="12">World Map (Offline SVG)</text>
            </svg>

            <div style="margin-top: 20px;">
                <button onclick="window.simulateAlert()" style="padding: 8px 16px; background: #f87171; color: white; border: none; border-radius: 4px; cursor: pointer;">Simulate Connection Alert Window</button>
            </div>
        </div>
    `;

    let rulesHtml = `
        <div class="sidebar">
            <h3>Profiles</h3>
            <ul>
                <li>Default Profile</li>
            </ul>
        </div>
        <div class="main-content">
            <h3>Rules Table</h3>
            <table class="rules-table">
                <thead>
                    <tr>
                        <th>App</th>
                        <th>Action</th>
                        <th>Remote</th>
                    </tr>
                </thead>
                <tbody>
                    ${rulesData.map(r => `
                        <tr>
                            <td>${r.app}</td>
                            <td class="${r.action === 'allow' ? 'text-green' : 'text-red'}">${r.action.toUpperCase()}</td>
                            <td>${r.remote}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    `;

    let settingsHtml = `
        <div class="main-content">
            <h3>Settings</h3>
            <div class="settings-section">
                <h4>GeoIP Databases</h4>
                <div style="display: flex; gap: 10px; margin-bottom: 10px;">
                    <select id="db-select" style="padding: 5px; background: #333; color: white; border: 1px solid #444;">
                        ${dbData.map(db => `<option value="${db}">${db}</option>`).join('')}
                    </select>
                    <button onclick="alert('Update Database trigger')" style="padding: 5px 10px; background: #333; color: white; border: 1px solid #444; cursor: pointer;">Update Database</button>
                    <button onclick="alert('Choose File trigger')" style="padding: 5px 10px; background: #333; color: white; border: 1px solid #444; cursor: pointer;">Choose File...</button>
                </div>
                <ul>
                    ${dbData.map(db => `<li>${db}</li>`).join('')}
                </ul>
            </div>
            <div class="settings-section">
                <h4>General</h4>
                <p>Monitor network traffic and manage connection rules.</p>
            </div>
        </div>
    `;

    app.innerHTML = `
        <div class="app-container">
            <div class="header">
                <h1>Rat Network Monitor</h1>
                <div class="tabs">
                    <button class="${currentTab === 'monitor' ? 'active' : ''}" onclick="window.switchTab('monitor')">Monitor</button>
                    <button class="${currentTab === 'rules' ? 'active' : ''}" onclick="window.switchTab('rules')">Rules</button>
                    <button class="${currentTab === 'settings' ? 'active' : ''}" onclick="window.switchTab('settings')">Settings</button>
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

(window as any).switchTab = (tab: string) => {
    currentTab = tab;
    updateUI();
};

(window as any).simulateAlert = async () => {
    try {
        await invoke('simulate_alert');
    } catch (e) {
        console.error("Failed to simulate alert:", e);
    }
};

renderApp();
