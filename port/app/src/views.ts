// Pure renderers: data in, HTML string out. Every value goes through the `h`
// template (escaped); there are no inline event handlers or style attributes,
// so the strict CSP in tauri.conf.json holds. Behaviour is wired in main.ts
// with event delegation on `data-action` attributes.

import { h, raw, Safe } from './escape';
import { t } from './i18n';
import { formatBytes } from './utils';
import type { Rule } from './rules';

export interface ConnectionView {
    conn: {
        process: { pid: number; exe?: string | null; name: string; user?: string | null };
        protocol: string;
        local: string;
        remote?: string | null;
        listening?: boolean;
        bytes_in?: number | null;
        bytes_out?: number | null;
    };
    process_behind?: string | null;
    network_owner?: string | null;
    vpn_mark?: string | null;
    proxy_mark?: string | null;
    service_name?: string | null;
}

export type StatusCode =
    | 'connecting'
    | 'connected'
    | 'not_running'
    | 'access_denied'
    | 'protocol_mismatch'
    | 'failed';

export interface DaemonStatus {
    code: StatusCode;
    detail?: string | null;
    demo: boolean;
}

export interface AlertData {
    id: number;
    alert: {
        app: string;
        app_name: string;
        host: string;
        remote: string;
        proto: string;
    };
}

export type Tab = 'monitor' | 'rules' | 'settings';

/** Fill `{name}` placeholders of a translation with Safe fragments or text. */
export function fmt(key: Parameters<typeof t>[0], args: Record<string, Safe | string>): Safe {
    const template = t(key);
    const out: Array<Safe | string> = [];
    let rest = template;
    while (rest.length > 0) {
        const open = rest.indexOf('{');
        const close = open === -1 ? -1 : rest.indexOf('}', open);
        if (open === -1 || close === -1) {
            out.push(rest);
            break;
        }
        const name = rest.slice(open + 1, close);
        out.push(rest.slice(0, open));
        out.push(Object.prototype.hasOwnProperty.call(args, name) ? args[name] : rest.slice(open, close + 1));
        rest = rest.slice(close + 1);
    }
    return h`${out}`;
}

export function statusMessageKey(code: StatusCode): Parameters<typeof t>[0] | null {
    switch (code) {
        case 'connected':
            return null;
        case 'connecting':
            return 'status_connecting';
        case 'not_running':
            return 'status_not_running';
        case 'access_denied':
            return 'status_access_denied';
        case 'protocol_mismatch':
            return 'status_protocol_mismatch';
        default:
            return 'status_failed';
    }
}

export function renderBanner(status: DaemonStatus | null): Safe {
    if (!status) return raw('');
    if (status.demo) {
        return h`<div class="banner banner-demo" role="status">${t('status_demo')}</div>`;
    }
    const key = statusMessageKey(status.code);
    if (!key) return raw('');
    return h`<div class="banner banner-${status.code}" role="status">${t(key)}${
        status.detail ? h` <small><bdi>${status.detail}</bdi></small>` : ''
    }</div>`;
}

function renderConnectionCard(c: ConnectionView): Safe {
    const p = c.conn.process;
    return h`
        <div class="conn-card" tabindex="0" aria-label="Connection from ${p.name}">
            <p><strong>${t('app')}:</strong> ${p.name} (${t('pid')}: <bdi>${p.pid}</bdi>)</p>
            ${c.process_behind ? h`<p><strong>${t('via')}:</strong> ${c.process_behind}</p>` : ''}
            <p><strong>${t('local')}:</strong> <bdi>${c.conn.local}</bdi></p>
            <p><strong>${t('remote')}:</strong> <bdi>${c.conn.remote || (c.conn.listening ? t('listening') : t('none'))}</bdi></p>
            ${c.network_owner ? h`<p><strong>${t('network_owner')}:</strong> ${c.network_owner}</p>` : ''}
            ${c.vpn_mark ? h`<p><strong>${t('vpn')}:</strong> ${c.vpn_mark}</p>` : ''}
            ${c.proxy_mark ? h`<p><strong>${t('proxy')}:</strong> ${c.proxy_mark}</p>` : ''}
            ${c.service_name ? h`<p><strong>${t('service')}:</strong> ${c.service_name}</p>` : ''}
        </div>`;
}

export function renderMonitor(connections: ConnectionView[], showSimulate: boolean): Safe {
    const groups = new Map<string, ConnectionView[]>();
    for (const c of connections) {
        const svc = c.service_name || t('unknown');
        const list = groups.get(svc);
        if (list) list.push(c);
        else groups.set(svc, [c]);
    }
    return h`
        <div class="sidebar">
            <h2 id="apps-heading">${t('apps_by_service')}</h2>
            <ul aria-labelledby="apps-heading">
                ${[...groups].map(([svc, list]) => h`
                    <li tabindex="0" class="group-head">${svc.toUpperCase()}</li>
                    ${list.map((c) => h`<li tabindex="0" class="group-item">${c.conn.process.name} - <bdi>${formatBytes(c.conn.bytes_in || 0)}</bdi> ${t('in')} / <bdi>${formatBytes(c.conn.bytes_out || 0)}</bdi> ${t('out')}</li>`)}
                `)}
            </ul>
        </div>
        <main class="main-content" aria-label="Monitor Content">
            <h2>${t('inspector')}</h2>
            <div id="inspector">
                ${connections.length === 0 ? h`<p>${t('no_connections')}</p>` : ''}
                ${connections.map(renderConnectionCard)}
            </div>

            <h2>${t('world_map')}</h2>
            <svg class="world-map" role="img" aria-label="${t('world_map_svg')}" width="100%" height="300" tabindex="0">
                <rect width="100%" height="100%" fill="var(--bg-color)" />
                <path d="M50 150 Q 150 50 300 150 T 550 150" fill="none" stroke="var(--accent-color)" stroke-width="2" />
                <circle cx="50" cy="150" r="4" fill="var(--btn-bg)" />
                <circle cx="300" cy="150" r="4" fill="var(--btn-bg)" />
                <circle cx="550" cy="150" r="4" fill="var(--btn-bg)" />
                <text x="50%" y="50%" text-anchor="middle" fill="var(--text-color)" font-size="12">${t('world_map_svg')}</text>
            </svg>

            ${showSimulate ? h`
            <div class="actions-row">
                <button class="btn-primary" aria-label="Simulate Alert Window" tabindex="0" data-action="simulate-alert">${t('simulate_alert')}</button>
            </div>` : ''}
        </main>
    `;
}

function actionCell(action: string): Safe {
    if (action === 'allow') return h`<td class="text-green">${t('allow')}</td>`;
    if (action === 'ask') return h`<td>${t('ask')}</td>`;
    return h`<td class="text-red">${t('deny')}</td>`;
}

export function renderRules(rules: Rule[], canEdit: boolean): Safe {
    return h`
        <div class="sidebar">
            <h2 id="profiles-heading">${t('profiles')}</h2>
            <ul aria-labelledby="profiles-heading">
                <li tabindex="0">${t('default_profile')}</li>
            </ul>
        </div>
        <main class="main-content" aria-label="Rules Content">
            <h2>${t('rules_table')}</h2>
            <div class="table-wrap">
                <table class="rules-table" tabindex="0" aria-label="${t('rules_table')}">
                    <thead>
                        <tr>
                            <th scope="col">${t('app')}</th>
                            <th scope="col">${t('action')}</th>
                            <th scope="col">${t('remote')}</th>
                            ${canEdit ? h`<th scope="col"><span class="sr-only">${t('delete_rule')}</span></th>` : ''}
                        </tr>
                    </thead>
                    <tbody>
                        ${rules.map((r) => h`
                            <tr tabindex="0">
                                <td><bdi>${r.app}</bdi></td>
                                ${actionCell(r.action)}
                                <td><bdi>${r.remote}</bdi></td>
                                ${canEdit ? h`<td><button class="btn-small" data-action="delete-rule" data-id="${r.id}" aria-label="${t('delete_rule')} ${r.app}">${t('delete_rule')}</button></td>` : ''}
                            </tr>
                        `)}
                    </tbody>
                </table>
            </div>
            ${rules.length === 0 ? h`<p>${t('no_rules')}</p>` : ''}
            ${canEdit ? h`
            <form id="rule-form" class="rule-form settings-section">
                <label for="rule-app">${t('rule_app_path')}</label>
                <input id="rule-app" name="app" type="text" required maxlength="1024" autocomplete="off" spellcheck="false" />
                <label for="rule-action">${t('action')}</label>
                <select id="rule-action" name="action">
                    <option value="allow">${t('allow')}</option>
                    <option value="deny">${t('deny')}</option>
                </select>
                <label for="rule-remote">${t('rule_remote_hint')}</label>
                <input id="rule-remote" name="remote" type="text" maxlength="253" autocomplete="off" spellcheck="false" />
                <button type="submit" class="btn-primary">${t('add_rule')}</button>
            </form>` : ''}
        </main>
    `;
}

export function renderSettings(dbs: string[]): Safe {
    return h`
        <main class="main-content" aria-label="Settings Content">
            <h2>${t('settings')}</h2>
            <div class="settings-section">
                <h2 id="geoip-heading">${t('geoip_databases')}</h2>
                <div class="toolbar">
                    <select id="db-select" aria-label="GeoIP Database Selection" tabindex="0">
                        ${dbs.map((db) => h`<option value="${db}">${db}</option>`)}
                    </select>
                    <button class="btn-small" tabindex="0" data-action="update-db">${t('update_database')}</button>
                    <button class="btn-small" tabindex="0" data-action="choose-file">${t('choose_file')}</button>
                </div>
                <ul aria-labelledby="geoip-heading">
                    ${dbs.map((db) => h`<li tabindex="0">${db}</li>`)}
                </ul>
            </div>
            <div class="settings-section" tabindex="0">
                <h2>${t('general')}</h2>
                <p>${t('general_desc')}</p>
            </div>
        </main>
    `;
}

export function renderShell(tab: Tab, inner: Safe, status: DaemonStatus | null): Safe {
    const tabButton = (id: Tab, label: string) =>
        h`<button id="tab-btn-${id}" aria-controls="main-view" aria-selected="${tab === id}" role="tab" tabindex="0" class="${tab === id ? 'active' : ''}" data-action="switch-tab" data-tab="${id}">${label}</button>`;
    return h`
        <div class="app-container">
            <header class="header">
                <h1>${t('app_title')}</h1>
                <nav class="tabs" aria-label="Primary Navigation" role="tablist">
                    ${tabButton('monitor', t('monitor'))}
                    ${tabButton('rules', t('rules'))}
                    ${tabButton('settings', t('settings'))}
                </nav>
            </header>
            <div id="banner-slot">${renderBanner(status)}</div>
            <div id="main-view" class="content-area">
                ${inner}
            </div>
        </div>
    `;
}

export function renderError(e: unknown): Safe {
    return h`<div class="banner banner-failed" role="alert">${t('error_loading')} ${String(e)}</div>`;
}

/** The alert window body. `null` = nothing pending (or not loaded yet). */
export function renderAlert(data: AlertData | null): Safe {
    if (!data) {
        return h`<div class="header"><p tabindex="0">${t('alert_none')}</p></div>`;
    }
    const a = data.alert;
    const lastColon = a.remote.lastIndexOf(':');
    const ip = lastColon === -1 ? a.remote : a.remote.slice(0, lastColon).replace(/^\[|\]$/g, '');
    const port = lastColon === -1 ? '' : a.remote.slice(lastColon + 1);
    return h`
        <div class="header">
          <h1 tabindex="0">${t('alert_blocked')}</h1>
          <p tabindex="0">${fmt('alert_wants_to_connect', {
              app: h`<strong>${a.app_name}</strong>`,
              ip: h`<bdi><strong>${a.host && a.host !== ip ? `${a.host} (${ip})` : ip}</strong></bdi>`,
              port: h`<bdi>${port}</bdi>`,
          })}</p>
          <p class="path" tabindex="0"><bdi>${a.app}</bdi></p>
        </div>

        <div class="options">
          <div class="field">
            <label for="scope">${t('scope')}</label>
            <select id="scope" tabindex="0">
              <option value="any">${t('any_connection')}</option>
              <option value="domain">${t('this_domain')}</option>
              <option value="host">${t('this_ip')}</option>
              <option value="port">${t('this_port')}</option>
            </select>
          </div>
          <div class="field">
            <label for="timeout">${t('timeout')}</label>
            <select id="timeout" tabindex="0">
              <option value="forever">${t('forever')}</option>
              <option value="untilQuit">${t('until_quit')}</option>
              <option value="once">${t('once')}</option>
            </select>
          </div>
        </div>

        <div class="actions">
          <button class="btn-allow" tabindex="0" data-action="answer" data-verdict="allow">${t('btn_allow')}</button>
          <button class="btn-deny" tabindex="0" data-action="answer" data-verdict="deny">${t('btn_deny')}</button>
        </div>
    `;
}
