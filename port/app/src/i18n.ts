export const messages = {
  en: {
    app_title: "Rat Network Monitor",
    monitor: "Monitor",
    rules: "Rules",
    settings: "Settings",
    apps_by_service: "Apps (by Service)",
    inspector: "Inspector",
    app: "App",
    pid: "PID",
    via: "Via",
    local: "Local",
    remote: "Remote",
    network_owner: "Network Owner",
    vpn: "VPN",
    proxy: "Proxy",
    service: "Service",
    none: "None",
    world_map: "World Map",
    world_map_svg: "World Map (Offline SVG)",
    simulate_alert: "Simulate Connection Alert Window",
    profiles: "Profiles",
    default_profile: "Default Profile",
    rules_table: "Rules Table",
    action: "Action",
    allow: "ALLOW",
    deny: "DENY",
    geoip_databases: "GeoIP Databases",
    update_database: "Update Database",
    choose_file: "Choose File...",
    general: "General",
    general_desc: "Monitor network traffic and manage connection rules.",
    error_loading: "Error loading app data:",
    alert_title: "Connection Alert",
    alert_blocked: "Connection Attempt Blocked",
    alert_wants_to_connect: "{app} wants to connect to {ip} on port {port}.",
    scope: "Scope:",
    any_connection: "Any connection",
    this_domain: "This domain",
    this_ip: "This host / IP address",
    this_port: "This IP and port",
    timeout: "Timeout:",
    forever: "Forever",
    until_quit: "Until Quit",
    five_minutes: "5 Minutes",
    btn_allow: "Allow",
    btn_deny: "Deny",
    in: "in",
    out: "out",
    unknown: "unknown",
    ask: "ASK",
    status_connecting: "Connecting to the Rat service...",
    status_not_running: "The Rat service is not running. Start the Rat service; this window reconnects by itself.",
    status_access_denied: "Access denied. Run Rat as administrator (Windows) or add your user to the rat group (Linux).",
    status_protocol_mismatch: "The Rat service uses a different protocol version. Update Rat and the service together.",
    status_failed: "Cannot talk to the Rat service.",
    status_demo: "Demo mode: this is fake data, not your real connections.",
    no_connections: "No connections yet.",
    no_rules: "No rules yet.",
    listening: "Listening",
    add_rule: "Add Rule",
    rule_app_path: "Program path",
    rule_remote_hint: "Remote (empty = any, IP or domain)",
    delete_rule: "Delete",
    once: "Once",
    alert_none: "No connection is waiting for an answer.",
    alert_answer_failed: "Could not send the answer:",
    rule_failed: "Rule change failed:"
  }
};

const rtlMap: Record<string, string> = {
    a: 'ا', b: 'ب', c: 'ت', d: 'ث', e: 'ج', f: 'ح', g: 'خ', h: 'د', i: 'ذ', j: 'ر',
    k: 'ز', l: 'س', m: 'ش', n: 'ص', o: 'ض', p: 'ط', q: 'ظ', r: 'ع', s: 'غ', t: 'ف',
    u: 'ق', v: 'ك', w: 'ل', x: 'م', y: 'ن', z: 'ه',
    A: 'ا', B: 'ب', C: 'ت', D: 'ث', E: 'ج', F: 'ح', G: 'خ', H: 'د', I: 'ذ', J: 'ر',
    K: 'ز', L: 'س', M: 'ش', N: 'ص', O: 'ض', P: 'ط', Q: 'ظ', R: 'ع', S: 'غ', T: 'ف',
    U: 'ق', V: 'ك', W: 'ل', X: 'م', Y: 'ن', Z: 'ه'
};

const accents: Record<string, string> = {
    a: 'á', e: 'é', i: 'í', o: 'ó', u: 'ú',
    A: 'Á', E: 'É', I: 'Í', O: 'Ó', U: 'Ú'
};

function generatePseudo(str: string, rtl: boolean): string {
    // Replaced problematic regex with string iteration to prevent ReDoS SonarCloud issue
    let result = '';
    let i = 0;
    while (i < str.length) {
        if (str[i] === '{') {
            const endIdx = str.indexOf('}', i);
            if (endIdx !== -1) {
                result += str.substring(i, endIdx + 1);
                i = endIdx + 1;
                continue;
            }
        }

        const c = str[i];
        result += rtl ? (rtlMap[c] || c) : (accents[c] || c);
        i++;
    }

    // add 40% length padding
    const extraLen = Math.ceil(str.length * 0.4);
    const padChar = rtl ? 'غ' : 'x';
    const pad = ` ${padChar.repeat(5)}`.repeat(Math.ceil(extraLen / 5)).substring(0, extraLen);

    return `[${result}${pad}]`;
}

export const catalogs = {
    en: messages.en,
    'en-PSEUDO': Object.fromEntries(Object.entries(messages.en).map(([k, v]) => [k, generatePseudo(v, false)])),
    'ar-PSEUDO': Object.fromEntries(Object.entries(messages.en).map(([k, v]) => [k, generatePseudo(v, true)]))
};

let currentLocale = 'en';

export function setLocale(loc: string) {
    currentLocale = loc;
}

export function getLocale() {
    return currentLocale;
}

export function t(key: keyof typeof messages.en, args?: Record<string, string>): string {
    let str = (catalogs as any)[currentLocale]?.[key] || catalogs.en[key] || key;
    if (args) {
        for (const [k, v] of Object.entries(args)) {
            // Function replacer: a value like "$&" must stay literal text.
            str = str.replace(`{${k}}`, () => v);
        }
    }
    return str;
}
