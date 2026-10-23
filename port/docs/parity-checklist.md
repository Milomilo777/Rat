# Rat Parity Checklist

This document maps every user-visible behavior of the macOS app (App/Model and App/Views) to its corresponding Rust crate in the port, along with the source Swift file and line, an acceptance test idea, and platform-specific notes.

## 1. Network Monitoring and Attribution
1. **Sample process connections periodically** -> `rat-monitor-linux`, `rat-monitor-windows`: `App/Model/Ledger.swift:178`. Test: start a local HTTP server and make a request, verify it's captured.
2. **Collect system-wide connection snapshots** -> `rat-monitor-linux`, `rat-monitor-windows`: `App/Model/Ledger.swift:182` / `RatFilter/Sources/RatMonitor/SystemSnapshot.swift:15`. Test: run snapshot helper and verify sockets from other users are included.
3. **Capture connection traffic rates (rx/tx)** -> `rat-monitor-linux`, `rat-monitor-windows`: `App/Model/Ledger.swift:183`. Test: transfer 1MB file, verify traffic sum matches.
4. **Identify process app identity and signing** -> `rat-core` / `port/app`: `App/Model/AppInfo.swift:16`. Test: verify Chrome binary maps to Google Chrome app bundle and signing team. *Cannot exist on Linux:* Linux lacks a native code signing identity concept comparable to macOS/Windows Authenticode.
5. **Group processes into apps** -> `rat-core`: `RatFilter/Sources/RatMonitor/ProcessGrouping.swift:10`. Test: multiple child PIDs of a browser aggregate under one app identity.
6. **Identify shared system services** -> `rat-core`: `App/Model/Ledger.swift:295` / `App/Model/SharedServices.swift:15`. Test: mDNSResponder/svchost connections are tagged as shared.
7. **Identify standard port service names** -> `rat-names`: `RatFilter/Sources/RatMonitor/PortNames.swift:12`. Test: Port 443 maps to "HTTPS".
8. **Unmask proxy connections** -> `rat-enforcer`: `RatFilter/Sources/RatEnforce/ProxyWatch.swift:20` / `App/Model/ProxyUnmasking.swift:15`. Test: proxy request on lo0 correctly attributes the real destination to the client process.
9. **Identify VPN and system proxies** -> `rat-monitor-linux`, `rat-monitor-windows`: `App/Model/RouteMarker.swift:15`. Test: connection routed through utun/WireGuard interface is marked as VPN.

## 2. Policy and Rule Enforcement
10. **Evaluate connection against rule engine** -> `rat-core`: `RatFilter/Sources/RatFilterCore/RuleEngine.swift:34`. Test: connection matching deny rule returns Deny verdict.
11. **Resolve unknown connections to Ask** -> `rat-core`: `RatFilter/Sources/RatFilterCore/RuleEngine.swift:41`. Test: connection with no matching rule returns Ask verdict.
12. **Block denied app local ports** -> `rat-enforcer`: `App/Model/Ledger.swift:354`. Test: daemon successfully blocks specified local port.
13. **Block all sockets of explicitly denied apps** -> `rat-enforcer`: `App/Model/Ledger.swift:362`. Test: daemon blocks new loopback proxy connections of a denied app.
14. **Maintain session-only rules** -> `rat-core`: `App/Model/RulesModel.swift:221`. Test: "Until Quit" rules are purged on app shutdown.

## 3. Persistent State and Storage
15. **Save and load Ledger state (apps, buckets)** -> `rat-ledger`: `App/Model/Persistence.swift:59`. Test: simulated traffic state persists across app restart.
16. **Save and load Rule configurations** -> `rat-core`: `RatFilter/Sources/RatFilterCore/RuleEngine.swift:81`. Test: valid rules.json is loaded correctly.
17. **Handle malformed rule states safely** -> `rat-core`: `App/Model/RulesModel.swift:23`. Test: malformed rules.json does not trigger destructive overwrite of user rules.
18. **Store application settings** -> `port/app`: `App/Model/AppSettings.swift:54`. Test: changing a setting persists to preferences.

## 4. UI: Network Monitor and Alerts
19. **Display traffic chart with dynamic scaling** -> `port/app`: `App/Model/Ledger.swift:420`. Test: 5m range layout correctly computes peak and scales bars.
20. **Queue and present connection alerts** -> `port/app`: `App/Model/AlertCenter.swift:75`. Test: two concurrent Ask verdicts queue and present sequentially.
21. **Auto-timeout alerts to default action** -> `port/app`: `App/Model/AlertCenter.swift:86`. Test: alert unanswered for X seconds resolves to configured default.
22. **Deduplicate alerts for same domain/app** -> `port/app`: `App/Model/AlertCenter.swift:48`. Test: multiple connections to same domain only spawn one alert.
23. **Show Menu Bar throughput and modes** -> `port/app`: `App/Model/MenuBarController.swift:31`. Test: menu bar updates rx/tx rates dynamically. *Platform Note:* Menu bar icon behavior will need to adapt to Linux desktop environment tray APIs (e.g. AppIndicator) and Windows System Tray.

## 5. UI: Rules and Settings
24. **Filter rules by unapproved status** -> `port/app`: `App/Model/RulesModel.swift:184`. Test: Unapproved rules are highlighted/filtered in the rules list.
25. **Import/Export rule sets via JSON** -> `rat-core`: `App/Model/RulesModel.swift:200`. Test: exported rules can be cleanly imported into another instance.
26. **Switch rule profiles based on network** -> `rat-core`: `App/Model/RulesModel.swift:77`. Test: joining a new SSID triggers profile switch.
27. **Check for updates via GitHub** -> `port/app`: `App/Model/UpdateChecker.swift:22`. Test: checker identifies newer release tag and prompts user.
28. **Configure Silent Mode (Allow/Deny)** -> `rat-core`: `App/Model/RulesModel.swift:138`. Test: Silent Allow allows unknown connections without alerting.

## 6. Geolocation
29. **Lookup IP location in local MMDB** -> `rat-geo`: `App/Model/Geo.swift:34`. Test: specific public IP maps to correct City/Country.
30. **Lookup ASN for IP** -> `rat-geo`: `App/Model/GeoDatabases.swift:45`. Test: public IP maps to correct ASN and Org.
31. **Determine local machine coordinates** -> `rat-geo`: `App/Model/Geo.swift:44`. Test: local point maps based on system timezone.
