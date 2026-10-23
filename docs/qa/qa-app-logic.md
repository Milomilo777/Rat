# QA Report for App Logic

## Requirement Map

| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1: a removed rule shrinks the pf blocklist | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | App/Model/Ledger.swift:344, App/Model/RulesModel.swift:193 |
| R2: an app with a rule never prompts | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | App/Model/Ledger.swift:252, App/Model/AlertCenter.swift:48 |
| R3: alerts time out to the configured default | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | App/Model/AlertCenter.swift:86 |
| R4: imported rules arrive disabled and unapproved | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | RatFilter/Sources/RatFilterCore/RuleEngine.swift:45, App/Model/RulesModel.swift:207 |
| R5: state is written atomically and survives a crash mid-write | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | App/Model/Persistence.swift:69, RatFilter/Sources/RatFilterCore/RuleEngine.swift:81, App/Model/Enforcer.swift:132 |
| R6: a malformed state file does not wipe user rules | NOT MET | N/A (macOS-only Swift code can only be read) | App/Model/RulesModel.swift:23 |
| R7: the update checker never runs code it downloads | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | App/Model/UpdateChecker.swift:56 |
| R8: timers and observers do not leak on window close | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | App/RatApp.swift:26, App/Model/Ledger.swift:150 |
| R9: no data race on shared state between the sampler and the UI | NOT TESTABLE HERE | N/A (macOS-only Swift code can only be read) | App/Model/Ledger.swift:178, App/Model/Ledger.swift:210 |

*Note: All statuses are NOT TESTABLE HERE or NOT MET because Rat is a macOS app, and its Swift code cannot be built or tested on Linux. Analysis was performed statically by reading the code.*

## Detailed Analysis

### R1: a removed rule shrinks the pf blocklist
**PASS** (Changed by v1.2.0)
*   **Evidence:** `App/Model/Ledger.swift` (`refreshEnforcement()`). In v1.2.0, Rat never blocks remote addresses. Instead, the pf blocklist consists of the local ports of live denied sockets (`deniedPorts`) and the paths of all apps explicitly denied (`deniedAppPaths`).
*   **Reason:** If a `.deny` rule is removed, on the very next `ingest` (which runs every 1.5 seconds), the live connection that was previously denied will now evaluate to `.allow` or `.ask` in `judge(...)`. It will not be added to `portsNow` (the accumulator for `deniedPorts`). Then `refreshEnforcement()` is called, which invokes `enforcer.syncPorts(deniedPorts, loopback: deniedLoopbackPorts)`, directly shrinking the pf blocklist of local ports.

### R2: an app with a rule never prompts
**PASS**
*   **Evidence:** `App/Model/Ledger.swift:252` (evaluating a new remote). The code uses `let matched = rules.engine.matchingRule(conn)` and `let verdict = matched?.verdict ?? rules.engine.defaultVerdict`. Alerts are queued only when `verdict == .ask`. Additionally, queued alerts that match a newly added rule are dropped in `App/Model/AlertCenter.swift:48` (`revalidate()`).
*   **Reason:** Since `.allow` or `.deny` rules mean `verdict != .ask`, it will never queue an alert for an app that already has a rule covering the connection.

### R3: alerts time out to the configured default
**PASS**
*   **Evidence:** `App/Model/AlertCenter.swift:86` (`startTimeout()`)
*   **Reason:** The method captures `let secs = AppSettings.shared.alertTimeout`. A `Task { try? await Task.sleep(for: .seconds(secs)) ... }` is launched. Upon completion, it automatically resolves the alert to `.allow` or `.deny` using `AppSettings.shared.alertTimeoutAllows`.

### R4: imported rules arrive disabled and unapproved
**PASS**
*   **Evidence:** `App/Model/RulesModel.swift:207` calls `engine.importRules(export, markUnapproved: true)`. In `RatFilter/Sources/RatFilterCore/RuleEngine.swift:45` (`importRules`), it explicitly checks `if markUnapproved { r.approved = false; r.enabled = false }`.
*   **Reason:** The boolean forces imported rules to lose their approved and enabled status.

### R5: state is written atomically and survives a crash mid-write
**PASS**
*   **Evidence:** `App/Model/Persistence.swift:69` (`try enc.encode(state).write(to: url, options: .atomic)`), `RatFilter/Sources/RatFilterCore/RuleEngine.swift:81` (`try e.encode(s).write(to: url, options: .atomic)`), and `App/Model/Enforcer.swift:132` (`try ips.sorted().joined(separator: "\n").appending("\n").write(to: listURL, atomically: true, encoding: .utf8)`).
*   **Reason:** All file writes use Foundation's atomic writing options, which write data to a temporary file first, followed by a guaranteed atomic move operation over the destination file.

### R6: a malformed state file does not wipe user rules
**FAIL**
*   **Evidence:** `App/Model/RulesModel.swift:23`
*   **Concrete input sequence:**
    1. The user's `rules.json` becomes malformed (e.g., partial write during a power failure, despite atomic writes, or manually corrupted by the user).
    2. The app starts and initializes `RulesModel`. `RuleStore.loadSet()` fails to parse the malformed JSON and throws an error.
    3. `RulesModel.init` catches this implicitly with `(try? store.loadSet()) ?? RuleSet.standard()`.
    4. The model assigns `ruleSet = set`. Because `ruleSet` is an `@Published` property, its `didSet` block fires and calls `scheduleSave()`.
    5. A short time later, `scheduleSave()` overwrites `rules.json` with the empty `RuleSet.standard()`. The malformed but potentially recoverable rules are permanently destroyed.
*   **Proposed patch:**
    We must use the underlying storage (e.g. `_ruleSet = Published(initialValue: set)`) during initialization to avoid triggering `didSet`, and only call `scheduleSave()` if the load was successful.

```diff
<<<<<<< SEARCH
    init(directory: URL) {
        store = RuleStore(url: directory.appendingPathComponent("rules.json"))
        var set = (try? store.loadSet()) ?? RuleSet.standard()
        if !set.profiles.contains(where: { $0.id == set.activeProfileID }), let first = set.profiles.first { set.activeProfileID = first.id }
        Self.repair(&set)
        ruleSet = set
        engine = RuleEngine(ruleSet: set)
    }
=======
    init(directory: URL) {
        store = RuleStore(url: directory.appendingPathComponent("rules.json"))
        let loaded = try? store.loadSet()
        var set = loaded ?? RuleSet.standard()
        if !set.profiles.contains(where: { $0.id == set.activeProfileID }), let first = set.profiles.first { set.activeProfileID = first.id }
        Self.repair(&set)
        _ruleSet = Published(initialValue: set)
        engine = RuleEngine(ruleSet: set)
        if loaded != nil { scheduleSave() }
    }
>>>>>>> REPLACE
```

### R7: the update checker never runs code it downloads
**PASS**
*   **Evidence:** `App/Model/UpdateChecker.swift:56` (`present(_ r: Release, current: String)`)
*   **Reason:** The method `NSWorkspace.shared.open(u)` is used to launch the default web browser and open the GitHub releases URL. No binary is downloaded or executed programmatically.

### R8: timers and observers do not leak on window close
**PASS**
*   **Evidence:** `App/RatApp.swift:26`, `App/Model/Ledger.swift:150`
*   **Reason:** The app does not utilize bare Foundation Timers. The ledger loop relies on `Task { await loop() }` bound to a `@StateObject`, which matches the lifetime of the application, not an individual window. NotificationCenter observers are attached via SwiftUI's `.onReceive` to the window, which automatically manages its lifecycle without manual `addObserver` cleanup leaks.

### R9: no data race on shared state between the sampler and the UI
**PASS**
*   **Evidence:** `App/Model/Ledger.swift:178` (`Task.detached(priority: .utility)` for background sampling) and `App/Model/Ledger.swift:210` (`ingest(_:_:)`)
*   **Reason:** The `Ledger` is a `@MainActor` class. Background operations are correctly detached using `Task.detached`, resulting in Sendable value types (`ObservedConnection`, `TrafficCounter`) being returned to the actor context. State mutations in `ingest` occur safely on the main thread, avoiding data races with SwiftUI views. Other shared caches like `GeoService` use `NSLock`.

## Cross-Module FAIL Mapping

### R6: a malformed state file does not wipe user rules
*   **App Logic (`App/Model`)**: FAIL. As detailed above, `RulesModel.init` falls back to `RuleSet.standard()` when loading a malformed `rules.json`, which then triggers a save that overwrites and permanently destroys the user's rules.
*   **Pure Swift Package (`RatFilter/Sources`)**: The same hazardous pattern exists in `RatFilter/Sources/RatFilterCore/RuleEngine.swift`. In the `RuleStore.save(_ rules: [Rule])` method (the v0.1 API), the code does:
    `var s = (try? loadSet()) ?? RuleSet.standard(); s.rules = rules; try saveSet(s)`
    If `loadSet()` throws due to a malformed file, this method silently falls back to `RuleSet.standard()`, injects the new rules, and overwrites the file, wiping any existing groups, profiles, and unrecoverable user rules.

## FAIL Rankings by User Impact

1.  **R6: a malformed state file does not wipe user rules**
    *   **Impact:** Data loss (Highest)
    *   **Reason:** A crash, power failure, or manual edit that corrupts `rules.json` will cause the application (or any API consumer using `RuleStore.save`) to irreversibly wipe all user-configured rules, profiles, and groups on the very next save operation, instead of preserving the file or halting execution.
