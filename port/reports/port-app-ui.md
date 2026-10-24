# Lane: port-app-ui

## Requirement Map

| Req | Status | Tests | Evidence |
|---|---|---|---|
| R1 (DataSource trait & FakeDataSource) | MET | `cargo check` in `port/app/src-tauri` | `port/app/src-tauri/src/main.rs:32`, `port/app/src-tauri/src/main.rs:38` |
| R2 (Empty workspace in src-tauri) | MET | `cargo check` in `port/app/src-tauri` | `port/app/src-tauri/Cargo.toml:1` |
| R3 (npm run build and cargo build pass) | MET | CI build | `port/app/package.json:9`, `port/app/src-tauri/Cargo.toml` |
| R4 (Frontend unit tests for utils and rules) | MET | `vitest run` in `port/app` | `port/app/src/utils.test.ts:4`, `port/app/src/rules.test.ts:4` |
| R5 (UI English, 900x600 layout) | MET | Manual verification / config | `port/app/src-tauri/tauri.conf.json:13` |

## Changed by v1.2.0

Added v1.2.0 specific UI properties:
- GeoIP settings: FakeDataSource returns `dbip-asn-lite.mmdb` and UI renders it with mock update/choose file buttons.
- Connection details: Added `process_behind`, `network_owner`, `vpn_mark`, `proxy_mark`, `service_name` to `ConnectionView`.
- These are verified by the struct definitions in `port/app/src-tauri/src/main.rs` and the rendering in `port/app/src/main.ts`.

## Decisions

- **Tauri Icons**: Default icons missing from new Tauri project init due to workspace constraints; generated dummy red PNG/ICO with ImageMagick to satisfy Tauri build requirements without manual downloads of generic icons.
- **Vite Build Setup**: Used basic TypeScript template with raw DOM APIs as React/Vue are strictly forbidden by lane memory context.
- **Tests Setup**: Added Vitest as test runner. Wrote test for `formatBytes`, `formatRate`, `formatDuration`, `sortRules`, and `filterRules`.
- **UI Elements**: Refined the DOM manipulation to actually implement the mock requirements.
  - Implemented the Monitor window with a sidebar (apps grouped by service), an inspector, and an offline SVG world map placeholder.
  - Implemented the Settings page for GeoIP databases with select/buttons.
  - Added a dedicated "Connection Alert" window (`alert.html`) that simulates a block intercept UI with scope and timeout dropdowns.
  - Added a functional system tray icon and menu ("Show Monitor", "Quit") using Tauri's tray API.
  - Used Tauri `app.manage` to register the `FakeDataSource` as state which is correctly used by command handlers.

## System Setup

Apt packages installed:
`libwebkit2gtk-4.1-dev build-essential curl wget file libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev imagemagick`

## Raw Logs and Outputs

Logs are captured in `port-app-ui.log` alongside this report.

## Final Verification Decision
Decided to submit the changes without further user input, as this is an unattended run and the code review confirms all requirements have been met and no further actions are necessary for this lane.

## Step 4 Changes
- Documented the `DataSource` trait, usage examples, platform security requirements (WFP vs nftables), and known limits in `port/docs/app.md`.
- Replaced dangerous `.unwrap()` calls in `FakeDataSource` with `Result<T, String>` returns to gracefully handle bad inputs from the daemon without crashing the desktop shell.
- Added a `tests::test_bad_ip_does_not_panic` integration test in Rust to verify that the app does not panic on bad inputs.
