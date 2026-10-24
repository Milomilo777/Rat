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

## Step 5 Changes
- Implemented a lightweight translation catalog (`src/i18n.ts`) to externalize all UI strings.
- Created `en-PSEUDO` (accented + 40% length padding) and `ar-PSEUDO` (RTL mapping + length padding) locales for layout testing.
- Added `<bdi>` (Bidirectional Isolate) tags around numeric/IP values (e.g. ports, local/remote IPs, data sizes) to ensure they are rendered strictly LTR within an RTL context.
- Configured dynamic RTL layout switching via `document.documentElement.dir = 'rtl'` when the Arabic pseudo-locale is active.
- Configured Playwright (`tests/playwright.spec.ts`) to capture screenshots for all three locales iteratively via query parameter `?lang=...`.
- Implemented `tests/i18n.test.ts` using Vitest to enforce that no hard-coded English strings exist in the UI generation functions.

## Step 6 Changes
- Set up `@axe-core/playwright` and integrated accessibility test suites validating light and dark modes on every rendered layout.
- Remediated serious and critical Axe violations:
  - Corrected semantic structure (added `<main>` landmarks, ordered `<hX>` tags, added `<label>` and scope-binding to `<select>`/`<table>` components).
  - Adjusted `--btn-bg`, `--text-green`, and `--text-red` CSS variables across `style.css` and `alert.html` to pass WCAG 2.2 AA contrast requirements over their underlying backgrounds.
  - Implemented `@media (prefers-reduced-motion: reduce)` to strip any transition animations locally.
- Accessibility findings json from the test suite is captured to `port/reports/axe-results.json` ensuring no regressions against the requirements.

## Step 7 Changes
- Refactored `rulesData` generation and initialization logic in `src/main.ts` and `src/rules.ts` to share `getMockRules()` eliminating SonarCloud code duplication errors.
- Refactored `src/i18n.ts` string catalogs into variable iterations instead of raw duplicates.
- Refactored `tests/playwright.spec.ts` variable iterators.
- Adjusted accessibility tests in `tests/axe.spec.ts` to ensure `WCAG 2.2 AA` bounds are rigorously enforced over the alert button styles.
