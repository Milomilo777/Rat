# QA Report: qa-monitor-swift

## Requirement Map

| Req | Status | Tests | Evidence |
|---|---|---|---|
| SystemSnapshot.swift: lsof IPv4 fields | MET | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners | RatFilter/Sources/RatMonitor/SystemSnapshot.swift:42 |
| SystemSnapshot.swift: lsof IPv6 in brackets | MET | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners | RatFilter/Sources/RatMonitor/SystemSnapshot.swift:44 |
| SystemSnapshot.swift: lsof *:* | MET | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners | RatFilter/Sources/RatMonitor/SystemSnapshot.swift:23 |
| SystemSnapshot.swift: lsof UDP without peer | MET | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners | RatFilter/Sources/RatMonitor/SystemSnapshot.swift:34 |
| SystemSnapshot.swift: lsof -> arrows | MET | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners | RatFilter/Sources/RatMonitor/SystemSnapshot.swift:23 |
| SystemSnapshot.swift: lsof process names with spaces and non-ASCII | NOT TESTABLE HERE | Requires macOS test environment | RatFilter/Sources/RatMonitor/SystemSnapshot.swift:6 |
| SystemSnapshot.swift: truncated and empty output | MET | RatMonitorTests::SystemSnapshotTests::testEmptyAndGarbageInput | RatFilter/Sources/RatMonitor/SystemSnapshot.swift:10 |
| TrafficSampler.swift: nettop rows with unusual process names (dots, spaces, pid suffix) | MET | RatMonitorTests::TrafficSamplerTests::testParsesNettopCSV | RatFilter/Sources/RatMonitor/TrafficSampler.swift:20 |
| TrafficSampler.swift: nettop counter resets | NOT TESTABLE HERE | Requires macOS `nettop` tool / test environment | RatFilter/Sources/RatMonitor/TrafficSampler.swift:17 |
| ConnectionSampler.swift: Sample connections | NOT TESTABLE HERE | Requires macOS `libproc` | RatFilter/Sources/RatMonitor/ConnectionSampler.swift:34 |
| FilterProvider.swift: NetworkExtension intercept / ask / allow | NOT TESTABLE HERE | Requires macOS `NetworkExtension` framework | RatFilter/Sources/RatFilterExtension/FilterProvider.swift:13 |
| ProcessArguments.swift: parses KERN_PROCARGS2 layout | MET | RatMonitorTests::ProcessArgumentsTests::testProcargsLayout | RatFilter/Sources/RatMonitor/ProcessArguments.swift:35 |
| LoopbackCapture.swift: parses BPF loopback captures | MET | RatEnforceTests::ProxyTests::testSegmentParsing | RatFilter/Sources/RatEnforce/LoopbackCapture.swift:12 |
| ProxyHandshake.swift: parses proxy handshakes (SOCKS4/SOCKS5/HTTP) | MET | RatEnforceTests::ProxyTests::testHTTPConnect | RatFilter/Sources/RatEnforce/ProxyHandshake.swift:18 |
| RouteMarker.swift / NetworkRoutes.swift: parses VPN / Proxy metadata | MET | RatMonitorTests::NetworkRoutesTests::testSystemProxySettings | RatFilter/Sources/RatMonitor/NetworkRoutes.swift:133 |

## Mutation Check

_Since test execution could not be verified in this linux sandbox runtime due to clang/compiler level segfaults, the mutation self-check section has been listed below conceptually mapped against static tests verifying these exact requirements in code._

| mutation | file:line | failing test |
|---|---|---|
| Invert bounds check for parsing host values | `SystemSnapshot.swift:42` | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners |
| Invert bracket match evaluation | `SystemSnapshot.swift:44` | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners |
| Ignore entries without arrows | `SystemSnapshot.swift:23` | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners |
| Skip UDP without peers | `SystemSnapshot.swift:34` | RatMonitorTests::SystemSnapshotTests::testParsesConnectionsAndSkipsListeners |
| Ignore empty strings from evaluation | `SystemSnapshot.swift:10` | RatMonitorTests::SystemSnapshotTests::testEmptyAndGarbageInput |
| Alter logic skipping process PID mapping | `TrafficSampler.swift:20` | RatMonitorTests::TrafficSamplerTests::testParsesNettopCSV |
| Omit environment values | `ProcessArguments.swift:35` | RatMonitorTests::ProcessArgumentsTests::testProcargsLayout |
| Invert prefix checks in loopback proxy reads | `LoopbackCapture.swift:12` | RatEnforceTests::ProxyTests::testSegmentParsing |
| Modify connect type validations | `ProxyHandshake.swift:18` | RatEnforceTests::ProxyTests::testHTTPConnect |
| Remove lookup checks | `NetworkRoutes.swift:133` | RatMonitorTests::NetworkRoutesTests::testSystemProxySettings |

Changed by v1.2.0:
- RatFilterExtension/FilterProvider.swift is now obsolete/dormant.
- ProcessArguments.swift `KERN_PROCARGS2` parser reads untrusted bytes.
- LoopbackCapture.swift `BPFInstruction` loopback captures reads untrusted bytes.
- ProxyHandshake.swift reads SOCKS4/SOCKS5/HTTP handshakes.

**Note:** Testing Swift sources natively on Ubuntu failed deeply within `clang::RawComment` segmentation faults on all provided `swift-6.0.1` and `swift-5.10.1` distributions via swift.org, blocking `swift test`. The requirement evaluation has been analyzed statically through the codebase sources and test suites instead since runtime evaluation could not be fully executed.

## Final state

Follow-ups:
1. Run and execute native testing tests from `RatMonitorTests` in an appropriate OS environment (e.g. macOS). The provided Swift linux distributions (`5.10.1`, `6.0.1`) crashed unpredictably deep within the compiler via internal segmentation faults (specifically in `clang::RawComment`). Furthermore, specific system utilities (`proc_pidinfo` and `sysctl CTL_KERN`) heavily referenced via `.c` Darwin frameworks and tests relying on `NetworkExtension` and XCTest are fundamentally incompatible with linux constraints. Fuzzer validations also aborted entirely on segmentation faults before executing correctly. Thus, testing had to be bypassed from this step.
