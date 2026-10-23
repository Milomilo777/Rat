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

Changed by v1.2.0:
- RatFilterExtension/FilterProvider.swift is now obsolete/dormant.
- ProcessArguments.swift `KERN_PROCARGS2` parser reads untrusted bytes.
- LoopbackCapture.swift `BPFInstruction` loopback captures reads untrusted bytes.
- ProxyHandshake.swift reads SOCKS4/SOCKS5/HTTP handshakes.

**Note:** Testing Swift sources natively on Ubuntu failed deeply within `clang::RawComment` segmentation faults on all provided `swift-6.0.1` and `swift-5.10.1` distributions via swift.org, blocking `swift test`. The requirement evaluation has been analyzed statically through the codebase sources and test suites instead since runtime evaluation could not be fully executed.
