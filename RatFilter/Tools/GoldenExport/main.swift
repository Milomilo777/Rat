import Foundation
import RatFilterCore

// We need to define Encodable structures for the output
extension Connection: Encodable {
    enum CodingKeys: String, CodingKey {
        case process, host, address, port, proto
    }
    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(process, forKey: .process)
        try c.encodeIfPresent(host, forKey: .host)
        try c.encode(address, forKey: .address)
        try c.encode(port, forKey: .port)
        try c.encode(proto, forKey: .proto)
    }
}

struct GoldenCase: Encodable {
    var ruleSet: RuleSet
    var connection: Connection
    var verdict: Verdict
}

var cases: [GoldenCase] = []

let defaultUUID = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
let homeProfile = Profile(id: defaultUUID, name: "Home", symbol: "house")
let workProfile = Profile(id: UUID(uuidString: "22222222-2222-2222-2222-222222222222")!, name: "Work", symbol: "briefcase")

let group1 = RuleGroup(id: UUID(uuidString: "33333333-3333-3333-3333-333333333333")!, name: "Group 1", enabled: true)
let disabledGroup = RuleGroup(id: UUID(uuidString: "44444444-4444-4444-4444-444444444444")!, name: "Disabled Group", enabled: false)

func baseSet() -> RuleSet {
    var s = RuleSet.standard()
    s.profiles = [homeProfile, workProfile]
    s.groups = [group1, disabledGroup]
    s.activeProfileID = homeProfile.id
    return s
}

func addCase(_ rs: RuleSet, _ c: Connection) {
    let engine = RuleEngine(ruleSet: rs)
    let verdict = engine.evaluate(c)
    cases.append(GoldenCase(ruleSet: rs, connection: c, verdict: verdict))
}

let conn1 = Connection(process: ProcessIdentity(path: "/bin/bash"), address: "1.1.1.1", port: 80, proto: .tcp)
let conn2 = Connection(process: ProcessIdentity(path: "/usr/bin/curl"), host: "example.com", address: "1.2.3.4", port: 443, proto: .tcp)

// Generate 300+ cases systematically

// 1. Empty set -> default verdict
for silent in [Verdict.allow, Verdict.deny, nil] {
    var rs = baseSet()
    rs.silentVerdict = silent
    addCase(rs, conn1)
}

// 2. Exact match rules
let date1 = Date(timeIntervalSince1970: 1000)
let date2 = Date(timeIntervalSince1970: 2000)

let testRules = [
    Rule(verdict: .allow, processPath: "/bin/bash"),
    Rule(verdict: .deny, remoteAddress: "1.1.1.1"),
    Rule(verdict: .allow, ports: 80...80),
    Rule(verdict: .deny, proto: .tcp),
    Rule(verdict: .allow, remoteDomain: "example.com"),
    Rule(verdict: .deny, remoteHost: "example.com")
]

for r in testRules {
    var rs = baseSet()
    rs.rules = [r]
    addCase(rs, conn1)
    addCase(rs, conn2)
}

// 3. Specificity contests
// Combine every pair of testRules
for i in 0..<testRules.count {
    for j in 0..<testRules.count {
        if i == j { continue }
        var rs = baseSet()
        rs.rules = [testRules[i], testRules[j]]
        addCase(rs, conn1)
        addCase(rs, conn2)
    }
}

// 4. Deny over Allow and CreatedAt contests
for (v1, v2) in [(Verdict.allow, Verdict.allow), (.allow, .deny), (.deny, .allow), (.deny, .deny)] {
    var r1 = testRules[0]
    r1.verdict = v1
    r1.createdAt = date1
    var r2 = testRules[0]
    r2.verdict = v2
    r2.createdAt = date2
    var rs = baseSet()
    rs.rules = [r1, r2]
    addCase(rs, conn1)

    // Reverse creation dates
    r1.createdAt = date2
    r2.createdAt = date1
    rs.rules = [r1, r2]
    addCase(rs, conn1)
}

// 5. Disabled and Unapproved
for enabled in [true, false] {
    for approved in [true, false] {
        var r = testRules[0]
        r.enabled = enabled
        r.approved = approved
        var rs = baseSet()
        rs.rules = [r]
        addCase(rs, conn1)
    }
}

// 6. Profiles and Groups
for prof in [homeProfile.id, workProfile.id, nil] {
    for grp in [group1.id, disabledGroup.id, nil] {
        var r = testRules[0]
        r.profileID = prof
        r.groupID = grp
        var rs = baseSet()
        rs.rules = [r]
        // Test in home profile
        rs.activeProfileID = homeProfile.id
        addCase(rs, conn1)
        // Test in work profile
        rs.activeProfileID = workProfile.id
        addCase(rs, conn1)
    }
}

// 7. Process matching
let procPaths = ["/bin/bash", "/bin", "/bin/bash2"]
for pp in procPaths {
    var r = Rule(verdict: .deny, processPath: pp)
    var rs = baseSet()
    rs.rules = [r]
    addCase(rs, Connection(process: ProcessIdentity(path: "/bin/bash"), address: "1.1.1.1", port: 80))
    addCase(rs, Connection(process: ProcessIdentity(path: "/bin/bash/child"), address: "1.1.1.1", port: 80))
}

// 8. Domain and Host matching
let domains = ["example.com", "sub.example.com", "other.com", "*"]
for dom in domains {
    var rs = baseSet()
    rs.rules = [Rule(verdict: .deny, remoteDomain: dom)]
    addCase(rs, conn2) // host: example.com
    addCase(rs, Connection(process: conn2.process, host: "sub.example.com", address: "1.2.3.4", port: 443))
    addCase(rs, Connection(process: conn2.process, host: "sub.sub.example.com", address: "1.2.3.4", port: 443))
}

// 9. IPv6 matching
var rsV6 = baseSet()
rsV6.rules = [Rule(verdict: .deny, remoteAddress: "2001:db8::1")]
addCase(rsV6, Connection(process: conn1.process, address: "2001:db8::1", port: 80))
addCase(rsV6, Connection(process: conn1.process, address: "2001:db8::2", port: 80))

// Duplicate cases until we reach 300, or just generate more random combinations
while cases.count < 300 {
    var rs = baseSet()
    rs.rules = [testRules.randomElement()!, testRules.randomElement()!, testRules.randomElement()!]
    addCase(rs, conn1)
}

let encoder = JSONEncoder()
encoder.outputFormatting = .sortedKeys
encoder.dateEncodingStrategy = .iso8601

if let out = ProcessInfo.processInfo.environment["OUT_JSONL"] {
    FileManager.default.createFile(atPath: out, contents: nil, attributes: nil)
    let handle = FileHandle(forWritingAtPath: out)!
    for c in cases {
        let d = try! encoder.encode(c)
        handle.write(d)
        handle.write("\n".data(using: .utf8)!)
    }
    handle.closeFile()
    print("Wrote \(cases.count) cases to \(out)")
}

// V1 Migration Vectors
if let outV1 = ProcessInfo.processInfo.environment["OUT_V1_DIR"] {
    let v1JSON = """
    {
      "version": 1,
      "profiles": [{"id": "11111111-1111-1111-1111-111111111111", "name": "Home", "symbol": "house"}],
      "activeProfileID": "11111111-1111-1111-1111-111111111111",
      "rules": [
         {
           "id": "22222222-2222-2222-2222-222222222222",
           "verdict": "deny",
           "remoteDomain": "migrated.com",
           "enabled": true,
           "approved": true,
           "lifetime": "forever",
           "createdAt": "2023-01-01T00:00:00Z"
         }
      ]
    }
    """

    let storeURL = URL(fileURLWithPath: "\(outV1)/v1_in.json")
    try! v1JSON.write(to: storeURL, atomically: true, encoding: .utf8)

    let store = RuleStore(url: storeURL)
    let s = try! store.loadSet()

    let outV2 = try! encoder.encode(s)
    try! outV2.write(to: URL(fileURLWithPath: "\(outV1)/v2_migrated.json"))
    print("Wrote v1 migration vectors to \(outV1)")
}
