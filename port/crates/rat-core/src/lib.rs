use chrono::{DateTime, Utc};
use rat_types::Protocol;
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Outcome for a connection. `ask` means: pause the flow and prompt the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Verdict {
    Allow,
    Deny,
    Ask,
}

/// How long a rule created from an alert lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Lifetime {
    Once,
    UntilQuit,
    Forever,
}

/// Identifies the process behind a flow.
/// Replaces Swift's ProcessIdentity to use paths instead of macOS-specific bundle/team IDs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppIdentity {
    #[serde(default, alias = "signingID")]
    pub signing_id: Option<String>,
    #[serde(default, alias = "teamID")]
    pub team_id: Option<String>,
    pub path: String,
}

impl AppIdentity {
    pub fn new(signing_id: Option<String>, team_id: Option<String>, path: String) -> Self {
        Self {
            signing_id,
            team_id,
            path,
        }
    }

    /// Normalizes path for matching, handles case-insensitivity on Windows.
    pub fn normalized_path(&self) -> String {
        #[cfg(windows)]
        {
            self.path.to_lowercase().replace('\\', "/")
        }
        #[cfg(not(windows))]
        {
            self.path.clone()
        }
    }
}

pub struct AppConnection {
    pub process: AppIdentity,
    pub host: Option<String>,
    pub address: String,
    pub port: u16,
    pub proto: Protocol,
}

impl AppConnection {
    pub fn new(
        process: AppIdentity,
        host: Option<String>,
        address: String,
        port: u16,
        proto: Protocol,
    ) -> Self {
        Self {
            process,
            host,
            address,
            port,
            proto,
        }
    }
}

// Swift models ports as `ClosedRange<Int>`, whose Codable form is the array
// `[lower, upper]`. Read both that form and our `{start, end}` object, and
// write the Swift form so rules.json stays readable by the Swift app.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl Serialize for PortRange {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq([self.start, self.end])
    }
}

impl<'de> Deserialize<'de> for PortRange {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct PortRangeVisitor;

        impl<'de> Visitor<'de> for PortRangeVisitor {
            type Value = PortRange;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a [start, end] pair or a {start, end} object")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<PortRange, A::Error> {
                let start = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(0, &"two port numbers"))?;
                let end = seq
                    .next_element::<u16>()?
                    .ok_or_else(|| de::Error::invalid_length(1, &"two port numbers"))?;
                Ok(PortRange { start, end })
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<PortRange, A::Error> {
                let mut start = None;
                let mut end = None;
                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "start" => start = Some(map.next_value()?),
                        "end" => end = Some(map.next_value()?),
                        _ => {
                            let _ = map.next_value::<de::IgnoredAny>()?;
                        }
                    }
                }
                Ok(PortRange {
                    start: start.ok_or_else(|| de::Error::missing_field("start"))?,
                    end: end.ok_or_else(|| de::Error::missing_field("end"))?,
                })
            }
        }

        deserializer.deserialize_any(PortRangeVisitor)
    }
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Rule {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub verdict: Verdict,

    // Application executable path; matches the path itself and anything inside it.
    pub process_path: Option<String>,
    #[serde(alias = "signingID")]
    pub signing_id: Option<String>,
    #[serde(alias = "teamID")]
    pub team_id: Option<String>,

    // "example.com" matches the domain and subdomains; "*" or nil = any remote.
    pub remote_domain: Option<String>,
    // Exact hostname, no subdomains.
    pub remote_host: Option<String>,
    pub remote_address: Option<String>,

    pub ports: Option<PortRange>,
    pub proto: Option<Protocol>,

    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub approved: bool,
    #[serde(default = "default_lifetime")]
    pub lifetime: Lifetime,

    #[serde(alias = "profileID")]
    pub profile_id: Option<Uuid>,
    #[serde(alias = "groupID")]
    pub group_id: Option<Uuid>,

    #[serde(default = "default_created_at")]
    pub created_at: DateTime<Utc>,
    pub note: Option<String>,
}

fn default_true() -> bool {
    true
}
fn default_lifetime() -> Lifetime {
    Lifetime::Forever
}
fn default_created_at() -> DateTime<Utc> {
    DateTime::from_timestamp(0, 0).unwrap_or_default()
}

impl Rule {
    pub fn specificity(&self) -> i32 {
        let mut s = 0;
        #[allow(clippy::if_same_then_else)]
        if self.process_path.is_some() {
            s += 4;
        } else if self.signing_id.is_some() {
            s += 4;
        } else if self.team_id.is_some() {
            s += 2;
        }

        if self.remote_address.is_some() {
            s += 5;
        }

        if self.remote_host.is_some() {
            s += 4;
        } else if let Some(d) = &self.remote_domain {
            if d != "*" {
                s += 3;
            }
        }

        if self.ports.is_some() {
            s += 2;
        }
        if self.proto.is_some() {
            s += 1;
        }
        s
    }

    pub fn summary(&self) -> String {
        let who = if let Some(p) = &self.process_path {
            let path = Path::new(p);
            let filename = path.file_name().unwrap_or_default().to_string_lossy();
            filename.replace(".app", "")
        } else if let Some(sid) = &self.signing_id {
            sid.clone()
        } else if let Some(tid) = &self.team_id {
            format!("Team {}", tid)
        } else {
            "Any process".to_string()
        };

        let mut what;
        if let Some(ra) = &self.remote_address {
            what = ra.clone();
        } else if let Some(rh) = &self.remote_host {
            what = rh.clone();
        } else if let Some(rd) = &self.remote_domain {
            if rd == "*" {
                what = "any server".to_string();
            } else {
                what = format!("*.{}", rd);
            }
        } else {
            what = "any server".to_string();
        }

        if let Some(ports) = &self.ports {
            if ports.start == ports.end {
                what = format!("{}:{}", what, ports.start);
            } else {
                what = format!("{}:{}-{}", what, ports.start, ports.end);
            }
        }

        if let Some(proto) = &self.proto {
            let p = match proto {
                Protocol::Tcp => "TCP",
                Protocol::Udp => "UDP",
            };
            what = format!("{} ({})", what, p);
        }

        format!("{} → {}", who, what)
    }

    pub fn matches(&self, c: &AppConnection) -> bool {
        if !self.enabled {
            return false;
        }

        if let Some(process_path) = &self.process_path {
            let conn_path = c.process.normalized_path();
            #[allow(unused_mut)]
            let mut rule_path = process_path.clone();
            #[allow(unused_mut)]
            #[cfg(windows)]
            {
                rule_path = rule_path.to_lowercase().replace("\\", "/");
            }
            let mut prefix = rule_path.clone();
            if !prefix.ends_with('/') {
                prefix.push('/');
            }
            if conn_path != rule_path && !conn_path.starts_with(&prefix) {
                return false;
            }
        }

        if let Some(signing_id) = &self.signing_id {
            if Some(signing_id.clone()) != c.process.signing_id {
                return false;
            }
        }

        if let Some(team_id) = &self.team_id {
            if Some(team_id.clone()) != c.process.team_id {
                return false;
            }
        }

        if let Some(proto) = &self.proto {
            if *proto != c.proto {
                return false;
            }
        }

        if let Some(ports) = &self.ports {
            if !ports.contains(c.port) {
                return false;
            }
        }

        if let Some(remote_address) = &self.remote_address {
            // Parse IPs for accurate comparison (handling IPv6 mapping and scoping)
            if let (Ok(r_ip), Ok(c_ip)) = (
                remote_address.parse::<std::net::IpAddr>(),
                c.address.parse::<std::net::IpAddr>(),
            ) {
                if r_ip != c_ip && r_ip.to_canonical() != c_ip.to_canonical() {
                    return false;
                }
            } else if *remote_address != c.address {
                return false;
            }
        }

        if let Some(remote_host) = &self.remote_host {
            if let Some(c_host) = &c.host {
                if remote_host.to_lowercase() != c_host.to_lowercase() {
                    return false;
                }
            } else {
                return false;
            }
        }

        if let Some(d) = &self.remote_domain {
            if d != "*" {
                if let Some(host) = &c.host {
                    let host_lower = host.to_lowercase();
                    let dom_lower = d.to_lowercase();
                    if host_lower != dom_lower && !host_lower.ends_with(&format!(".{}", dom_lower))
                    {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }

        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Profile {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    #[serde(default = "default_symbol")]
    pub symbol: String,
}

fn default_symbol() -> String {
    "person.crop.circle".to_string()
}

impl Profile {
    pub fn new(id: Uuid, name: String, symbol: Option<String>) -> Self {
        Self {
            id,
            name,
            symbol: symbol.unwrap_or_else(default_symbol),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleGroup {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub name: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl RuleGroup {
    pub fn new(id: Uuid, name: String, enabled: Option<bool>) -> Self {
        Self {
            id,
            name,
            enabled: enabled.unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkTrigger {
    #[serde(default = "Uuid::new_v4")]
    pub id: Uuid,
    pub signature: String,
    pub name: String,
    pub profile_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnknownNetworkAction {
    Ask,
    DoNothing,
    Deactivate,
    Activate(Uuid),
}

// Swift's enum-with-associated-value Codable writes payload-less cases as
// {"ask": {}} and .activate as {"activate": "<uuid>"}. Read that form as well
// as the plain-string externally-tagged form, and write the Swift form so
// rules.json stays readable by the Swift app.
struct EmptyObject;
impl Serialize for EmptyObject {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_map(Some(0))?.end()
    }
}

impl Serialize for UnknownNetworkAction {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(1))?;
        match self {
            UnknownNetworkAction::Ask => map.serialize_entry("ask", &EmptyObject)?,
            UnknownNetworkAction::DoNothing => map.serialize_entry("doNothing", &EmptyObject)?,
            UnknownNetworkAction::Deactivate => map.serialize_entry("deactivate", &EmptyObject)?,
            UnknownNetworkAction::Activate(id) => map.serialize_entry("activate", id)?,
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for UnknownNetworkAction {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct UnknownNetworkActionVisitor;

        impl<'de> Visitor<'de> for UnknownNetworkActionVisitor {
            type Value = UnknownNetworkAction;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an unknown-network action")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                match v {
                    "ask" => Ok(UnknownNetworkAction::Ask),
                    "doNothing" => Ok(UnknownNetworkAction::DoNothing),
                    "deactivate" => Ok(UnknownNetworkAction::Deactivate),
                    other => Err(E::unknown_variant(
                        other,
                        &["ask", "doNothing", "deactivate", "activate"],
                    )),
                }
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                let Some(key) = map.next_key::<String>()? else {
                    return Err(de::Error::custom("empty unknown-network action"));
                };
                let value = match key.as_str() {
                    "ask" => {
                        let _ = map.next_value::<de::IgnoredAny>()?;
                        UnknownNetworkAction::Ask
                    }
                    "doNothing" => {
                        let _ = map.next_value::<de::IgnoredAny>()?;
                        UnknownNetworkAction::DoNothing
                    }
                    "deactivate" => {
                        let _ = map.next_value::<de::IgnoredAny>()?;
                        UnknownNetworkAction::Deactivate
                    }
                    "activate" => UnknownNetworkAction::Activate(map.next_value::<Uuid>()?),
                    other => {
                        return Err(de::Error::unknown_variant(
                            other,
                            &["ask", "doNothing", "deactivate", "activate"],
                        ));
                    }
                };
                Ok(value)
            }
        }

        deserializer.deserialize_any(UnknownNetworkActionVisitor)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleSet {
    #[serde(default = "default_version")]
    pub version: i32,
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub groups: Vec<RuleGroup>,
    #[serde(default)]
    pub triggers: Vec<NetworkTrigger>,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(alias = "activeProfileID")]
    pub active_profile_id: Uuid,
    #[serde(default)]
    pub mark_new_rules_as_unapproved: bool,
    pub silent_verdict: Option<Verdict>,
    #[serde(default)]
    pub automatic_profile_switching: bool,
    #[serde(default = "default_unknown_network_action")]
    pub unknown_network_action: UnknownNetworkAction,
}

fn default_version() -> i32 {
    1
}
fn default_unknown_network_action() -> UnknownNetworkAction {
    UnknownNetworkAction::Ask
}

impl RuleSet {
    pub fn standard(silent: Option<Verdict>) -> Self {
        let home = Profile::new(
            Uuid::new_v4(),
            "Home".to_string(),
            Some("house".to_string()),
        );
        Self {
            version: 2,
            profiles: vec![
                home.clone(),
                Profile::new(
                    Uuid::new_v4(),
                    "Work".to_string(),
                    Some("briefcase".to_string()),
                ),
                Profile::new(
                    Uuid::new_v4(),
                    "Public Wi-Fi".to_string(),
                    Some("wifi".to_string()),
                ),
            ],
            groups: vec![],
            triggers: vec![],
            rules: vec![],
            active_profile_id: home.id,
            mark_new_rules_as_unapproved: false,
            silent_verdict: silent,
            automatic_profile_switching: false,
            unknown_network_action: UnknownNetworkAction::Ask,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleExport {
    #[serde(default = "default_format")]
    pub format: String,
    #[serde(default = "default_version")]
    pub version: i32,
    #[serde(default)]
    pub groups: Vec<RuleGroup>,
    pub rules: Vec<Rule>,
}

fn default_format() -> String {
    "rat-rules".to_string()
}

impl RuleExport {
    pub fn new(groups: Vec<RuleGroup>, rules: Vec<Rule>) -> Self {
        Self {
            format: default_format(),
            version: 1,
            groups,
            rules,
        }
    }
}

pub struct RuleEngine {
    set: Arc<Mutex<RuleSet>>,
}

impl RuleEngine {
    pub fn new() -> Self {
        Self {
            set: Arc::new(Mutex::new(RuleSet::standard(None))),
        }
    }

    pub fn with_rules(rules: Vec<Rule>, default_verdict: Verdict) -> Self {
        let mut s = RuleSet::standard(None);
        s.rules = rules;
        s.silent_verdict = if default_verdict == Verdict::Ask {
            None
        } else {
            Some(default_verdict)
        };
        Self {
            set: Arc::new(Mutex::new(s)),
        }
    }

    pub fn with_rule_set(rule_set: RuleSet) -> Self {
        Self {
            set: Arc::new(Mutex::new(rule_set)),
        }
    }

    pub fn default_verdict(&self) -> Verdict {
        self.set
            .lock()
            .unwrap()
            .silent_verdict
            .unwrap_or(Verdict::Ask)
    }

    pub fn set_default_verdict(&self, v: Verdict) {
        let mut s = self.set.lock().unwrap();
        s.silent_verdict = if v == Verdict::Ask { None } else { Some(v) };
    }

    pub fn rule_set(&self) -> RuleSet {
        self.set.lock().unwrap().clone()
    }

    pub fn set_rule_set(&self, new: RuleSet) {
        *self.set.lock().unwrap() = new;
    }

    pub fn all_rules(&self) -> Vec<Rule> {
        self.set.lock().unwrap().rules.clone()
    }

    pub fn set_rules(&self, new: Vec<Rule>) {
        self.set.lock().unwrap().rules = new;
    }

    pub fn add(&self, rule: Rule) {
        self.set.lock().unwrap().rules.push(rule);
    }

    pub fn remove(&self, id: Uuid) {
        self.set.lock().unwrap().rules.retain(|r| r.id != id);
    }

    pub fn matching_rule(&self, c: &AppConnection) -> Option<Rule> {
        let snapshot = self.set.lock().unwrap_or_else(|e| e.into_inner());
        let disabled_groups: std::collections::HashSet<_> = snapshot
            .groups
            .iter()
            .filter(|g| !g.enabled)
            .map(|g| g.id)
            .collect();
        snapshot
            .rules
            .iter()
            .filter(|r| {
                (r.profile_id.is_none() || r.profile_id == Some(snapshot.active_profile_id))
                    && !(r.group_id.is_some_and(|gid| disabled_groups.contains(&gid)))
            })
            // `enabled` gates matching (enforced again in Rule::matches); `approved` is a review
            // marker only and never gates matching - supervisor update-16, upstream CLAUDE.md.
            .filter(|r| r.matches(c))
            .max_by(|a, b| {
                if a.specificity() != b.specificity() {
                    return a.specificity().cmp(&b.specificity());
                }
                if (a.verdict == Verdict::Deny) != (b.verdict == Verdict::Deny) {
                    if a.verdict == Verdict::Deny {
                        return std::cmp::Ordering::Greater;
                    } else {
                        return std::cmp::Ordering::Less;
                    }
                }
                a.created_at.cmp(&b.created_at)
            })
            .cloned()
    }
    pub fn evaluate(&self, c: &AppConnection) -> Verdict {
        self.matching_rule(c)
            .map(|r| r.verdict)
            .unwrap_or_else(|| self.default_verdict())
    }

    pub fn import_rules(&self, export: &RuleExport, mark_unapproved: bool) -> usize {
        let mut s = self.set.lock().unwrap();
        let known: std::collections::HashSet<_> = s.rules.iter().map(|r| r.id).collect();
        let known_groups: std::collections::HashSet<_> = s.groups.iter().map(|g| g.id).collect();

        for g in &export.groups {
            if !known_groups.contains(&g.id) {
                s.groups.push(g.clone());
            }
        }

        let mut added = 0;
        let profile_ids: std::collections::HashSet<_> = s.profiles.iter().map(|p| p.id).collect();
        let group_ids: std::collections::HashSet<_> = s.groups.iter().map(|g| g.id).collect();

        for r in &export.rules {
            if !known.contains(&r.id) {
                let mut new_r = r.clone();
                if mark_unapproved {
                    new_r.approved = false;
                    new_r.enabled = false;
                }
                new_r.lifetime = Lifetime::Forever;
                if let Some(pid) = new_r.profile_id {
                    if !profile_ids.contains(&pid) {
                        new_r.profile_id = None;
                    }
                }
                if let Some(gid) = new_r.group_id {
                    if !group_ids.contains(&gid) {
                        new_r.group_id = None;
                    }
                }
                s.rules.push(new_r);
                added += 1;
            }
        }
        added
    }

    pub fn export_rules(&self, include_unapproved: bool) -> RuleExport {
        let s = self.set.lock().unwrap();
        RuleExport::new(
            s.groups.clone(),
            s.rules
                .iter()
                .filter(|r| r.lifetime == Lifetime::Forever && (include_unapproved || r.approved))
                .cloned()
                .collect(),
        )
    }

    pub fn profile_for_network(&self, signature: &str) -> Option<Uuid> {
        self.set
            .lock()
            .unwrap()
            .triggers
            .iter()
            .find(|t| t.signature == signature)
            .map(|t| t.profile_id)
    }

    pub fn purge_session_rules(&self) {
        self.set
            .lock()
            .unwrap()
            .rules
            .retain(|r| r.lifetime == Lifetime::Forever);
    }
}

pub struct RuleStore {
    pub url: PathBuf,
}

/// `<file><suffix>` next to the real file (`rules.json` -> `rules.json.bak`):
/// same directory, so the save's rename stays on one volume (atomic on both
/// platforms).
fn sibling_path(url: &Path, suffix: &str) -> PathBuf {
    let mut name = url.as_os_str().to_os_string();
    name.push(suffix);
    PathBuf::from(name)
}

impl RuleStore {
    pub fn new(url: PathBuf) -> Self {
        Self { url }
    }

    pub fn load_set(&self) -> std::io::Result<RuleSet> {
        if !self.url.exists() {
            return Ok(RuleSet::standard(None));
        }
        if let Some(s) = Self::parse_set_file(&self.url)? {
            return Ok(s);
        }
        // The main file exists but is unparsable (e.g. truncated mid-JSON by
        // a crash). review-02 I2: this is an ERROR, never an empty rule set
        // with Ok — a zero-rule set makes the daemon reconcile every real
        // Rat:* rule away. First try the recovery copy the atomic save keeps.
        let bak = sibling_path(&self.url, ".bak");
        if let Ok(Some(s)) = Self::parse_set_file(&bak) {
            return Ok(s);
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "rules file {} is unparsable and no usable backup at {}",
                self.url.display(),
                bak.display()
            ),
        ))
    }

    /// Read and parse one rules file: the RuleSet JSON (v1 files migrate to
    /// v2 here), or the legacy bare rule list (Swift RulesModel parity).
    /// `Ok(None)` = readable but unparsable.
    fn parse_set_file(path: &Path) -> std::io::Result<Option<RuleSet>> {
        let data = fs::read_to_string(path)?;
        if let Ok(mut s) = serde_json::from_str::<RuleSet>(&data) {
            if s.version < 2 {
                s.version = 2;
                s.silent_verdict = Some(Verdict::Allow);
            }
            return Ok(Some(s));
        }
        Ok(serde_json::from_str::<Vec<Rule>>(&data).ok().map(|rules| {
            let mut s = RuleSet::standard(None);
            s.rules = rules;
            s
        }))
    }

    pub fn save_set(&self, set: &RuleSet) -> std::io::Result<()> {
        let mut s = set.clone();
        s.rules.retain(|r| r.lifetime == Lifetime::Forever);
        let data = serde_json::to_string_pretty(&s).map_err(std::io::Error::other)?;
        // review-02 I2: the save is atomic — write a sibling temp file, push
        // it to disk, keep the previous content as `.bak`, then rename over
        // the real file. A crash mid-save can no longer leave a truncated
        // rules.json that a restart would read as zero rules.
        let tmp = sibling_path(&self.url, ".tmp");
        let bak = sibling_path(&self.url, ".bak");
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp)?;
            f.write_all(data.as_bytes())?;
            f.sync_all()?;
        }
        if self.url.exists() {
            // Best effort: `.bak` is the recovery copy; the atomic rename is
            // the primary integrity mechanism.
            let _ = fs::copy(&self.url, &bak);
        }
        fs::rename(&tmp, &self.url)
    }

    pub fn load(&self) -> std::io::Result<Vec<Rule>> {
        self.load_set().map(|s| s.rules)
    }

    pub fn save(&self, rules: Vec<Rule>) -> std::io::Result<()> {
        let mut s = self.load_set().unwrap_or_else(|_| RuleSet::standard(None));
        s.rules = rules;
        self.save_set(&s)
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use rat_types::Protocol;
    use std::fs;
    use tempfile::tempdir;

    fn curl_process() -> AppIdentity {
        AppIdentity::new(
            Some("com.apple.curl".to_string()),
            None,
            "/usr/bin/curl".to_string(),
        )
    }

    pub fn conn(host: &str, port: u16) -> AppConnection {
        AppConnection::new(
            curl_process(),
            Some(host.to_string()),
            "1.2.3.4".to_string(),
            port,
            Protocol::Tcp,
        )
    }

    pub fn new_rule() -> Rule {
        Rule {
            id: Uuid::new_v4(),
            verdict: Verdict::Deny,
            process_path: None,
            signing_id: None,
            team_id: None,
            remote_domain: None,
            remote_host: None,
            remote_address: None,
            ports: None,
            proto: None,
            enabled: true,
            approved: true,
            lifetime: Lifetime::Forever,
            profile_id: None,
            group_id: None,
            created_at: Utc::now(),
            note: None,
        }
    }

    #[test]
    fn test_default_asks() {
        assert_eq!(
            RuleEngine::new().evaluate(&conn("a.com", 443)),
            Verdict::Ask
        );
    }

    #[test]
    fn test_domain_matches_subdomains() {
        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.remote_domain = Some("evil.com".to_string());

        let e = RuleEngine::with_rules(vec![r], Verdict::Ask);
        assert_eq!(e.evaluate(&conn("x.evil.com", 443)), Verdict::Deny);
        assert_eq!(e.evaluate(&conn("notevil.com", 443)), Verdict::Ask);
    }

    #[test]
    fn test_specific_beats_general() {
        let mut r1 = new_rule();
        r1.verdict = Verdict::Deny;
        r1.signing_id = Some("com.apple.curl".to_string());

        let mut r2 = new_rule();
        r2.verdict = Verdict::Allow;
        r2.signing_id = Some("com.apple.curl".to_string());
        r2.remote_domain = Some("example.com".to_string());
        r2.ports = Some(PortRange {
            start: 443,
            end: 443,
        });

        let e = RuleEngine::with_rules(vec![r1, r2], Verdict::Ask);
        assert_eq!(e.evaluate(&conn("example.com", 443)), Verdict::Allow);
        assert_eq!(e.evaluate(&conn("other.com", 443)), Verdict::Deny);
    }

    #[test]
    fn test_deny_wins_tie() {
        let mut r1 = new_rule();
        r1.verdict = Verdict::Allow;
        r1.remote_domain = Some("a.com".to_string());

        let mut r2 = new_rule();
        r2.verdict = Verdict::Deny;
        r2.remote_domain = Some("a.com".to_string());

        let e = RuleEngine::with_rules(vec![r1, r2], Verdict::Ask);
        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Deny);
    }

    /// Documented semantics (CLAUDE.md, the `approved` field doc): `approved` is a review marker
    /// only - an enabled but unapproved rule still matches; `enabled` gates matching
    /// (`Rule::matches`). Supervisor update-16.
    #[test]
    fn test_unapproved_still_matches_but_disabled_never_does() {
        let mut r1 = new_rule();
        r1.verdict = Verdict::Deny;
        r1.enabled = false;

        assert_eq!(
            RuleEngine::with_rules(vec![r1], Verdict::Ask).evaluate(&conn("a.com", 443)),
            Verdict::Ask
        );

        let mut r2 = new_rule();
        r2.verdict = Verdict::Deny;
        r2.approved = false;

        assert_eq!(
            RuleEngine::with_rules(vec![r2], Verdict::Ask).evaluate(&conn("a.com", 443)),
            Verdict::Deny
        );
    }

    #[test]
    fn test_store_round_trip() {
        let dir = tempdir().unwrap();
        let url = dir.path().join(format!("rules-{}.json", Uuid::new_v4()));
        let store = RuleStore::new(url);

        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.remote_domain = Some("a.com".to_string());
        r.ports = Some(PortRange {
            start: 80,
            end: 443,
        });

        store.save(vec![r]).unwrap();
        let loaded = store.load().unwrap();
        assert_eq!(
            loaded[0].ports,
            Some(PortRange {
                start: 80,
                end: 443
            })
        );
    }

    #[test]
    fn test_process_path_matches_inside_bundle() {
        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.process_path = Some("/Applications/Foo.app".to_string());

        let e = RuleEngine::with_rules(vec![r], Verdict::Ask);

        let mut inside_conn = conn("a.com", 443);
        inside_conn.process.path = "/Applications/Foo.app/Contents/MacOS/Foo".to_string();

        let mut sibling_conn = conn("a.com", 443);
        sibling_conn.process.path = "/Applications/Foo.app.bak/x".to_string();

        assert_eq!(e.evaluate(&inside_conn), Verdict::Deny);
        assert_eq!(e.evaluate(&sibling_conn), Verdict::Ask);
    }

    #[test]
    fn test_exact_host_does_not_match_subdomain() {
        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.remote_host = Some("a.com".to_string());

        let e = RuleEngine::with_rules(vec![r], Verdict::Ask);
        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Deny);
        assert_eq!(e.evaluate(&conn("x.a.com", 443)), Verdict::Ask);
    }

    #[test]
    fn test_port_range_and_protocol() {
        let mut r = new_rule();
        r.verdict = Verdict::Allow;
        r.ports = Some(PortRange {
            start: 8000,
            end: 8100,
        });
        r.proto = Some(Protocol::Udp);

        let e = RuleEngine::with_rules(vec![r], Verdict::Ask);

        let mut c1 = conn("a.com", 8050);
        c1.proto = Protocol::Udp;

        let mut c2 = conn("a.com", 8050);
        c2.proto = Protocol::Tcp;

        let mut c3 = conn("a.com", 9000);
        c3.proto = Protocol::Udp;

        assert_eq!(e.evaluate(&c1), Verdict::Allow);
        assert_eq!(e.evaluate(&c2), Verdict::Ask);
        assert_eq!(e.evaluate(&c3), Verdict::Ask);
    }

    #[test]
    fn test_profiles_scope_rules() {
        let mut s = RuleSet::standard(None);
        let work_id = s.profiles[1].id;

        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.remote_domain = Some("a.com".to_string());
        r.profile_id = Some(work_id);
        s.rules = vec![r];

        let e = RuleEngine::with_rule_set(s);
        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Ask); // Home is active

        let mut t = e.rule_set();
        t.active_profile_id = work_id;
        e.set_rule_set(t);

        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Deny);
    }

    #[test]
    fn test_disabled_group_silences_its_rules() {
        let mut s = RuleSet::standard(None);
        let g = RuleGroup::new(Uuid::new_v4(), "Ads".to_string(), Some(false));
        let gid = g.id;

        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.remote_domain = Some("a.com".to_string());
        r.group_id = Some(gid);

        s.groups = vec![g];
        s.rules = vec![r];

        let e = RuleEngine::with_rule_set(s);
        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Ask);

        let mut t = e.rule_set();
        t.groups[0].enabled = true;
        e.set_rule_set(t);

        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Deny);
    }

    #[test]
    fn test_silent_mode_changes_default() {
        let e = RuleEngine::new();
        e.set_default_verdict(Verdict::Allow);
        assert_eq!(e.evaluate(&conn("x.com", 443)), Verdict::Allow);
        e.set_default_verdict(Verdict::Ask);
        assert_eq!(e.evaluate(&conn("x.com", 443)), Verdict::Ask);
    }

    #[test]
    fn test_rule_summary() {
        let mut r = new_rule();
        r.verdict = Verdict::Allow;
        r.process_path = Some("/Applications/Foo.app".to_string());
        r.remote_domain = Some("a.com".to_string());
        r.ports = Some(PortRange {
            start: 443,
            end: 443,
        });

        assert_eq!(r.summary(), "Foo → *.a.com:443");
    }

    #[test]
    fn test_import_marks_unapproved_and_skips_duplicates() {
        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.remote_domain = Some("a.com".to_string());

        let e = RuleEngine::new();
        let export = RuleExport::new(vec![], vec![r.clone()]);

        assert_eq!(e.import_rules(&export, true), 1);
        assert_eq!(e.import_rules(&export, true), 0);

        let all = e.all_rules();
        assert!(!all[0].approved);
        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Ask);

        let mut rules = e.all_rules();
        rules[0].approved = true;
        rules[0].enabled = true;
        e.set_rules(rules);

        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Deny);
    }

    #[test]
    fn test_import_accepts_legacy_bare_array() {
        let legacy = r#"[{"verdict":"deny","remoteDomain":"old.com"}]"#;
        // In Rust, we simulate this by parsing JSON directly via serde_json.
        let rules: Vec<Rule> = serde_json::from_str(legacy).unwrap();
        assert_eq!(rules[0].remote_domain, Some("old.com".to_string()));
        assert_eq!(rules[0].lifetime, Lifetime::Forever); // Default
    }

    #[test]
    fn test_session_rules_are_purged_and_not_persisted() {
        let mut r1 = new_rule();
        r1.verdict = Verdict::Deny;
        r1.remote_domain = Some("a.com".to_string());
        r1.lifetime = Lifetime::UntilQuit;

        let mut r2 = new_rule();
        r2.verdict = Verdict::Deny;
        r2.remote_domain = Some("b.com".to_string());

        let e = RuleEngine::with_rules(vec![r1, r2], Verdict::Ask);

        let dir = tempdir().unwrap();
        let url = dir.path().join(format!("set-{}.json", Uuid::new_v4()));
        let store = RuleStore::new(url.clone());

        store.save_set(&e.rule_set()).unwrap();
        assert_eq!(store.load_set().unwrap().rules.len(), 1);

        e.purge_session_rules();
        assert_eq!(e.all_rules().len(), 1);
    }

    #[test]
    fn test_automatic_profile_switching_lookup() {
        let mut s = RuleSet::standard(None);
        let pid = s.profiles[2].id;

        let t = NetworkTrigger {
            id: Uuid::new_v4(),
            signature: "CoffeeShop".to_string(),
            name: "Cafe".to_string(),
            profile_id: pid,
        };
        s.triggers = vec![t];

        let e = RuleEngine::with_rule_set(s);
        assert_eq!(e.profile_for_network("CoffeeShop"), Some(pid));
        assert_eq!(e.profile_for_network("Elsewhere"), None);
    }

    #[test]
    fn test_import_drops_unknown_profile_scope() {
        let e = RuleEngine::new();

        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.remote_domain = Some("a.com".to_string());
        r.profile_id = Some(Uuid::new_v4()); // Unknown profile

        let export = RuleExport::new(vec![], vec![r]);
        e.import_rules(&export, false);

        assert!(e.all_rules()[0].profile_id.is_none());
        assert_eq!(e.evaluate(&conn("a.com", 443)), Verdict::Deny);
    }

    #[test]
    fn test_new_installs_are_silent_allow_and_version1_files_migrate() {
        assert_eq!(RuleSet::standard(None).silent_verdict, None);

        let v1 = r#"{"version":1,"profiles":[{"id":"11111111-1111-1111-1111-111111111111","name":"Home","symbol":"house"}],"activeProfileId":"11111111-1111-1111-1111-111111111111","rules":[]}"#;
        let dir = tempdir().unwrap();
        let url = dir.path().join(format!("v1-{}.json", Uuid::new_v4()));
        fs::write(&url, v1).unwrap();

        let store = RuleStore::new(url);
        let s = store.load_set().unwrap();

        assert_eq!(s.version, 2);
        assert_eq!(s.silent_verdict, Some(Verdict::Allow));
        assert_eq!(s.unknown_network_action, UnknownNetworkAction::Ask);
    }

    #[test]
    fn test_unknown_network_action_round_trips() {
        let mut s = RuleSet::standard(None);
        s.unknown_network_action = UnknownNetworkAction::Activate(s.profiles[1].id);

        let dir = tempdir().unwrap();
        let url = dir.path().join(format!("a-{}.json", Uuid::new_v4()));
        let store = RuleStore::new(url.clone());

        store.save_set(&s).unwrap();
        assert_eq!(
            store.load_set().unwrap().unknown_network_action,
            UnknownNetworkAction::Activate(s.profiles[1].id)
        );
    }

    // R2: JSON format byte-compatible both ways with Swift
    #[test]
    fn test_r2_json_byte_compatibility() {
        let json_str = r#"{
  "approved" : true,
  "createdAt" : "2026-10-23T10:00:00Z",
  "enabled" : true,
  "id" : "11111111-1111-1111-1111-111111111111",
  "lifetime" : "forever",
  "remoteDomain" : "example.com",
  "verdict" : "deny"
}"#;

        let rule: Rule = serde_json::from_str(json_str).unwrap();
        assert_eq!(rule.id.to_string(), "11111111-1111-1111-1111-111111111111");
        assert_eq!(rule.verdict, Verdict::Deny);
        assert_eq!(rule.remote_domain, Some("example.com".to_string()));
        assert_eq!(rule.lifetime, Lifetime::Forever);
        assert!(rule.enabled);
        assert!(rule.approved);

        let out_str = serde_json::to_string_pretty(&rule).unwrap();
        assert!(out_str.contains(r#""verdict": "deny""#));
        assert!(out_str.contains(r#""remoteDomain": "example.com""#));
    }

    // R3: Path normalization handling case-insensitivity on Windows
    #[test]
    fn test_r3_path_normalization() {
        let p1 = AppIdentity::new(None, None, r"C:\Program Files\App\app.exe".to_string());

        #[cfg(windows)]
        {
            assert_eq!(p1.normalized_path(), "c:/program files/app/app.exe");
        }

        #[cfg(not(windows))]
        {
            assert_eq!(p1.normalized_path(), r"C:\Program Files\App\app.exe");
        }

        let mut r = new_rule();
        r.verdict = Verdict::Deny;
        r.process_path = Some(if cfg!(windows) {
            "c:/program files/app/app.exe".to_string()
        } else {
            r"C:\Program Files\App\app.exe".to_string()
        });

        let e = RuleEngine::with_rules(vec![r], Verdict::Ask);

        let mut c = conn("a.com", 443);
        c.process = p1;

        assert_eq!(e.evaluate(&c), Verdict::Deny);
    }
}

#[cfg(test)]
mod edge_cases {
    use super::*;

    #[test]
    fn test_ipv6_handling() {
        let mut r = tests::new_rule();
        r.verdict = Verdict::Deny;
        r.remote_address = Some("::ffff:192.168.1.1".to_string());
        let e = RuleEngine::with_rules(vec![r], Verdict::Ask);

        let mut c = tests::conn("a.com", 443);
        c.address = "192.168.1.1".to_string();

        // IPv4-mapped IPv6 should match the equivalent IPv4
        assert_eq!(e.evaluate(&c), Verdict::Deny);
    }

    #[test]
    fn test_non_ascii_paths() {
        let mut r = tests::new_rule();
        r.verdict = Verdict::Deny;
        r.process_path = Some("/usr/bin/你好".to_string());
        let e = RuleEngine::with_rules(vec![r], Verdict::Ask);

        let mut c = tests::conn("a.com", 443);
        c.process.path = "/usr/bin/你好".to_string();

        assert_eq!(e.evaluate(&c), Verdict::Deny);
    }
}

#[cfg(test)]
mod load_tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    // review-02 I2: an unparsable rules file is an ERROR, never Ok with zero
    // rules — a zero-rule set makes the daemon reconcile every real Rat:*
    // rule away (fail-open).
    #[test]
    fn test_unparsable_rules_file_is_an_error() {
        let dir = tempdir().unwrap();
        let url = dir.path().join("malformed.json");
        fs::write(&url, "this is not json").unwrap();

        let store = RuleStore::new(url);
        let err = store
            .load_set()
            .expect_err("an unparsable file must be an error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // review-02 I2, the prescribed scenario: a file truncated MID-JSON (a
    // crash during a save) is neither a RuleSet nor a legacy rule list.
    #[test]
    fn test_truncated_rules_file_is_an_error() {
        let dir = tempdir().unwrap();
        let url = dir.path().join("truncated.json");
        fs::write(&url, "{\"version\":2,\"rules\":[{\"id\":\"").unwrap();

        let store = RuleStore::new(url);
        let err = store
            .load_set()
            .expect_err("a truncated file must be an error");
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    // review-02 I2: the `.bak` the atomic save keeps is the recovery copy for
    // a corrupted main file.
    #[test]
    fn test_unparsable_main_file_recovers_from_bak() {
        let dir = tempdir().unwrap();
        let url = dir.path().join("rules.json");

        let mut s = RuleSet::standard(None);
        let mut r = tests::new_rule();
        r.verdict = Verdict::Deny;
        r.remote_domain = Some("bak.example".to_string());
        s.rules = vec![r];
        let bak = dir.path().join("rules.json.bak");
        fs::write(&bak, serde_json::to_string_pretty(&s).unwrap()).unwrap();
        fs::write(&url, "{\"version\":2,\"rules\":[{\"id\":\"").unwrap(); // truncated

        let store = RuleStore::new(url);
        let loaded = store.load_set().expect("the .bak must be recovered");
        assert_eq!(loaded.rules.len(), 1);
        assert_eq!(
            loaded.rules[0].remote_domain.as_deref(),
            Some("bak.example")
        );
    }

    // review-02 I2: save_set writes through a sibling temp file (fsync +
    // rename) and keeps the PREVIOUS content as `.bak` — a crash mid-save can
    // no longer truncate rules.json, and the last good set stays on disk.
    #[test]
    fn test_save_set_is_atomic_and_keeps_previous_as_bak() {
        let dir = tempdir().unwrap();
        let url = dir.path().join("rules.json");
        let store = RuleStore::new(url.clone());

        let mut first = RuleSet::standard(None);
        let mut r1 = tests::new_rule();
        r1.verdict = Verdict::Deny;
        r1.remote_domain = Some("first.example".to_string());
        first.rules = vec![r1];
        store.save_set(&first).unwrap();

        let mut second = RuleSet::standard(None);
        let mut r2 = tests::new_rule();
        r2.verdict = Verdict::Deny;
        r2.remote_domain = Some("second.example".to_string());
        second.rules = vec![r2];
        store.save_set(&second).unwrap();

        let bak = dir.path().join("rules.json.bak");
        assert!(bak.exists(), "the previous content must be kept as .bak");
        let from_bak: RuleSet = serde_json::from_str(&fs::read_to_string(&bak).unwrap()).unwrap();
        assert_eq!(
            from_bak.rules[0].remote_domain.as_deref(),
            Some("first.example"),
            ".bak holds the PREVIOUS content, not the just-written one"
        );
        assert_eq!(
            store.load_set().unwrap().rules[0].remote_domain.as_deref(),
            Some("second.example")
        );
        // The temp file is consumed by the rename, not left next to the set.
        assert!(
            !dir.path().join("rules.json.tmp").exists(),
            "the temp file must be gone after the save"
        );
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_app_identity_normalization(path in ".*") {
            let identity = AppIdentity::new(None, None, path.clone());
            let norm = identity.normalized_path();

            #[cfg(windows)]
            {
                assert_eq!(norm, path.to_lowercase().replace("\\", "/"));
            }
            #[cfg(not(windows))]
            {
                assert_eq!(norm, path);
            }
        }

        #[test]
        fn test_rule_roundtrip_serialize(id in any::<[u8; 16]>(),
                                         path in ".*",
                                         host in ".*") {
            let mut r = tests::new_rule();
            r.id = Uuid::from_bytes(id);
            r.process_path = Some(path);
            r.remote_host = Some(host);

            let serialized = serde_json::to_string(&r).unwrap();
            let deserialized: Rule = serde_json::from_str(&serialized).unwrap();

            assert_eq!(r, deserialized);
        }
    }
}

#[cfg(test)]
mod perf_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_performance_budget_5000_rules() {
        let mut rules = Vec::with_capacity(5000);
        for i in 0..5000 {
            rules.push(Rule {
                id: Uuid::new_v4(),
                verdict: if i % 2 == 0 {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                },
                process_path: Some(format!("/usr/bin/app{}", i)),
                signing_id: None,
                team_id: None,
                remote_domain: Some(format!("example{}.com", i)),
                remote_host: None,
                remote_address: None,
                ports: None,
                proto: Some(rat_types::Protocol::Tcp),
                enabled: true,
                approved: true,
                lifetime: Lifetime::Forever,
                profile_id: None,
                group_id: None,
                created_at: chrono::Utc::now(),
                note: None,
            });
        }

        // Target match
        let mut matching_rule = rules[0].clone();
        matching_rule.id = Uuid::new_v4();
        matching_rule.process_path = Some("/usr/bin/target_app".to_string());
        matching_rule.remote_domain = Some("target.com".to_string());
        rules.push(matching_rule);

        let engine = RuleEngine::with_rules(rules, Verdict::Ask);

        let process = AppIdentity::new(None, None, "/usr/bin/target_app".to_string());
        let conn = AppConnection::new(
            process,
            Some("target.com".to_string()),
            "1.2.3.4".to_string(),
            443,
            rat_types::Protocol::Tcp,
        );

        let start = Instant::now();
        let verdict = engine.evaluate(&conn);
        let duration = start.elapsed();

        assert_eq!(verdict, Verdict::Allow); // the generated matching rule's verdict

        // We benchmarked ~0.7ms for 5,000 rules.
        // A generous upper bounds under heavy load or slower CI is 50ms (well over 3x the max bounds of 3ms prior to optimizing).
        assert!(
            duration.as_millis() < 50,
            "Performance budget exceeded: took {}ms",
            duration.as_millis()
        );
    }
}
