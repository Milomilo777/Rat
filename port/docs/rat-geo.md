# rat-geo

## Purpose
`rat-geo` is the geolocation backend for Rat's network monitoring. It provides offline IP-to-location mapping using DB-IP (or compatible MaxMind MMDB) databases, resolving country codes, city names, and coordinates. It also provides offline time-zone-based approximate location lookup to determine the user's home position. Finally, it resolves Autonomous System Numbers (ASN) to network owners.

## Public API

```rust
use rat_geo::{GeoIP, ASNDatabase, TimeZoneLocator};

// 1. IP Geolocation
let geo_db = GeoIP::new("/path/to/dbip-city-lite.mmdb").expect("Valid MMDB");
if let Some(location) = geo_db.locate("1.2.3.4".parse().unwrap()) {
    println!("{} in {}", location.city, location.country);
}

// 2. ASN lookup
let asn_db = ASNDatabase::new("/path/to/dbip-asn-lite.mmdb").expect("Valid ASN MMDB");
if let Some(owner) = asn_db.owner("1.1.1.1".parse().unwrap()) {
    println!("Network: {}", owner.label());
}

// 3. Time zone location
if let Some((lat, lon, city)) = TimeZoneLocator::coordinates() {
    println!("Home coordinates: {}, {}", lat, lon);
}
```

## Platform Notes
- **Linux:** Coordinates lookup reads `/etc/localtime` (a symlink) and `/usr/share/zoneinfo/zone.tab`. Both are standard reads available to unprivileged users.
- **Windows:** Coordinates lookup invokes the built-in `tzutil /g` utility and translates the result using a vendored CLDR mapping. No admin privileges required. (Currently the `tzutil` call and reading process is included, though `tzutil` execution tests can't be run on Linux).

## Known Limits
- Built for offline databases: only DB-IP Lite or MaxMind GeoLite2 databases (or equivalently-shaped MMDB files) are supported.
- `TimeZoneLocator::coordinates()` gives only the approximate geographic center assigned to the current time zone in `zone.tab`, not an exact GPS position.
- Network lookups skip private, link-local, loopback, and multicast addresses.
- The underlying `maxminddb` crate correctly handles bounds checks and sets decoding limits to prevent untrusted input from panicking or infinitely looping, thus maintaining the untrusted-input bounds requirements.
