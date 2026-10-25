//! PROPOSALS #6: the home position must resolve on Windows without a
//! system zone.tab, and every zone the CLDR map can produce must have
//! vendored coordinates (except the Etc/* offsets, which have no reference
//! city — the Swift app's zone.tab lookup also returns None for them).

use rat_geo::TimeZoneLocator;
use rat_geo::windows_tz::{WINDOWS_TO_IANA, map_windows_zone_to_iana};

#[test]
fn test_every_mapped_windows_zone_resolves_to_coordinates() {
    assert!(WINDOWS_TO_IANA.len() > 100);
    for (windows, iana) in WINDOWS_TO_IANA {
        assert_eq!(map_windows_zone_to_iana(windows), Some(*iana));
        if iana.starts_with("Etc/") {
            assert_eq!(
                TimeZoneLocator::zone_coordinates(iana),
                None,
                "Etc/* zone {iana} should have no reference city"
            );
        } else {
            assert!(
                TimeZoneLocator::zone_coordinates(iana).is_some(),
                "no vendored coordinates for {iana}"
            );
        }
    }
}

#[test]
fn test_known_home_positions() {
    for (zone, lat, lon) in [
        ("America/New_York", 40.71, -74.01),
        ("Europe/Berlin", 52.5, 13.37),
        ("Pacific/Honolulu", 21.31, -157.86),
        ("Asia/Calcutta", 22.57, 88.37), // legacy spelling the CLDR map yields
        ("Europe/Kiev", 50.43, 30.52),   // legacy spelling the CLDR map yields
        ("America/Buenos_Aires", -34.61, -58.38),
    ] {
        let (got_lat, got_lon) = TimeZoneLocator::zone_coordinates(zone)
            .unwrap_or_else(|| panic!("no coordinates for {zone}"));
        assert!(
            (got_lat - lat).abs() < 0.5,
            "{zone}: latitude {got_lat} far from {lat}"
        );
        assert!(
            (got_lon - lon).abs() < 0.5,
            "{zone}: longitude {got_lon} far from {lon}"
        );
    }

    assert_eq!(TimeZoneLocator::zone_coordinates("Mars/Olympus_Mons"), None);
}
