sed -i 's#Self::lookup_in_zone_tab(iana, "/usr/share/zoneinfo/zone.tab")\n        None#Self::lookup_in_zone_tab(iana, "/usr/share/zoneinfo/zone.tab")#' port/crates/rat-geo/src/lib.rs
