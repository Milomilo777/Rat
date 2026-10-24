use rat_monitor_windows::{parse_port, convert_ipv4_addr, convert_ipv6_addr, extract_process_name_from_path, check_is_vpn_interface_type};
use proptest::prelude::*;

proptest! {
    #[test]
    fn test_parse_port_prop(port in any::<u32>()) {
        let p1 = parse_port(port);
        let p2 = parse_port(port);
        assert_eq!(p1, p2);
    }

    #[test]
    fn test_convert_ipv4_addr_prop(addr in any::<u32>()) {
        let ip1 = convert_ipv4_addr(addr);
        let ip2 = convert_ipv4_addr(addr);
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_convert_ipv6_addr_prop(addr in any::<[u8; 16]>()) {
        let ip1 = convert_ipv6_addr(&addr);
        let ip2 = convert_ipv6_addr(&addr);
        assert_eq!(ip1, ip2);
    }

    #[test]
    fn test_extract_process_name_from_path_prop(path in any::<String>()) {
        let name1 = extract_process_name_from_path(Some(std::path::Path::new(&path)));
        let name2 = extract_process_name_from_path(Some(std::path::Path::new(&path)));
        assert_eq!(name1, name2);
    }

    #[test]
    fn test_check_is_vpn_interface_type_prop(if_type in any::<u32>(), alias in any::<String>()) {
        let is_vpn1 = check_is_vpn_interface_type(if_type, &alias);
        let is_vpn2 = check_is_vpn_interface_type(if_type, &alias);
        assert_eq!(is_vpn1, is_vpn2);
    }
}
