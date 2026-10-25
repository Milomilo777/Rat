//! Pure generator of the nftables script. Kept free of OS calls so it is
//! compiled and unit-tested on every platform (the nft glue is Linux-only).

/// Build the atomic `nft -f -` script for the given local ports.
///
/// `flush table` empties chains but NOT set elements, and re-declaring a set
/// ADDS elements to the existing one, so ports blocked once would never be
/// released. The script therefore does `add table` (creates it if missing, so
/// the next `delete` cannot fail) + `delete table` + the full definition, all
/// in one transaction.
pub fn nft_script(local_ports: &[u16]) -> String {
    let mut ports = local_ports.to_vec();
    ports.sort_unstable();
    ports.dedup();

    let ports_str = if ports.is_empty() {
        String::new()
    } else {
        let p: Vec<String> = ports.iter().map(|p| p.to_string()).collect();
        format!("elements = {{ {} }}\n\t\t", p.join(", "))
    };

    format!(
        "add table inet rat\n\
         delete table inet rat\n\
         table inet rat {{\n\
             \tset rat_ports {{\n\
                 \t\ttype inet_service\n\
                 \t\t{}\
             }}\n\
             \tchain drop_out {{\n\
                 \t\ttype filter hook output priority filter; policy accept;\n\
                 \t\ttcp sport @rat_ports drop\n\
                 \t\tudp sport @rat_ports drop\n\
             \t}}\n\
             \tchain drop_in {{\n\
                 \t\ttype filter hook input priority filter; policy accept;\n\
                 \t\ttcp dport @rat_ports drop\n\
                 \t\tudp dport @rat_ports drop\n\
             \t}}\n\
         }}\n",
        ports_str
    )
}

#[cfg(test)]
mod tests {
    use super::nft_script;

    #[test]
    fn deletes_table_before_defining_it() {
        let plan = nft_script(&[23886]);
        let add = plan.find("add table inet rat\n").expect("add table");
        let del = plan.find("delete table inet rat\n").expect("delete table");
        let def = plan.find("table inet rat {").expect("table definition");
        let set = plan.find("set rat_ports {").expect("set definition");
        let elems = plan.find("elements = {").expect("elements");
        assert!(add < del && del < def && def < set && set < elems);
        assert_eq!(plan.matches("delete table").count(), 1);
        assert!(!plan.contains("flush table"));
    }

    #[test]
    fn empty_port_list_has_no_elements() {
        let plan = nft_script(&[]);
        assert!(plan.contains("set rat_ports {"));
        assert!(!plan.contains("elements"));
    }

    #[test]
    fn shrinking_ports_leaves_no_stale_element() {
        let before = nft_script(&[23886, 26357]);
        let after = nft_script(&[23886]);
        assert!(before.contains("elements = { 23886, 26357 }"));
        assert!(after.contains("elements = { 23886 }"));
        assert!(!after.contains("26357"));
    }

    #[test]
    fn ports_sorted_and_deduplicated() {
        assert!(nft_script(&[8080, 443, 8080]).contains("elements = { 443, 8080 }"));
    }
}
