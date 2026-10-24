
## Final state

Final check outputs:

```
$ CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test --target x86_64-pc-windows-gnu --manifest-path port/Cargo.toml

running 7 tests
test edge_case_tests::test_extract_process_name_from_path ... ok
test edge_case_tests::test_ipv6_variations ... ok
test tests::test_convert_ipv4_addr ... ok
test tests::test_convert_ipv6_addr ... ok
test tests::test_is_listening_state ... ok
test tests::test_parse_port ... ok
test vpn_tests::test_check_is_vpn_interface_type ... ok

test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s


running 3 tests
test test_budget_check_is_vpn ... ok
test test_budget_parse_port ... ok
test test_budget_extract_process_name ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 5 tests
test test_convert_ipv4_addr_prop ... ok
test test_convert_ipv6_addr_prop ... ok
test test_parse_port_prop ... ok
test test_check_is_vpn_interface_type_prop ... ok
test test_extract_process_name_from_path_prop ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.09s


running 6 tests
test wine_tests::test_backslash_and_unc_paths ... ok
test wine_tests::test_crlf_line_endings ... ok
test wine_tests::test_drive_letter_case ... ok
test wine_tests::test_file_locking ... ok
test wine_tests::test_long_paths ... ok
test wine_tests::test_utf16_non_ascii_names ... ok

test result: ok. 6 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
```
