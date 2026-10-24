#![no_main]

use libfuzzer_sys::fuzz_target;
use rat_names::{Resolver, ResolverConfig};

fuzz_target!(|data: &[u8]| {
    if let Ok(name) = std::str::from_utf8(data) {
        let config = ResolverConfig::default();
        if let Ok(resolver) = Resolver::new(config) {
            // Our backend isn't real, but we can fuzz IDNA converting if we use it,
            // though our crate doesn't expose IDNA directly, only through resolve.
            // Let's create a custom backend that returns the fuzzed string
            struct FuzzBackend { response: String }
            impl rat_names::resolver::LookupBackend for FuzzBackend {
                fn reverse_lookup(&self, _ip: std::net::IpAddr) -> Option<String> {
                    Some(self.response.clone())
                }
            }

            let backend = std::sync::Arc::new(FuzzBackend { response: name.to_string() });
            let config2 = ResolverConfig::default();
            if let Ok(r2) = Resolver::with_backend(config2, backend) {
                let _ = r2.resolve("1.1.1.1".parse().unwrap());
            }
        }
    }
});
