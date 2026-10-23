#[cfg(test)]
mod tests {
    use super::super::*;
    use rat_types::Protocol;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    struct MockBackend {
        ip: IpAddr,
        response: Option<String>,
        delay: Option<Duration>,
        called: Arc<Mutex<usize>>,
    }

    impl resolver::LookupBackend for MockBackend {
        fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
            let mut called = self.called.lock().unwrap();
            *called += 1;

            if ip == self.ip {
                if let Some(delay) = self.delay {
                    std::thread::sleep(delay);
                }
                self.response.clone()
            } else {
                None
            }
        }
    }

    #[test]
    fn test_service_names() {
        assert_eq!(services::service_name(443, Protocol::Tcp), Some("HTTPS"));
        assert_eq!(services::service_name(443, Protocol::Udp), Some("QUIC"));
        assert_eq!(services::service_name(80, Protocol::Tcp), Some("HTTP"));
        assert_eq!(services::service_name(12345, Protocol::Tcp), None);
    }

    #[test]
    fn test_idn_names() {
        let called = Arc::new(Mutex::new(0));
        let backend = Arc::new(MockBackend {
            ip: "1.1.1.1".parse().unwrap(),
            response: Some("www.xn--0zwm56d.com".to_string()),
            delay: None,
            called: called.clone(),
        });

        let config = ResolverConfig::default();
        let resolver = Resolver::with_backend(config, backend).unwrap();

        let info = resolver.resolve("1.1.1.1".parse().unwrap()).unwrap();
        assert_eq!(info.display_name, "www.测试.com");
        assert_eq!(info.punycode, "www.xn--0zwm56d.com");

        // Persian
        let called2 = Arc::new(Mutex::new(0));
        let backend2 = Arc::new(MockBackend {
            ip: "2.2.2.2".parse().unwrap(),
            response: Some("xn--mgba3a4f16a.com".to_string()), // ایران.com
            delay: None,
            called: called2.clone(),
        });

        let config2 = ResolverConfig::default();
        let resolver2 = Resolver::with_backend(config2, backend2).unwrap();
        let info2 = resolver2.resolve("2.2.2.2".parse().unwrap()).unwrap();
        assert_eq!(info2.display_name, "ایران.com");
        assert_eq!(info2.punycode, "xn--mgba3a4f16a.com");

        assert_eq!(info, info.clone());
        assert_ne!(info, info2);
    }

    #[test]
    fn test_edge_cases() {
        // Very long name
        let long_name = "a".repeat(200) + ".com";
        let called = Arc::new(Mutex::new(0));
        let backend = Arc::new(MockBackend {
            ip: "10.0.0.1".parse().unwrap(),
            response: Some(long_name.clone()),
            delay: None,
            called: called.clone(),
        });

        let config = ResolverConfig::default();
        let resolver = Resolver::with_backend(config, backend).unwrap();
        let info = resolver.resolve("10.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(info.display_name, long_name);
        assert_eq!(info.punycode, long_name);

        // IPv6 Link-Local
        let called = Arc::new(Mutex::new(0));
        let backend = Arc::new(MockBackend {
            ip: "fe80::1".parse().unwrap(),
            response: Some("local-router".to_string()),
            delay: None,
            called: called.clone(),
        });

        let config = ResolverConfig::default();
        let resolver = Resolver::with_backend(config, backend).unwrap();
        let info = resolver.resolve("fe80::1".parse().unwrap()).unwrap();
        assert_eq!(info.display_name, "local-router");

        // IPv4-mapped IPv6
        let called = Arc::new(Mutex::new(0));
        let backend = Arc::new(MockBackend {
            ip: "::ffff:192.168.1.1".parse().unwrap(),
            response: Some("mapped-router".to_string()),
            delay: None,
            called: called.clone(),
        });

        let config = ResolverConfig::default();
        let resolver = Resolver::with_backend(config, backend).unwrap();
        let info = resolver.resolve("::ffff:192.168.1.1".parse().unwrap()).unwrap();
        assert_eq!(info.display_name, "mapped-router");
    }

    #[test]
    fn test_cache_and_timeout() {
        let called = Arc::new(Mutex::new(0));
        let backend = Arc::new(MockBackend {
            ip: "8.8.8.8".parse().unwrap(),
            response: Some("dns.google".to_string()),
            delay: Some(Duration::from_millis(100)),
            called: called.clone(),
        });

        let mut config = ResolverConfig::default();
        config.lookup_timeout = Duration::from_millis(50);
        let resolver = Resolver::with_backend(config, backend).unwrap();

        // Timeout
        let info = resolver.resolve("8.8.8.8".parse().unwrap());
        assert!(info.is_none());
        assert_eq!(*called.lock().unwrap(), 1); // was called

        // Try again, should hit negative cache, NO wait, NO backend call
        let called_before = *called.lock().unwrap();
        let info2 = resolver.resolve("8.8.8.8".parse().unwrap());
        assert!(info2.is_none());
        assert_eq!(*called.lock().unwrap(), called_before);

        // Positive cache test
        let called = Arc::new(Mutex::new(0));
        let backend = Arc::new(MockBackend {
            ip: "8.8.4.4".parse().unwrap(),
            response: Some("dns.google".to_string()),
            delay: None,
            called: called.clone(),
        });

        let config = ResolverConfig::default();
        let resolver = Resolver::with_backend(config, backend).unwrap();

        let info = resolver.resolve("8.8.4.4".parse().unwrap());
        assert!(info.is_some());
        assert_eq!(*called.lock().unwrap(), 1);

        let info2 = resolver.resolve("8.8.4.4".parse().unwrap());
        assert!(info2.is_some());
        assert_eq!(*called.lock().unwrap(), 1); // Not called again, hit positive cache
    }

    #[test]
    fn test_bad_input() {
        let mut config = ResolverConfig::default();
        config.cache_size = 0;
        let result = Resolver::new(config);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Cache size must be greater than 0");
    }
}
