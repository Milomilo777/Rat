use crossbeam_channel::unbounded;
use dns_lookup;
use lru::LruCache;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use threadpool::ThreadPool;

#[derive(Debug, Clone)]
pub struct ReverseDnsInfo {
    pub display_name: String,
    pub punycode: String,
}

impl PartialEq for ReverseDnsInfo {
    fn eq(&self, other: &Self) -> bool {
        // R4: compared in punycode
        self.punycode == other.punycode
    }
}
impl Eq for ReverseDnsInfo {}

#[derive(Debug, Clone)]
pub struct ResolverConfig {
    pub workers: usize,
    pub cache_size: usize,
    pub positive_ttl: Duration,
    pub negative_ttl: Duration,
    pub lookup_timeout: Duration,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            workers: 4,
            cache_size: 1000,
            positive_ttl: Duration::from_secs(3600), // 1 hour
            negative_ttl: Duration::from_secs(60),   // 1 min
            lookup_timeout: Duration::from_secs(2),  // 2 seconds
        }
    }
}

enum CacheEntry {
    Hit(ReverseDnsInfo, Instant),
    Miss(Instant),
}

pub trait LookupBackend: Send + Sync + 'static {
    fn reverse_lookup(&self, ip: IpAddr) -> Option<String>;
}

struct DefaultLookupBackend;
impl LookupBackend for DefaultLookupBackend {
    fn reverse_lookup(&self, ip: IpAddr) -> Option<String> {
        dns_lookup::lookup_addr(&ip).ok()
    }
}

pub struct Resolver {
    config: ResolverConfig,
    cache: Arc<Mutex<LruCache<IpAddr, CacheEntry>>>,
    pool: ThreadPool,
    backend: Arc<dyn LookupBackend>,
}

impl std::fmt::Debug for Resolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Resolver")
            .field("config", &self.config)
            .finish()
    }
}

impl Resolver {
    pub fn new(config: ResolverConfig) -> Result<Self, &'static str> {
        Self::with_backend(config, Arc::new(DefaultLookupBackend))
    }

    pub fn with_backend(config: ResolverConfig, backend: Arc<dyn LookupBackend>) -> Result<Self, &'static str> {
        if config.cache_size == 0 {
            return Err("Cache size must be greater than 0");
        }
        Ok(Self {
            cache: Arc::new(Mutex::new(LruCache::new(
                std::num::NonZeroUsize::new(config.cache_size).unwrap(),
            ))),
            pool: ThreadPool::new(config.workers),
            config,
            backend,
        })
    }

    pub fn resolve(&self, ip: IpAddr) -> Option<ReverseDnsInfo> {
        {
            if let Ok(mut cache) = self.cache.lock() {
                let now = Instant::now();
                if let Some(entry) = cache.get(&ip) {
                    match entry {
                        CacheEntry::Hit(info, expiry) => {
                            if now < *expiry {
                                return Some(info.clone());
                            }
                        }
                        CacheEntry::Miss(expiry) => {
                            if now < *expiry {
                                return None;
                            }
                        }
                    }
                }
            } else {
                // If lock fails, proceed with query, but don't cache
            }
        }

        let (tx, rx) = unbounded();
        let backend = Arc::clone(&self.backend);

        self.pool.execute(move || {
            let res = backend.reverse_lookup(ip);
            let _ = tx.send(res);
        });

        let now = Instant::now();
        let result = match rx.recv_timeout(self.config.lookup_timeout) {
            Ok(Some(name)) => {
                let display = idna::domain_to_unicode(&name).0;
                let puny = match idna::domain_to_ascii(&name) {
                    Ok(p) => p,
                    Err(_) => name.clone(), // fallback
                };
                let info = ReverseDnsInfo {
                    display_name: display,
                    punycode: puny,
                };

                if let Ok(mut cache) = self.cache.lock() {
                    cache.put(
                        ip,
                        CacheEntry::Hit(info.clone(), now + self.config.positive_ttl),
                    );
                }
                Some(info)
            }
            Ok(None) | Err(_) => {
                if let Ok(mut cache) = self.cache.lock() {
                    cache.put(ip, CacheEntry::Miss(now + self.config.negative_ttl));
                }
                None
            }
        };

        result
    }
}
