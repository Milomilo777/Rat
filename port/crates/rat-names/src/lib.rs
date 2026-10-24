pub mod resolver;
pub mod services;
#[cfg(test)]
mod tests;

pub use resolver::{Resolver, ResolverConfig, ReverseDnsInfo};
pub use services::service_name;
