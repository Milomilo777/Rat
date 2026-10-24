pub mod resolver;
pub mod services;
mod tests;

pub use resolver::{Resolver, ResolverConfig, ReverseDnsInfo};
pub use services::service_name;
