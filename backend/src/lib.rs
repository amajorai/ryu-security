//! Local-first security workbench for `@ryu/security`.
//!
//! The sidecar owns the versioned scan, repository, and finding store. It is
//! intentionally independent from `apps/core`; Core registers the manifest and
//! carries this app through the generic authenticated ext-proxy seam.

pub mod api;
pub mod model;
pub mod paths;
pub mod scanner;
pub mod store;

pub use api::{routes, tenant_from_headers, Ctx};
pub use model::TenantContext;
pub use store::Store;
