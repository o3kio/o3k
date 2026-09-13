mod audit;
mod building_block;
mod composition;
mod composition_profile;
mod compute;
pub mod diagnostics;
mod governance;
mod helpers;
pub mod metering;
mod network;
mod operation;
mod quota;
pub(crate) mod resource;
mod token;
mod volume;

#[cfg(test)]
mod tests;

pub use audit::AuditReaderAdapter;
pub use building_block::BuildingBlockAdapter;
pub use composition::CompositionResourceHandler;
pub use composition_profile::CloudProfileAdapter;
pub use compute::ServerReaderAdapter;
pub use diagnostics::DiagnosticsReaderAdapter;
pub use governance::GovernanceReaderAdapter;
pub use metering::MeteringAdapter;
pub use network::NetworkReaderAdapter;
pub use operation::OperationReaderAdapter;
pub use quota::QuotaReaderAdapter;
pub use resource::GenericResourceApplication;
pub use token::TokenIssuerAdapter;
pub use volume::VolumeReaderAdapter;
