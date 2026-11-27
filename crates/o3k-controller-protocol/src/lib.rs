//! Versioned, language-neutral external controller wire protocol.
pub mod proto {
    tonic::include_proto!("o3k.controller.v1");
}

pub mod composition {
    tonic::include_proto!("o3k.composition.v1");
}

pub mod storage {
    tonic::include_proto!("o3k.storage.v1");
}

pub mod conversion;

pub const PROTOCOL_VERSION: (u16, u16) = (1, 0);
pub const MAX_DIAGNOSTIC_BYTES: usize = 4096;
pub const MAX_RESOURCE_PAYLOAD_BYTES: usize = 1024 * 1024;
pub const MAX_DELEGATION_BYTES: usize = 16 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("missing required field: {0}")]
    Missing(&'static str),
    #[error("invalid field: {0}")]
    Invalid(String),
    #[error("payload exceeds limit: {0}")]
    Limit(&'static str),
}

pub fn bounded_bytes(value: &[u8], max: usize, name: &'static str) -> Result<(), ProtocolError> {
    if value.len() > max {
        return Err(ProtocolError::Limit(name));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn v1_wire_service_is_present() {
        let request = proto::RegisterRequest {
            service_id: "svc".into(),
            namespace: "ns".into(),
            ..Default::default()
        };
        assert_eq!(request.service_id, "svc");
    }
    #[test]
    fn payload_limits_fail_closed() {
        assert!(
            bounded_bytes(
                &[0; MAX_DIAGNOSTIC_BYTES + 1],
                MAX_DIAGNOSTIC_BYTES,
                "diagnostic"
            )
            .is_err()
        );
    }

    #[test]
    fn composition_wire_service_is_versioned_and_generic() {
        let request = composition::ChildRequest {
            lifecycle: "create".into(),
            resource_type: "compute:server".into(),
            ..Default::default()
        };
        assert_eq!(request.lifecycle, "create");
        assert_eq!(request.resource_type, "compute:server");
    }
}
