use async_trait::async_trait;
use o3k_kernel::{
    ActionId, AuditEvent, AuditOutcome, AuditQuery, DurableAuditPage, DurableAuditRepository,
    EventId, OwnershipScope, PrincipalId, PrincipalKind, ResourceId, ResourceType, ScopeId,
    ServiceNamespace,
};

use super::O3kStore;
use crate::AuditEventRecord;
use crate::port::service_repos::AuditRepository;

impl O3kStore {
    pub async fn insert_audit_event(
        &self,
        event: &crate::AuditEventRecord,
    ) -> Result<(), crate::StoreError> {
        match self {
            Self::Sqlite(store) => store.insert_audit_event(event).await,
            Self::Postgres(store) => store.insert_audit_event(event).await,
        }
    }
}

fn err<E: std::fmt::Display>(e: E) -> o3k_kernel::KernelError {
    o3k_kernel::KernelError::AuditUnavailable(e.to_string())
}

fn row_event(r: AuditEventRecord) -> Result<AuditEvent, o3k_kernel::KernelError> {
    let (_, action_name) = r
        .action
        .split_once(':')
        .ok_or_else(|| err("invalid audit action"))?;
    let service = ServiceNamespace::new(r.service).map_err(err)?;
    let action = ActionId::new(service.as_str(), action_name).map_err(err)?;
    let scope = OwnershipScope::project(ScopeId::new_unchecked(r.effective_scope), None, None);
    let resource_type = r
        .resource_type
        .as_deref()
        .and_then(|v| v.split_once(':'))
        .map(|(ns, n)| ResourceType::new_unchecked(ns, n));
    Ok(AuditEvent {
        event_id: EventId::from_string(r.event_id),
        timestamp: r.timestamp,
        request_id: r.request_id,
        audit_id: r.audit_id,
        principal_id: PrincipalId::new_unchecked(r.principal_id),
        principal_kind: if r.principal_kind.to_lowercase().contains("service") {
            PrincipalKind::Service
        } else {
            PrincipalKind::User
        },
        effective_scope: scope,
        service_namespace: service,
        action,
        resource_type,
        resource_id: r.resource_id.map(ResourceId::new_unchecked),
        owner_scope: r
            .owner_scope
            .map(|v| OwnershipScope::project(ScopeId::new_unchecked(v), None, None)),
        authorization_decision: None,
        operation_id: r.operation_id.and_then(|v| uuid::Uuid::parse_str(&v).ok()),
        outcome: match r.outcome.as_str() {
            "allowed" => AuditOutcome::Allowed,
            "denied" => AuditOutcome::Denied,
            "failed" => AuditOutcome::Failed,
            "unknown_outcome" => AuditOutcome::UnknownOutcome,
            _ => AuditOutcome::Succeeded,
        },
        reason_category: r.reason_category,
        service_principal: None,
    })
}

#[async_trait]
impl DurableAuditRepository for O3kStore {
    async fn append(&self, event: &AuditEvent) -> Result<(), o3k_kernel::KernelError> {
        let record = AuditEventRecord::from_kernel_event(event);
        let result = match self {
            Self::Sqlite(s) => s.insert_audit_event(&record).await,
            Self::Postgres(s) => s.insert_audit_event(&record).await,
        };
        result.map_err(|error| {
            if matches!(error, crate::StoreError::AuditEventConflict) {
                o3k_kernel::KernelError::AuditConflict
            } else {
                err(error)
            }
        })
    }

    async fn page(&self, query: &AuditQuery) -> Result<DurableAuditPage, o3k_kernel::KernelError> {
        query.validate()?;
        let page = match self {
            Self::Sqlite(s) => s.list_audit_events_page_query(query).await,
            Self::Postgres(s) => s.list_audit_events_page_query(query).await,
        }
        .map_err(err)?;
        let events = page
            .items
            .into_iter()
            .map(row_event)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(DurableAuditPage {
            events,
            has_more: page.has_more,
            continuation_key: page.continuation_key,
        })
    }

    async fn prune_before(&self, cutoff: &str) -> Result<u64, o3k_kernel::KernelError> {
        const BATCH: usize = 200;
        match self {
            Self::Sqlite(s) => s.prune_audit_events_before(cutoff, BATCH).await,
            Self::Postgres(s) => s.prune_audit_events_before(cutoff, BATCH).await,
        }
        .map_err(err)
    }
}
