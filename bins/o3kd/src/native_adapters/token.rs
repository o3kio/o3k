use std::sync::Arc;
use std::time::SystemTime;

use o3k_native_api::{
    auth::{NativeCredentialV1, NativeTokenRequestV1, TokenIssuer},
    error::ProblemDetails,
};

/// Adapter for issuing native API tokens through the identity service.
pub struct TokenIssuerAdapter {
    pub service: Arc<o3k_identity::TokenService>,
    pub oidc_validator: Option<Arc<o3k_identity::oidc::OidcValidator>>,
}

impl TokenIssuerAdapter {
    #[must_use]
    pub fn with_oidc_validator(
        mut self,
        validator: Arc<o3k_identity::oidc::OidcValidator>,
    ) -> Self {
        self.oidc_validator = Some(validator);
        self
    }
}

#[async_trait::async_trait]
impl TokenIssuer for TokenIssuerAdapter {
    async fn issue_native(
        &self,
        request: &NativeTokenRequestV1,
    ) -> Result<(String, serde_json::Value), ProblemDetails> {
        let credential = request
            .auth
            .credential()
            .map_err(ProblemDetails::bad_request)?;
        if let NativeCredentialV1::Federated {
            ref access_token,
            ref project_id,
            system,
        } = credential
        {
            let validator = self.oidc_validator.as_ref().ok_or_else(|| {
                ProblemDetails::with_detail(
                    o3k_native_api::error::ErrorCode::NotAvailable,
                    "federated identity is not configured",
                )
            })?;
            let identity = validator.validate(access_token).await.map_err(|error| {
                tracing::debug!(error = %error, "federated OIDC validation failed");
                ProblemDetails::unauthorized()
            })?;
            let issued = if system {
                self.service
                    .issue_federated_system(&identity, SystemTime::now())
            } else {
                self.service
                    .issue_federated(&identity, project_id, SystemTime::now())
            };
            return match issued {
                Ok((token, response)) => serde_json::to_value(response)
                    .map(|value| (token, value))
                    .map_err(|_| ProblemDetails::internal()),
                Err(_) => Err(ProblemDetails::unauthorized()),
            };
        }
        let (methods, password, token) = match credential {
            NativeCredentialV1::Password { user_id, password } => (
                vec!["password".to_owned()],
                Some(o3k_identity::PasswordIdentity {
                    user: o3k_identity::UserReference {
                        id: Some(user_id),
                        name: None,
                        domain: None,
                        password,
                    },
                }),
                None,
            ),
            NativeCredentialV1::Token { token } => (
                vec!["token".to_owned()],
                None,
                Some(o3k_identity::TokenIdentity { id: token }),
            ),
            NativeCredentialV1::Federated { .. } => {
                return Err(ProblemDetails::bad_request("invalid federated credential"));
            }
        };
        // Native token issuance stays project-scoped. Keystone's unscoped
        // discovery flow is deliberately not exposed on the native surface, so
        // a project-less native request remains a bounded rejection.
        let Some(project_id) = request.auth.project_id.as_ref() else {
            return Err(ProblemDetails::unauthorized());
        };
        // Build a Keystone-compatible TokenRequest from native request
        let token_req = o3k_identity::TokenRequest {
            auth: o3k_identity::Auth {
                identity: o3k_identity::Identity {
                    methods,
                    password,
                    token,
                },
                scope: Some(o3k_identity::ScopeRequest::Structured(
                    o3k_identity::StructuredScope {
                        project: Some(o3k_identity::ProjectReference {
                            id: Some(project_id.clone()),
                            name: None,
                            domain: None,
                        }),
                    },
                )),
            },
        };

        match self.service.issue(&token_req, SystemTime::now()) {
            Ok((token, response)) => match serde_json::to_value(response) {
                Ok(val) => Ok((token, val)),
                Err(_) => Err(ProblemDetails::internal()),
            },
            Err(_) => Err(ProblemDetails::unauthorized()),
        }
    }

    async fn auth_context(&self, token: &str) -> Result<o3k_kernel::AuthContext, ProblemDetails> {
        self.service
            .auth_context(token, SystemTime::now())
            .map_err(|_| ProblemDetails::unauthorized())
    }

    async fn discover_federated_scopes(
        &self,
        access_token: &str,
    ) -> Result<Vec<o3k_native_api::auth::FederatedScopeDescriptor>, ProblemDetails> {
        let validator = self.oidc_validator.as_ref().ok_or_else(|| {
            ProblemDetails::with_detail(
                o3k_native_api::error::ErrorCode::NotAvailable,
                "federated identity is not configured",
            )
        })?;
        let identity = validator.validate(access_token).await.map_err(|error| {
            tracing::debug!(error = %error, "federated OIDC validation failed");
            ProblemDetails::unauthorized()
        })?;
        self.service
            .discover_federated_scopes(&identity)
            .map(|scopes| {
                scopes
                    .into_iter()
                    .map(|scope| o3k_native_api::auth::FederatedScopeDescriptor {
                        id: scope.id,
                        kind: scope.kind.as_str().to_owned(),
                        name: scope.name,
                        domain_id: scope.domain_id,
                        can_request_token: scope.can_request_token,
                    })
                    .collect()
            })
            .map_err(|error| {
                tracing::debug!(error = %error, "federated scope discovery failed");
                ProblemDetails::unauthorized()
            })
    }
}

// ── ServerReader ──────────────────────────────────────────────────────────
