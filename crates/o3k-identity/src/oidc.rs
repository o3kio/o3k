//! Trusted OIDC access-token validation.
//!
//! This module deliberately stops at authentication evidence. It does not
//! provision principals, discover scopes, or issue O3K tokens.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use jsonwebtoken::{Algorithm, DecodingKey, TokenData, Validation, decode, decode_header};
use reqwest::{Url, redirect::Policy};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

const DEFAULT_MAX_TOKEN_BYTES: usize = 16 * 1024;
const DEFAULT_MAX_DOCUMENT_BYTES: usize = 512 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustedIssuer {
    pub id: String,
    pub issuer: Url,
    pub audience: String,
    pub algorithms: Vec<Algorithm>,
    pub discovery_url: Url,
    pub allow_insecure_local: bool,
    pub timeout: Duration,
    pub cache_ttl: Duration,
    pub max_token_bytes: usize,
    pub max_document_bytes: usize,
    pub clock_skew: Duration,
}

impl TrustedIssuer {
    pub fn validate(&self) -> Result<(), OidcError> {
        if self.id.trim().is_empty()
            || self.audience.trim().is_empty()
            || self.algorithms.is_empty()
            || self.timeout.is_zero()
            || self.cache_ttl.is_zero()
            || self.max_token_bytes == 0
            || self.max_document_bytes == 0
        {
            return Err(OidcError::InvalidConfiguration);
        }
        if self.issuer.path() != "/" && self.issuer.path().ends_with('/') {
            return Err(OidcError::InvalidConfiguration);
        }
        if self.issuer.query().is_some()
            || self.issuer.fragment().is_some()
            || self.discovery_url.query().is_some()
            || self.discovery_url.fragment().is_some()
            || !self.issuer.username().is_empty()
            || self.issuer.password().is_some()
            || !self.discovery_url.username().is_empty()
            || self.discovery_url.password().is_some()
        {
            return Err(OidcError::InvalidConfiguration);
        }
        if !self.allow_insecure_local
            && (self.issuer.scheme() != "https" || self.discovery_url.scheme() != "https")
        {
            return Err(OidcError::InsecureIssuer);
        }
        if self.allow_insecure_local
            && (!is_local_url(&self.issuer) || !is_local_url(&self.discovery_url))
        {
            return Err(OidcError::InvalidConfiguration);
        }
        Ok(())
    }

    #[must_use]
    pub fn test_local(id: &str, issuer: Url, audience: &str, discovery_url: Url) -> Self {
        Self {
            id: id.to_owned(),
            issuer,
            audience: audience.to_owned(),
            algorithms: vec![Algorithm::RS256],
            discovery_url,
            allow_insecure_local: true,
            timeout: Duration::from_secs(2),
            cache_ttl: Duration::from_secs(300),
            max_token_bytes: DEFAULT_MAX_TOKEN_BYTES,
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            clock_skew: Duration::from_secs(30),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ValidatedExternalIdentity {
    pub trusted_issuer_id: String,
    pub issuer: String,
    pub subject: String,
    pub expires_at: u64,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OidcError {
    #[error("OIDC authentication failed")]
    AuthenticationFailed,
    #[error("OIDC issuer configuration is invalid")]
    InvalidConfiguration,
    #[error("OIDC issuer must use HTTPS")]
    InsecureIssuer,
    #[error("OIDC discovery or JWKS document is unavailable")]
    ProviderUnavailable,
    #[error("OIDC discovery or JWKS document exceeds its configured limit")]
    DocumentTooLarge,
}

#[derive(Debug, Deserialize)]
struct DiscoveryDocument {
    issuer: String,
    jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct Claims {
    iss: String,
    sub: String,
    exp: u64,
    #[serde(default)]
    typ: Option<String>,
}

#[derive(Clone)]
struct CachedKeys {
    fetched_at: Instant,
    keys: jsonwebtoken::jwk::JwkSet,
}

#[derive(Clone)]
pub struct OidcValidator {
    client: reqwest::Client,
    issuer: TrustedIssuer,
    keys: Arc<RwLock<Option<CachedKeys>>>,
}

impl OidcValidator {
    pub fn new(issuer: TrustedIssuer) -> Result<Self, OidcError> {
        issuer.validate()?;
        let client = reqwest::Client::builder()
            .connect_timeout(issuer.timeout)
            .timeout(issuer.timeout)
            .redirect(Policy::none())
            .build()
            .map_err(|_| OidcError::InvalidConfiguration)?;
        Ok(Self {
            client,
            issuer,
            keys: Arc::new(RwLock::new(None)),
        })
    }

    #[must_use]
    pub fn issuer(&self) -> &TrustedIssuer {
        &self.issuer
    }

    /// Validate an access token using the cached JWKS, refreshing once when
    /// the token names a key that is not cached. No token bytes enter errors.
    pub async fn validate(&self, token: &str) -> Result<ValidatedExternalIdentity, OidcError> {
        if token.len() > self.issuer.max_token_bytes {
            return Err(OidcError::AuthenticationFailed);
        }
        let header = decode_header(token).map_err(|_| OidcError::AuthenticationFailed)?;
        let kid = header
            .kid
            .as_deref()
            .ok_or(OidcError::AuthenticationFailed)?;
        let keys = self.get_keys(kid).await?;
        self.validate_with_jwks(token, &keys)
    }

    fn validate_with_jwks(
        &self,
        token: &str,
        keys: &jsonwebtoken::jwk::JwkSet,
    ) -> Result<ValidatedExternalIdentity, OidcError> {
        if token.len() > self.issuer.max_token_bytes {
            return Err(OidcError::AuthenticationFailed);
        }
        let kid = decode_header(token)
            .map_err(|_| OidcError::AuthenticationFailed)?
            .kid
            .ok_or(OidcError::AuthenticationFailed)?;
        self.decode(token, &kid, keys)
    }

    async fn get_keys(&self, kid: &str) -> Result<jsonwebtoken::jwk::JwkSet, OidcError> {
        if let Some(cached) = self.keys.read().await.clone()
            && cached.fetched_at.elapsed() < self.issuer.cache_ttl
            && cached.keys.find(kid).is_some()
        {
            return Ok(cached.keys);
        }
        let fresh = self.fetch_jwks().await?;
        if fresh.find(kid).is_none() {
            return Err(OidcError::AuthenticationFailed);
        }
        *self.keys.write().await = Some(CachedKeys {
            fetched_at: Instant::now(),
            keys: fresh.clone(),
        });
        Ok(fresh)
    }

    fn decode(
        &self,
        token: &str,
        kid: &str,
        keys: &jsonwebtoken::jwk::JwkSet,
    ) -> Result<ValidatedExternalIdentity, OidcError> {
        let jwk = keys.find(kid).ok_or(OidcError::AuthenticationFailed)?;
        let algorithm = decode_header(token)
            .map_err(|_| OidcError::AuthenticationFailed)?
            .alg;
        if !self.issuer.algorithms.contains(&algorithm) {
            return Err(OidcError::AuthenticationFailed);
        }
        let key = DecodingKey::from_jwk(jwk).map_err(|_| OidcError::AuthenticationFailed)?;
        let header = decode_header(token).map_err(|_| OidcError::AuthenticationFailed)?;
        let header_is_access_token =
            matches!(header.typ.as_deref(), Some("at+jwt" | "application/at+jwt"));
        let keycloak_compatible_access_token = header.typ.as_deref() == Some("JWT");
        if !header_is_access_token && !keycloak_compatible_access_token {
            return Err(OidcError::AuthenticationFailed);
        }
        let mut validation = Validation::new(algorithm);
        validation.leeway = self.issuer.clock_skew.as_secs();
        validation.validate_nbf = true;
        validation.set_issuer(&[self.issuer.issuer.as_str()]);
        validation.set_audience(std::slice::from_ref(&self.issuer.audience));
        validation
            .required_spec_claims
            .extend(["iss", "aud", "sub"].into_iter().map(str::to_owned));
        let TokenData { claims, .. }: TokenData<Claims> =
            decode(token, &key, &validation).map_err(|_| OidcError::AuthenticationFailed)?;
        // RFC 9068 access tokens use an `at+jwt` media type.  Some otherwise
        // standards-based OIDC providers emit a generic JWT header and mark
        // the OAuth access token in the payload instead.  Accept that bounded
        // form without accepting an untyped ID token.
        if keycloak_compatible_access_token && claims.typ.as_deref() != Some("Bearer") {
            return Err(OidcError::AuthenticationFailed);
        }
        if claims.sub.is_empty() || claims.sub.len() > 512 {
            return Err(OidcError::AuthenticationFailed);
        }
        Ok(ValidatedExternalIdentity {
            trusted_issuer_id: self.issuer.id.clone(),
            issuer: claims.iss,
            subject: claims.sub,
            expires_at: claims.exp,
        })
    }

    async fn fetch_jwks(&self) -> Result<jsonwebtoken::jwk::JwkSet, OidcError> {
        let discovery = self
            .client
            .get(self.issuer.discovery_url.clone())
            .send()
            .await
            .map_err(|_| OidcError::ProviderUnavailable)?;
        if !discovery.status().is_success() {
            return Err(OidcError::ProviderUnavailable);
        }
        let body = bounded_body(discovery, self.issuer.max_document_bytes).await?;
        let document: DiscoveryDocument =
            serde_json::from_slice(&body).map_err(|_| OidcError::ProviderUnavailable)?;
        let discovered_issuer =
            Url::parse(&document.issuer).map_err(|_| OidcError::ProviderUnavailable)?;
        if discovered_issuer != self.issuer.issuer {
            return Err(OidcError::ProviderUnavailable);
        }
        let jwks_url =
            Url::parse(&document.jwks_uri).map_err(|_| OidcError::ProviderUnavailable)?;
        if !self.issuer.allow_insecure_local && jwks_url.scheme() != "https" {
            return Err(OidcError::InsecureIssuer);
        }
        if self.issuer.allow_insecure_local && !is_local_url(&jwks_url) {
            return Err(OidcError::InvalidConfiguration);
        }
        let response = self
            .client
            .get(jwks_url)
            .send()
            .await
            .map_err(|_| OidcError::ProviderUnavailable)?;
        if !response.status().is_success() {
            return Err(OidcError::ProviderUnavailable);
        }
        let body = bounded_body(response, self.issuer.max_document_bytes).await?;
        serde_json::from_slice(&body).map_err(|_| OidcError::ProviderUnavailable)
    }
}

async fn bounded_body(mut response: reqwest::Response, max: usize) -> Result<Vec<u8>, OidcError> {
    if response
        .content_length()
        .is_some_and(|length| length > max as u64)
    {
        return Err(OidcError::DocumentTooLarge);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| OidcError::ProviderUnavailable)?
    {
        if chunk.len() > max.saturating_sub(body.len()) {
            return Err(OidcError::DocumentTooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn is_local_url(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("localhost" | "127.0.0.1" | "[::1]" | "::1")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Json, Router, extract::State, routing::get};
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{SystemTime, UNIX_EPOCH},
    };
    use tokio::net::TcpListener;

    struct TestProviderState {
        issuer: String,
        jwks_uri: String,
        first_key: serde_json::Value,
        rotated_key: serde_json::Value,
        jwks_requests: AtomicUsize,
    }

    async fn discovery(State(state): State<Arc<TestProviderState>>) -> Json<serde_json::Value> {
        Json(json!({"issuer": state.issuer, "jwks_uri": state.jwks_uri}))
    }

    async fn jwks(State(state): State<Arc<TestProviderState>>) -> Json<serde_json::Value> {
        let request = state.jwks_requests.fetch_add(1, Ordering::SeqCst);
        let key = if request == 0 {
            &state.first_key
        } else {
            &state.rotated_key
        };
        Json(json!({"keys": [key]}))
    }

    #[test]
    fn production_configuration_rejects_http() -> Result<(), OidcError> {
        let issuer_url =
            Url::parse("http://idp.example.test").map_err(|_| OidcError::InvalidConfiguration)?;
        let discovery_url = Url::parse("http://idp.example.test/.well-known/openid-configuration")
            .map_err(|_| OidcError::InvalidConfiguration)?;
        let issuer = TrustedIssuer {
            id: "test".to_owned(),
            issuer: issuer_url,
            audience: "o3k".to_owned(),
            algorithms: vec![Algorithm::RS256],
            discovery_url,
            allow_insecure_local: false,
            timeout: Duration::from_secs(1),
            max_token_bytes: DEFAULT_MAX_TOKEN_BYTES,
            max_document_bytes: DEFAULT_MAX_DOCUMENT_BYTES,
            clock_skew: Duration::from_secs(30),
            cache_ttl: Duration::from_secs(30),
        };
        assert_eq!(issuer.validate(), Err(OidcError::InsecureIssuer));
        Ok(())
    }

    #[test]
    fn local_test_configuration_is_explicit() -> Result<(), OidcError> {
        let issuer_url =
            Url::parse("http://127.0.0.1:9000").map_err(|_| OidcError::InvalidConfiguration)?;
        let discovery_url = Url::parse("http://127.0.0.1:9000/.well-known/openid-configuration")
            .map_err(|_| OidcError::InvalidConfiguration)?;
        let issuer = TrustedIssuer::test_local("local", issuer_url, "o3k", discovery_url);
        assert!(issuer.validate().is_ok());
        Ok(())
    }

    #[test]
    fn errors_are_not_token_bearing() {
        let error = OidcError::AuthenticationFailed;
        assert_eq!(error.to_string(), "OIDC authentication failed");
    }

    #[test]
    fn validates_claims_and_signature_against_explicit_jwks() -> Result<(), OidcError> {
        let issuer_url =
            Url::parse("http://127.0.0.1:9000").map_err(|_| OidcError::InvalidConfiguration)?;
        let discovery_url = Url::parse("http://127.0.0.1:9000/.well-known/openid-configuration")
            .map_err(|_| OidcError::InvalidConfiguration)?;
        let mut trusted = TrustedIssuer::test_local("local", issuer_url, "o3k", discovery_url);
        trusted.algorithms = vec![Algorithm::HS256];
        let validator = OidcValidator::new(trusted)?;
        let secret = b"a-test-secret-that-is-long-enough";
        let mut header = Header::new(Algorithm::HS256);
        header.typ = Some("at+jwt".to_owned());
        header.kid = Some("key-1".to_owned());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OidcError::InvalidConfiguration)?
            .as_secs();
        let token = encode(
            &header,
            &json!({
                "iss": "http://127.0.0.1:9000/",
                "sub": "external-subject",
                "aud": "o3k",
                "exp": now + 300,
                "nbf": now - 1,
            }),
            &EncodingKey::from_secret(secret),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        let mut jwk = jsonwebtoken::jwk::Jwk::from_decoding_key(
            &DecodingKey::from_secret(secret),
            Some(Algorithm::HS256),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        jwk.common.key_id = Some("key-1".to_owned());
        let keys = jsonwebtoken::jwk::JwkSet { keys: vec![jwk] };
        let identity_result = validator.validate_with_jwks(&token, &keys);
        let identity = identity_result?;
        assert_eq!(identity.trusted_issuer_id, "local");
        assert_eq!(identity.subject, "external-subject");

        let expired_access_token = encode(
            &header,
            &json!({
                "iss": "http://127.0.0.1:9000/",
                "sub": "external-subject",
                "aud": "o3k",
                "exp": now.saturating_sub(60),
            }),
            &EncodingKey::from_secret(secret),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        assert_eq!(
            validator.validate_with_jwks(&expired_access_token, &keys),
            Err(OidcError::AuthenticationFailed)
        );

        let mut id_token_header = Header::new(Algorithm::HS256);
        id_token_header.kid = Some("key-1".to_owned());
        let id_token = encode(
            &id_token_header,
            &json!({
                "iss": "http://127.0.0.1:9000/",
                "sub": "external-subject",
                "aud": "o3k",
                "exp": now + 300,
            }),
            &EncodingKey::from_secret(secret),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        assert_eq!(
            validator.validate_with_jwks(&id_token, &keys),
            Err(OidcError::AuthenticationFailed)
        );

        let wrong_audience = encode(
            &header,
            &json!({
                "iss": "http://127.0.0.1:9000/",
                "sub": "external-subject",
                "aud": "another-service",
                "exp": now + 300,
            }),
            &EncodingKey::from_secret(secret),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        assert_eq!(
            validator.validate_with_jwks(&wrong_audience, &keys),
            Err(OidcError::AuthenticationFailed)
        );
        assert_eq!(
            validator.validate_with_jwks(&"x".repeat(DEFAULT_MAX_TOKEN_BYTES + 1), &keys),
            Err(OidcError::AuthenticationFailed)
        );
        Ok(())
    }

    #[tokio::test]
    async fn fetches_discovery_and_refreshes_on_key_rotation() -> Result<(), OidcError> {
        let secret_one = b"first-test-secret-that-is-long-enough";
        let secret_two = b"rotated-test-secret-that-is-long-enough";
        let mut header_one = Header::new(Algorithm::HS256);
        header_one.typ = Some("at+jwt".to_owned());
        header_one.kid = Some("key-1".to_owned());
        let mut header_two = header_one.clone();
        header_two.kid = Some("key-2".to_owned());
        let mut jwk_one = jsonwebtoken::jwk::Jwk::from_decoding_key(
            &DecodingKey::from_secret(secret_one),
            Some(Algorithm::HS256),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        jwk_one.common.key_id = Some("key-1".to_owned());
        let mut jwk_two = jsonwebtoken::jwk::Jwk::from_decoding_key(
            &DecodingKey::from_secret(secret_two),
            Some(Algorithm::HS256),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        jwk_two.common.key_id = Some("key-2".to_owned());

        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| OidcError::ProviderUnavailable)?;
        let address = listener
            .local_addr()
            .map_err(|_| OidcError::ProviderUnavailable)?;
        let base = format!("http://{address}");
        let state = Arc::new(TestProviderState {
            issuer: format!("{base}/"),
            jwks_uri: format!("{base}/jwks"),
            first_key: serde_json::to_value(&jwk_one)
                .map_err(|_| OidcError::ProviderUnavailable)?,
            rotated_key: serde_json::to_value(&jwk_two)
                .map_err(|_| OidcError::ProviderUnavailable)?,
            jwks_requests: AtomicUsize::new(0),
        });
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let issuer = TrustedIssuer::test_local(
            "rotation-test",
            Url::parse(&format!("{base}/")).map_err(|_| OidcError::InvalidConfiguration)?,
            "o3k",
            Url::parse(&format!("{base}/.well-known/openid-configuration"))
                .map_err(|_| OidcError::InvalidConfiguration)?,
        );
        let validator = OidcValidator::new(TrustedIssuer {
            algorithms: vec![Algorithm::HS256],
            cache_ttl: Duration::from_secs(300),
            ..issuer
        })?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| OidcError::InvalidConfiguration)?
            .as_secs();
        let token_one = encode(
            &header_one,
            &json!({"iss": format!("{base}/"), "sub": "subject", "aud": "o3k", "exp": now + 300}),
            &EncodingKey::from_secret(secret_one),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        validator.validate(&token_one).await?;
        validator.validate(&token_one).await?;
        assert_eq!(state.jwks_requests.load(Ordering::SeqCst), 1);

        let token_two = encode(
            &header_two,
            &json!({"iss": format!("{base}/"), "sub": "subject", "aud": "o3k", "exp": now + 300}),
            &EncodingKey::from_secret(secret_two),
        )
        .map_err(|_| OidcError::AuthenticationFailed)?;
        validator.validate(&token_two).await?;
        assert_eq!(state.jwks_requests.load(Ordering::SeqCst), 2);
        server.abort();
        Ok(())
    }
}
