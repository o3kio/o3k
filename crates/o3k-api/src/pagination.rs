//! Shared bounded collection pagination for the OpenStack compatibility
//! adapters.
//!
//! The pinned unmodified Horizon client (`openstacksdk` 4.10.0) paginates every
//! collection it lists. When it supplies a `limit` and the response carries no
//! next link it falls back to "pagination ball": it re-requests the same URI
//! with `marker=<id of the last resource on this page>`. A conformant service
//! answers that follow-up with zero resources ("start after this one"), so the
//! loop terminates. A service that ignores `limit`/`marker` repeats the same
//! page instead, and the client aborts with
//! `Endless pagination loop detected, aborting`.
//!
//! These helpers implement the bounded subset the accepted PP.4 Horizon
//! journey exercises: a positive `limit`, a UUID `marker` interpreted as an
//! `id > marker` cursor over the collection's canonical (id-ascending) order,
//! and the upstream-shaped `*_links` array. `sort_key`/`sort_dir` stay
//! unimplemented deviations, and every other query parameter the pinned client
//! sends is ignored.
//!
//! Unknown-marker cursor behavior is O3K's bounded rule, not a claim of
//! upstream parity: a malformed `marker` is a bounded rejection, while a
//! well-formed `marker` that matches nothing simply selects the tail of the
//! canonical order and therefore cannot act as an existence oracle.

use axum::http::{StatusCode, Uri};
use serde::Serialize;
use uuid::Uuid;

use crate::error::keystone_error;

/// One upstream-shaped entry of a collection's `*_links` array.
#[derive(Serialize)]
pub(crate) struct CollectionLink {
    rel: &'static str,
    href: String,
}

/// A validated `limit`/`marker` pair. Absent members preserve the pre-existing
/// behavior of the route.
pub(crate) struct CollectionPage {
    limit: Option<usize>,
    marker: Option<Uuid>,
}

impl CollectionPage {
    /// Validates the raw query members. `limit` must be a positive integer and
    /// `marker` a well-formed UUID; anything else is a bounded 400 that never
    /// echoes the supplied value.
    #[allow(clippy::result_large_err)]
    pub(crate) fn parse(
        limit: Option<&str>,
        marker: Option<&str>,
    ) -> Result<Self, axum::response::Response> {
        let limit = match limit {
            None => None,
            Some(value) => Some(
                value
                    .parse::<usize>()
                    .ok()
                    .filter(|limit| *limit > 0)
                    .ok_or_else(|| {
                        keystone_error(
                            StatusCode::BAD_REQUEST,
                            "Bad Request",
                            "limit must be a positive integer",
                        )
                    })?,
            ),
        };
        let marker = match marker {
            None => None,
            Some(value) => Some(value.parse::<Uuid>().map_err(|_| {
                keystone_error(
                    StatusCode::BAD_REQUEST,
                    "Bad Request",
                    "marker must be a UUID",
                )
            })?),
        };
        Ok(Self { limit, marker })
    }

    /// Sorts `items` into canonical id-ascending order, applies the marker
    /// cursor and the page size in place, and returns the `*_links` array the
    /// pinned client reads. The array is `None` when no `limit` was supplied so
    /// that every existing non-paginating client keeps its byte-shape; when a
    /// `limit` was supplied it always carries `rel: self` and carries
    /// `rel: next` only when at least one further page exists.
    pub(crate) fn apply<T>(
        &self,
        items: &mut Vec<T>,
        id_of: impl Fn(&T) -> Uuid,
        request_uri: &Uri,
    ) -> Option<Vec<CollectionLink>> {
        items.sort_by_key(|item| id_of(item));
        if let Some(marker) = self.marker {
            items.retain(|item| id_of(item) > marker);
        }
        let limit = self.limit?;
        let has_next = items.len() > limit;
        items.truncate(limit);
        let mut links = vec![CollectionLink {
            rel: "self",
            href: request_href(request_uri),
        }];
        if has_next && let Some(last) = items.last() {
            links.push(CollectionLink {
                rel: "next",
                href: format!(
                    "{}?marker={}&limit={limit}",
                    request_uri.path(),
                    id_of(last)
                ),
            });
        }
        Some(links)
    }
}

/// The request URI as a correct URL relative to the service endpoint.
fn request_href(request_uri: &Uri) -> String {
    match request_uri.query() {
        Some(query) => format!("{}?{query}", request_uri.path()),
        None => request_uri.path().to_owned(),
    }
}
