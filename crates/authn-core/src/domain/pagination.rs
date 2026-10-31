//! Keyset pagination primitives shared by every listing endpoint (DOC-04).
//!
//! Listings never use `OFFSET`: they page by an opaque [`Cursor`] that
//! encodes the sort key of the last returned row plus its id as tie-breaker.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{AuthError, codes};

/// Hard upper bound for `limit`.
pub const MAX_PAGE_LIMIT: u32 = 100;
/// Limit used when the client does not send one.
pub const DEFAULT_PAGE_LIMIT: u32 = 20;

const CURSOR_VERSION: u8 = 1;
const CURSOR_BYTES: usize = 1 + 8 + 16;

/// Query parameters accepted by paginated endpoints: `?limit=&cursor=`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageRequest {
    /// Page size, 1–100 (default 20). Out-of-range values are clamped.
    pub limit: Option<u32>,
    /// Opaque cursor returned as `next_cursor` by the previous page.
    pub cursor: Option<String>,
}

impl PageRequest {
    /// Effective page size, clamped to `1..=MAX_PAGE_LIMIT`.
    #[must_use]
    pub fn limit(&self) -> u32 {
        self.limit
            .unwrap_or(DEFAULT_PAGE_LIMIT)
            .clamp(1, MAX_PAGE_LIMIT)
    }

    /// Decodes the cursor; a malformed cursor is a `validation_failed` error.
    pub fn cursor(&self) -> Result<Option<Cursor>, AuthError> {
        self.cursor
            .as_deref()
            .map(|raw| {
                Cursor::decode(raw).ok_or_else(|| AuthError::new(codes::common::VALIDATION_FAILED))
            })
            .transpose()
    }
}

/// Position after the last row of a page: `(sort_key, id)`.
///
/// `sort_key` is whatever the listing orders by (an `audit_events.seq`, a
/// timestamp in Unix microseconds, or `0` when ordering by id only). The
/// cursor is not integrity protected; every query must still apply its own
/// tenant / owner filters (ARC-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cursor {
    /// Primary sort key of the last row.
    pub sort_key: i64,
    /// Id of the last row (tie-breaker).
    pub id: Uuid,
}

impl Cursor {
    /// Encodes as URL-safe base64 without padding.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut bytes = Vec::with_capacity(CURSOR_BYTES);
        bytes.push(CURSOR_VERSION);
        bytes.extend_from_slice(&self.sort_key.to_be_bytes());
        bytes.extend_from_slice(self.id.as_bytes());
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Strict decoding: exact length, known version.
    #[must_use]
    pub fn decode(raw: &str) -> Option<Self> {
        if raw.len() > 64 {
            return None;
        }
        let bytes = URL_SAFE_NO_PAD.decode(raw).ok()?;
        if bytes.len() != CURSOR_BYTES || bytes.first() != Some(&CURSOR_VERSION) {
            return None;
        }
        let sort_key = i64::from_be_bytes(bytes.get(1..9)?.try_into().ok()?);
        let id = Uuid::from_slice(bytes.get(9..)?).ok()?;
        Some(Self { sort_key, id })
    }
}

/// One page of results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct Page<T> {
    /// The rows of this page.
    pub items: Vec<T>,
    /// Cursor for the next page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
}

impl<T> Page<T> {
    /// Builds a page from `limit + 1` fetched rows: if more than `limit` rows
    /// were fetched, the extra row is dropped and `next_cursor` is computed
    /// from the last kept row.
    pub fn from_overfetch(mut rows: Vec<T>, limit: u32, cursor_of: impl Fn(&T) -> Cursor) -> Self {
        let limit = usize::try_from(limit).unwrap_or(usize::MAX);
        let has_more = rows.len() > limit;
        rows.truncate(limit);
        let next_cursor = if has_more {
            rows.last().map(|row| cursor_of(row).encode())
        } else {
            None
        };
        Self {
            items: rows,
            next_cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn page_limit_is_clamped() {
        assert_eq!(PageRequest::default().limit(), DEFAULT_PAGE_LIMIT);
        let r = PageRequest {
            limit: Some(0),
            cursor: None,
        };
        assert_eq!(r.limit(), 1);
        let r = PageRequest {
            limit: Some(10_000),
            cursor: None,
        };
        assert_eq!(r.limit(), MAX_PAGE_LIMIT);
    }

    #[test]
    fn cursor_round_trip_and_strict_decoding() {
        let c = Cursor {
            sort_key: -42,
            id: Uuid::now_v7(),
        };
        assert_eq!(Cursor::decode(&c.encode()), Some(c));
        assert_eq!(Cursor::decode(""), None);
        assert_eq!(Cursor::decode("AAAA"), None);
        assert_eq!(Cursor::decode(&"A".repeat(500)), None);
        let r = PageRequest {
            limit: None,
            cursor: Some("!!".into()),
        };
        assert!(r.cursor().is_err());
    }

    #[test]
    fn page_from_overfetch() {
        let rows: Vec<i64> = (1..=6).collect();
        let page = Page::from_overfetch(rows, 5, |r| Cursor {
            sort_key: *r,
            id: Uuid::nil(),
        });
        assert_eq!(page.items, vec![1, 2, 3, 4, 5]);
        let next = Cursor::decode(page.next_cursor.as_deref().unwrap()).unwrap();
        assert_eq!(next.sort_key, 5);
        let page = Page::from_overfetch(vec![1_i64, 2], 5, |r| Cursor {
            sort_key: *r,
            id: Uuid::nil(),
        });
        assert_eq!(page.next_cursor, None);
    }
}
