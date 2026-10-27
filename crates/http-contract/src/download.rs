//! Typed framing for the existing product's verified binary streams; no storage or range parser.
use crate::signature::{Direction, Output, Representation, Schema};
use axum::{
    Json,
    body::Body,
    response::{IntoResponse, Response},
};
use http::{HeaderValue, StatusCode, header};
const MEDIA: &str = "application/octet-stream";
const CACHE: &str = "private, no-store";

#[derive(Clone, Copy)]
enum Kind {
    Full,
    Partial,
    Unsatisfied,
}
impl Kind {
    const ALL: [Self; 3] = [Self::Full, Self::Partial, Self::Unsatisfied];
    const fn status(self) -> StatusCode {
        match self {
            Self::Full => StatusCode::OK,
            Self::Partial => StatusCode::PARTIAL_CONTENT,
            Self::Unsatisfied => StatusCode::RANGE_NOT_SATISFIABLE,
        }
    }
}
#[derive(serde::Serialize, schemars::JsonSchema)]
#[serde(rename_all = "snake_case")]
enum Code {
    RangeNotSatisfiable,
}
#[derive(serde::Serialize, schemars::JsonSchema)]
struct Failure {
    code: Code,
}

/// Created only after the original content owner has selected and opened the exact byte range.
pub struct Download {
    kind: Kind,
    body: Body,
    length: u64,
    etag: Option<HeaderValue>,
    range: Option<HeaderValue>,
}
#[derive(Debug)]
pub enum InvalidFrame {
    Range,
    Header,
}
impl Download {
    pub fn stream(
        body: Body,
        etag: &str,
        start: u64,
        end: u64,
        total: u64,
        partial: bool,
    ) -> Result<Self, InvalidFrame> {
        if start > end
            || end > total
            || (partial && start == end)
            || (!partial && (start != 0 || end != total))
        {
            return Err(InvalidFrame::Range);
        }
        let range = partial
            .then(|| HeaderValue::from_str(&format!("bytes {start}-{}/{total}", end - 1)))
            .transpose()
            .map_err(|_| InvalidFrame::Header)?;
        Ok(Self {
            kind: if partial { Kind::Partial } else { Kind::Full },
            body,
            length: end - start,
            etag: Some(HeaderValue::from_str(etag).map_err(|_| InvalidFrame::Header)?),
            range,
        })
    }
    pub fn unsatisfied(total: u64) -> Self {
        Self {
            kind: Kind::Unsatisfied,
            body: Body::empty(),
            length: 0,
            etag: None,
            range: Some(
                HeaderValue::from_str(&format!("bytes */{total}")).expect("numeric content range"),
            ),
        }
    }
}
impl IntoResponse for Download {
    fn into_response(self) -> Response {
        let mut response = match self.kind {
            Kind::Unsatisfied => (
                self.kind.status(),
                Json(Failure {
                    code: Code::RangeNotSatisfiable,
                }),
            )
                .into_response(),
            Kind::Full | Kind::Partial => {
                let mut response = (self.kind.status(), self.body).into_response();
                let headers = response.headers_mut();
                headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(MEDIA));
                headers.insert(
                    header::CONTENT_LENGTH,
                    HeaderValue::from_str(&self.length.to_string())
                        .expect("numeric content length"),
                );
                headers.insert(header::ETAG, self.etag.expect("stream ETag"));
                headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
                headers.insert(header::CACHE_CONTROL, HeaderValue::from_static(CACHE));
                response
            }
        };
        if let Some(range) = self.range {
            response.headers_mut().insert(header::CONTENT_RANGE, range);
        }
        response
    }
}
impl Output for Download {
    fn responses() -> Vec<crate::signature::Response> {
        Kind::ALL
            .into_iter()
            .map(|kind| {
                let mut response = match kind {
                    Kind::Unsatisfied => {
                        crate::signature::Response::json::<Failure>(kind.status().as_u16())
                    }
                    Kind::Full | Kind::Partial => {
                        let mut response =
                            crate::signature::Response::empty(kind.status().as_u16());
                        response.body = Some(Representation {
                            content_type: MEDIA,
                            schema: Schema {
                                direction: Direction::Response,
                                value: serde_json::json!({"type":"string", "format":"binary"}),
                            },
                        });
                        for name in ["content-length", "etag"] {
                            response
                                .headers
                                .insert(name.into(), Schema::response::<String>());
                        }
                        for (name, value) in [("accept-ranges", "bytes"), ("cache-control", CACHE)]
                        {
                            let mut schema = Schema::response::<String>();
                            schema.value["const"] = value.into();
                            response.headers.insert(name.into(), schema);
                        }
                        response
                    }
                };
                if !matches!(kind, Kind::Full) {
                    response
                        .headers
                        .insert("content-range".into(), Schema::response::<String>());
                }
                response
            })
            .collect()
    }
}

/// A checked Content-Disposition header installed by the download's existing owner.
pub struct Attachment<T> {
    pub body: T,
    pub disposition: HeaderValue,
}
impl<T: IntoResponse> IntoResponse for Attachment<T> {
    fn into_response(self) -> Response {
        let mut response = self.body.into_response();
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, self.disposition);
        response
    }
}
impl<T: Output> Output for Attachment<T> {
    fn collection() -> bool {
        T::collection()
    }
    fn responses() -> Vec<crate::signature::Response> {
        T::responses()
            .into_iter()
            .map(|mut response| {
                response
                    .headers
                    .insert("content-disposition".into(), Schema::response::<String>());
                response
            })
            .collect()
    }
}
