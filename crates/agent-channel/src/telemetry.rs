//! Telemetry uses the existing mutually authenticated Agent runtime boundary.
use super::*;
use rss_mdm_http_contract::{Operation as RouteOperation, catalog as contracts};
use std::io::Read;
fn failure(error: rss_mdm_telemetry_service::Error) -> AgentError {
    use rss_mdm_telemetry_service::Error as T;
    match error {
        T::Unsupported => Error::Unsupported,
        T::NotFound => Error::NotFound,
        T::Invalid => Error::Malformed,
        T::Conflict => Error::Conflict,
        T::Denied => Error::Forbidden,
        T::Unknown => Error::CommitUnknown,
        T::Capacity | T::Storage => Error::Unavailable(Failure::Database),
    }
    .into()
}
fn service(app: &HttpState) -> Result<&Arc<rss_mdm_telemetry_service::Service>, AgentError> {
    app.telemetry
        .as_ref()
        .ok_or_else(|| Error::Unsupported.into())
}
pub(super) fn routes()
-> Router<Arc<HttpState>, impl rss_mdm_http_contract::module::Declaration + use<>> {
    {
        rss_mdm_http_contract::route_module! { struct RoutesModule1 for [Agent] { get_directory, get_material, get_current, get_configuration, post_gap_upload, get_gap_receipt, post_upload, get_receipt } }
        RoutesModule1 {
            get_directory: rss_mdm_http_contract::module::Route::new(
                "/telemetry/configurations",
                get(
                    directory,
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_material: rss_mdm_http_contract::module::Route::new(
                "/telemetry/configurations/{policy}/{version}/content",
                get(
                    material,
                    &contracts::DOWNLOAD_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_current: rss_mdm_http_contract::module::Route::new(
                "/telemetry/batches/{id}/observations/{observation}",
                get(
                    current,
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_configuration: rss_mdm_http_contract::module::Route::new(
                "/telemetry/configurations/{policy}/{version}",
                get(
                    configuration,
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            post_gap_upload: rss_mdm_http_contract::module::Route::new(
                "/telemetry/gaps",
                post(
                    gap_upload,
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_gap_receipt: rss_mdm_http_contract::module::Route::new(
                "/telemetry/gaps/{id}",
                get(
                    gap_receipt,
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            post_upload: rss_mdm_http_contract::module::Route::new(
                "/telemetry/batches",
                post(
                    upload,
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
            get_receipt: rss_mdm_http_contract::module::Route::new(
                "/telemetry/batches/{id}",
                get(
                    receipt,
                    &contracts::PROTOCOL_AGENT_CHANNEL,
                    &[RouteOperation::Action],
                ),
            ),
        }
        .assemble()
    }
}
async fn upload(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    body: Result<crate::contract::Buffered<TelemetryJson<wire::TelemetryUpload>>, BytesRejection>,
) -> Result<WithStatus<202, Json<wire::TelemetryReceipt>>, AgentError> {
    json_content_type(&headers)?;
    let service = service(&app)?;
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_upload",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    let bytes = body.map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    let decoded = bytes.decode(&headers, service.request_bytes())?;
    let input = decoded.value;
    let result = bounded(async {
        service
            .receive(&principal, &input, decoded.bytes)
            .await
            .map_err(failure)
    })
    .await?;
    Ok(WithStatus(Json(result)))
}
async fn gap_upload(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    body: Result<
        crate::contract::Buffered<TelemetryJson<wire::TelemetryGapReport>>,
        BytesRejection,
    >,
) -> Result<WithStatus<202, Json<wire::TelemetryGapReceipt>>, AgentError> {
    json_content_type(&headers)?;
    let service = service(&app)?;
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_gap_upload",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    let bytes = body.map_err(|_| AgentError::Wire(wire::ErrorCode::MalformedRequest))?;
    let decoded = bytes.decode(
        &headers,
        service.request_bytes().min(wire::TELEMETRY_GAP_MAX_BYTES),
    )?;
    let input = decoded.value;
    let result = bounded(async {
        service
            .receive_gap(&principal, &input, decoded.bytes)
            .await
            .map_err(failure)
    })
    .await?;
    Ok(WithStatus(Json(result)))
}
async fn gap_receipt(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path(id): Path<Uuid>,
) -> Result<Json<wire::TelemetryGapReceipt>, AgentError> {
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_gap_status",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    bounded(async {
        service(&app)?
            .gap_status(&principal, id)
            .await
            .map(Json)
            .map_err(failure)
    })
    .await
}

async fn receipt(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path(id): Path<Uuid>,
) -> Result<Json<wire::TelemetryReceipt>, AgentError> {
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_status",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    bounded(async {
        service(&app)?
            .status(&principal, id)
            .await
            .map(Json)
            .map_err(failure)
    })
    .await
}

async fn configuration(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path((policy, version)): Path<(Uuid, Uuid)>,
) -> Result<Json<wire::SignedTelemetryConfiguration>, AgentError> {
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_configuration",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    bounded(async {
        service(&app)?
            .configuration(&principal, policy, version)
            .await
            .map(Json)
            .map_err(failure)
    })
    .await
}

async fn current(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path((id, observation)): Path<(Uuid, Uuid)>,
) -> Result<Json<wire::TelemetryCurrentStatus>, AgentError> {
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_current_status",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    bounded(async {
        use rss_mdm_telemetry_service::CurrentObservation as C;
        let state = match service(&app)?
            .current_observation(&principal, id, observation)
            .await
            .map_err(failure)?
        {
            C::NotRequested => wire::TelemetryCurrentState::NotRequested,
            C::Pending => wire::TelemetryCurrentState::Pending,
            C::Admitted(run) => {
                let (observation, projection) =
                    projection_status(app.inventory.inspect(&run).await?)?;
                wire::TelemetryCurrentState::Observed {
                    observation,
                    projection,
                }
            }
        };
        Ok(Json(wire::TelemetryCurrentStatus {
            batch_id: id,
            observation_id: observation,
            state,
        }))
    })
    .await
}

fn decode(headers: &HeaderMap, bytes: &Bytes, limit: usize) -> Result<Vec<u8>, AgentError> {
    if headers.get_all(header::CONTENT_ENCODING).iter().count() > 1 {
        return Err(Error::Malformed.into());
    }
    if bytes.len() > limit {
        return Err(Error::Malformed.into());
    }
    let decoded = match headers.get(header::CONTENT_ENCODING).map(|v| v.to_str()) {
        None | Some(Ok("identity")) => bytes.to_vec(),
        Some(Ok("gzip")) => {
            let mut out = Vec::new();
            let mut decoder = flate2::bufread::GzDecoder::new(std::io::Cursor::new(bytes.as_ref()));
            (&mut decoder)
                .take(limit as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|_| Error::Malformed)?;
            if decoder.get_ref().position() != bytes.len() as u64 {
                return Err(Error::Malformed.into());
            }
            if out.len() > limit {
                return Err(Error::Malformed.into());
            }
            out
        }
        _ => return Err(Error::Malformed.into()),
    };
    Ok(decoded)
}

async fn material(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
    Path((policy, version)): Path<(Uuid, Uuid)>,
) -> Result<rss_mdm_http_contract::download::Download, AgentError> {
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_material",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    bounded(async {
        let store = app.content.as_ref().ok_or(Error::Unsupported)?.clone();
        let verified = service(&app)?
            .content(&principal, policy, version, store)
            .await
            .map_err(failure)?;
        super::content::response(verified, &headers)
            .await
            .map_err(Into::into)
    })
    .await
}

async fn directory(
    State(app): State<Arc<HttpState>>,
    Extension(audit): Extension<RequestAudit>,
    peer: Option<Extension<rss_mdm_certificate::ClientCertificateEvidence>>,
    crate::contract::RuntimeHeaders(headers): crate::contract::RuntimeHeaders,
) -> Result<Json<wire::TelemetryDirectory>, AgentError> {
    let principal = authenticate(&app.enrollment, &headers, peer.as_ref().map(|p| &p.0)).await?;
    audit.set_action(
        "agent_telemetry_directory",
        rss_mdm_audit_integration::AuditIntent::Routine,
    );
    audit.identify_device(principal.registration());
    audit.registration(principal.registration());
    audit.target_device(principal.device());
    bounded(async {
        service(&app)?
            .directory(&principal)
            .await
            .map(Json)
            .map_err(failure)
    })
    .await
}

struct TelemetryJson<T>(std::marker::PhantomData<fn() -> T>);
impl<T: serde::de::DeserializeOwned + schemars::JsonSchema> crate::contract::BodyDecoder
    for TelemetryJson<T>
{
    type Value = T;
    fn decode(
        bytes: Bytes,
        headers: &HeaderMap,
        limit: usize,
    ) -> Result<crate::contract::Decoded<T>, AgentError> {
        let decoded = decode(headers, &bytes, limit)?;
        Ok(crate::contract::Decoded {
            value: serde_json::from_slice(&decoded).map_err(|_| Error::Malformed)?,
            bytes: bytes.len().max(decoded.len()),
        })
    }
    fn request() -> rss_mdm_http_contract::signature::Request {
        use rss_mdm_http_contract::signature::{Direction, Representation, Request, Schema};
        Request {
            body: Some(Representation::json(Schema::request::<T>())),
            headers: [(
                "content-encoding".into(),
                Schema {
                    direction: Direction::Request,
                    value: serde_json::json!({"type":"string", "enum":["identity","gzip"]}),
                },
            )]
            .into(),
            ..Request::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    #[test]
    fn gzip_is_bounded_and_rejects_trailing_members_or_damaged_crc() {
        let mut compressor =
            flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        compressor.write_all(&vec![b'a'; 8192]).unwrap();
        let bytes = compressor.finish().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_ENCODING,
            axum::http::HeaderValue::from_static("gzip"),
        );
        assert!(decode(&headers, &Bytes::from(bytes.clone()), 1024).is_err());
        assert_eq!(
            decode(&headers, &Bytes::from(bytes.clone()), 16384)
                .map_err(|_| "gzip decode failed")
                .unwrap(),
            vec![b'a'; 8192]
        );
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(&bytes);
        assert!(decode(&headers, &Bytes::from(trailing), 32768).is_err());
        let mut damaged = bytes;
        let last = damaged.len() - 8;
        damaged[last] ^= 1;
        assert!(decode(&headers, &Bytes::from(damaged), 16384).is_err());
        headers.append(
            header::CONTENT_ENCODING,
            axum::http::HeaderValue::from_static("identity"),
        );
        assert!(decode(&headers, &Bytes::from_static(b"{}"), 1024).is_err());
    }
}
