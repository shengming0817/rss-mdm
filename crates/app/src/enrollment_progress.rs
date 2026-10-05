//! Product composition joins lifecycle coordinates with the native and PKI owners.
//! ref: sqlx sqlx-core/src/transaction.rs@v0.8.6; Microsoft OnPremise device enrollment.
use rss_mdm_inventory::ReportSource;
use rss_mdm_registration_service::{Error, enrollment::read::*};
use std::sync::Arc;
pub(crate) struct EnrollmentProgress {
    pub(crate) sessions: Arc<rss_mdm_authorization_service::session::SessionAuthority>,
    pub(crate) windows: Option<Arc<rss_mdm_windows_channel::Windows>>,
    pub(crate) apple: Option<Arc<rss_mdm_apple_channel::Apple>>,
}
impl NativeProgress for EnrollmentProgress {
    fn channels(&self) -> Vec<ChannelOption> {
        let mut channels = Vec::new();
        if self.windows.is_some() {
            channels.push(ChannelOption {
                source: ReportSource::MdmWindows,
                requires_local_administrator: true,
            });
        }
        if self.apple.is_some() {
            channels.push(ChannelOption {
                source: ReportSource::MdmApple,
                requires_local_administrator: true,
            });
        }
        channels
    }
    fn read<'a>(
        &'a self,
        c: &'a mut sqlx::PgConnection,
        context: &'a Context,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<NativeDetails, Error>> + Send + 'a>,
    > {
        Box::pin(async move {
            let mut details = match context.source {
                ReportSource::MdmWindows => self.windows(c, context).await?,
                ReportSource::MdmApple => self.apple(c, context).await?,
                ReportSource::AgentBuiltin => return Err(Error::Corrupt),
            };
            if let Some(registration) = &context.registration {
                let purpose = match context.source {
                    ReportSource::MdmWindows => rss_mdm_agent_wire::pki::Purpose::Windows,
                    ReportSource::MdmApple => rss_mdm_agent_wire::pki::Purpose::Apple,
                    ReportSource::AgentBuiltin => return Err(Error::Corrupt),
                };
                details.credential_usable =
                    rss_mdm_pki_service::certificates::current_native_credential_in(
                        c,
                        &context.tenant,
                        registration.id,
                        purpose,
                        context.now,
                    )
                    .await
                    .map_err(|_| Error::Storage)?;
            }
            Ok(details)
        })
    }
}
impl EnrollmentProgress {
    async fn windows(
        &self,
        c: &mut sqlx::PgConnection,
        context: &Context,
    ) -> Result<NativeDetails, Error> {
        let Some(windows) = &self.windows else {
            return Ok(unavailable());
        };
        let certificate_issued =
            rss_mdm_windows_channel::enrollment_store::certificate_issued(c, context)
                .await
                .map_err(|_| Error::Storage)?;
        let first_authenticated_check_in = context
            .registration
            .as_ref()
            .is_some_and(|r| r.first_authenticated_at.is_some());
        Ok(NativeDetails {
            instructions: Instructions::Windows {
                server: windows.enrollment_origin.clone(),
                discovery_url: format!(
                    "{}/EnrollmentServer/Discovery.svc",
                    windows.enrollment_origin
                ),
                username: windows
                    .enrollment_username(context.enrollment)
                    .map_err(|_| Error::Configuration)?,
                windows_profile: context.windows_profile.ok_or(Error::Corrupt)?,
                requires_local_administrator: true,
            },
            profile_prepared: Observation::NotApplicable,
            certificate_issued,
            first_authenticated_check_in,
            channel_ready: first_authenticated_check_in,
            credential_usable: false,
            reauthentication_required: false,
        })
    }
    async fn apple(
        &self,
        c: &mut sqlx::PgConnection,
        context: &Context,
    ) -> Result<NativeDetails, Error> {
        if self.apple.is_none() {
            return Ok(unavailable());
        }
        let evidence = rss_mdm_apple_channel::enrollment::progress_in(c, context)
            .await
            .map_err(|_| Error::Storage)?;
        let (instructions, reauthentication_required) = if context.organization_driven {
            (
                Instructions::MacosAde {
                    enrollment_method: "automated_device_enrollment",
                },
                false,
            )
        } else if context.account_driven {
            let (managed_account, required) =
                rss_mdm_apple_channel::account_enrollment::progress_in(c, &self.sessions, context)
                    .await
                    .map_err(|_| Error::Storage)?;
            (
                Instructions::MacosAccount {
                    managed_account,
                    enrollment_method: "account_driven_device_enrollment",
                },
                required,
            )
        } else {
            (
                Instructions::Macos {
                    profile_url: format!("/api/v1/enrollments/{}/profile", context.enrollment),
                    enrollment_method: "profile_based_device_enrollment",
                },
                false,
            )
        };
        Ok(NativeDetails {
            instructions,
            profile_prepared: if evidence.profile_prepared {
                Observation::Observed
            } else {
                Observation::Unknown
            },
            certificate_issued: evidence.certificate_issued,
            first_authenticated_check_in: evidence.first_authenticated_check_in,
            channel_ready: evidence.channel_ready,
            credential_usable: false,
            reauthentication_required,
        })
    }
}
fn unavailable() -> NativeDetails {
    // reason: absent product channel configuration is an explicit unavailable result.
    NativeDetails {
        instructions: Instructions::Unavailable,
        profile_prepared: Observation::Unknown,
        certificate_issued: false,
        first_authenticated_check_in: false,
        channel_ready: false,
        credential_usable: false,
        reauthentication_required: false,
    }
}
