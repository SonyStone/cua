// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

//! Extension point for services implemented outside this crate (the desktop
//! services: Computer, Windows, Accessibility, Stream, Presence), and the
//! stubs registered while no provider implements them.

use std::convert::Infallible;

use cua_proto::env::v1::Feature;

/// Fully-qualified names of the desktop services an extension provider is
/// expected to implement.
pub const DESKTOP_SERVICES: &[&str] = &[
    "cua.env.v1.ComputerService",
    "cua.env.v1.WindowsService",
    "cua.env.v1.AccessibilityService",
    "cua.env.v1.StreamService",
    "cua.env.v1.PresenceService",
];

/// Canonical feature names owned by the desktop services, reported as
/// unsupported unless a provider reports them.
pub const DESKTOP_FEATURES: &[&str] = &[
    "a11y",
    "background_input",
    "desktop_stream",
    "window_stream",
    "h264_hw",
    "h264_sw",
    "quic_media",
    "clipboard.text",
    "clipboard.files",
    "clipboard.image",
    "presence",
    "windows",
    "launch_app",
    "audio.desktop",
    "audio.per_app",
    "audio.uplink",
    "audio.opus",
];

pub use cua_spacesd_provider_api::host::ServiceProvider;

/// Feature helper.
pub fn feature(name: &str, supported: bool, limitation: impl Into<String>) -> Feature {
    Feature {
        name: name.to_owned(),
        supported,
        limitation: limitation.into(),
        attributes: Default::default(),
    }
}

/// Limitation reported for desktop features with no provider.
pub const NO_DESKTOP_PROVIDER: &str =
    "this cua-spacesd build has no desktop provider (Computer, Windows, Accessibility, Stream and Presence are unavailable)";

/// Feature named in the stub error for each desktop service.
fn stub_feature(service: &str) -> &'static str {
    match service {
        "cua.env.v1.ComputerService" => "background_input",
        "cua.env.v1.WindowsService" => "windows",
        "cua.env.v1.AccessibilityService" => "a11y",
        "cua.env.v1.StreamService" => "desktop_stream",
        "cua.env.v1.PresenceService" => "presence",
        _ => "desktop",
    }
}

/// Registers a stub answering every method of `service` with
/// `FAILED_PRECONDITION` + `ErrorInfo{FEATURE_UNSUPPORTED}`.
pub(crate) fn register_stub(routes: &mut tonic::service::Routes, service: &'static str) {
    register_stub_with(routes, service, stub_feature(service), NO_DESKTOP_PROVIDER);
}

/// Limitation reported by a driver that is not a host providing Spaces.
pub const NOT_A_SPACES_HOST: &str =
    "this computer does not provide Spaces (a host set up with `cua host setup --provide-spaces` does)";

/// [`register_stub`] with an explicit feature and limitation.
pub(crate) fn register_stub_with(
    routes: &mut tonic::service::Routes,
    service: &'static str,
    feature_name: &'static str,
    limitation: &'static str,
) {
    let stub = tower::service_fn(move |_req: http::Request<axum::body::Body>| async move {
        let status = crate::error::unsupported(feature_name, format!("{service}: {limitation}"));
        Ok::<_, Infallible>(status.into_http::<axum::body::Body>())
    });
    let router = std::mem::take(routes.axum_router_mut());
    *routes.axum_router_mut() = router.route_service(&format!("/{service}/{{*rest}}"), stub);
}
