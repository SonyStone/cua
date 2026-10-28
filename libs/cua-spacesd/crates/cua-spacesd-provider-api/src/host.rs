// SPDX-License-Identifier: FSL-1.1-MIT
// Copyright (c) 2026 Cua AI, Inc.

//! What a service provider needs from the server that hosts it: the
//! [`ServiceProvider`] extension point, the caller of a request, tickets for
//! side channels and the host state behind [`ProviderHost`].
//!
//! These live here, not in cua-spacesd-server, so a provider (the desktop
//! services) builds without the server and can be hosted by another one.
//! cua-spacesd-server re-exports every item and implements [`ProviderHost`]
//! for its `ServerContext`.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use cua_driver_core::server::ToolProvider;
use cua_proto::env::v1::{
    ComponentHealth, Display, DisplayServer, Feature, Principal, PrincipalKind,
};

/// Largest encoded gRPC message accepted or sent.
pub const MAX_MESSAGE_BYTES: u32 = 8 * 1024 * 1024;

/// What a ticket may open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TicketScope {
    /// The media WebSocket / QUIC session (`/media`).
    Media,
    /// TCP forwarding (`/tunnel`).
    Tunnel,
    /// Reverse-SOCKS egress (`/hotspot`).
    Hotspot,
    /// The Cua Volume mount's client socket (`/volume`).
    Volume,
    /// File transfer side channels.
    Files,
    /// The web viewer's scoped bearer (`SystemService.CreateViewerTicket`).
    Viewer,
}

impl TicketScope {
    /// Stable wire name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Media => "media",
            Self::Tunnel => "tunnel",
            Self::Hotspot => "hotspot",
            Self::Volume => "volume",
            Self::Files => "files",
            Self::Viewer => "viewer",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "media" => Self::Media,
            "tunnel" => Self::Tunnel,
            "hotspot" => Self::Hotspot,
            "volume" => Self::Volume,
            "files" => Self::Files,
            "viewer" => Self::Viewer,
            _ => return None,
        })
    }
}

/// Verified contents of a ticket.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketClaims {
    /// Scope the ticket was minted for.
    pub scope: TicketScope,
    /// Resource id the ticket is bound to (forward id, hotspot id, media
    /// session id, ...).
    pub resource: String,
    /// `Principal.id` of the minting caller (may be empty).
    pub principal_id: String,
    /// Expiry.
    pub expires_at: SystemTime,
}

/// What a viewer ticket allows, carried in the ticket's resource field.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct ViewerGrant {
    /// Highest `SessionPolicy` (as its proto number) media may open with.
    #[serde(rename = "p")]
    pub policy: i32,
    /// `ComputerService.GetClipboard` / `SetClipboard`.
    #[serde(rename = "c", default)]
    pub clipboard: bool,
    /// Absolute guest directory for `FilesystemService`, if any.
    #[serde(rename = "f", default, skip_serializing_if = "Option::is_none")]
    pub files_root: Option<String>,
    /// Microphone uplink.
    #[serde(rename = "u", default)]
    pub audio_uplink: bool,
    /// Principal id (already `viewer:`-prefixed).
    #[serde(rename = "i", default)]
    pub principal_id: String,
    /// Principal display name.
    #[serde(rename = "n", default)]
    pub display_name: String,
}

impl ViewerGrant {
    /// The principal a viewer ticket acts as.
    pub fn principal(&self) -> Principal {
        Principal {
            id: self.principal_id.clone(),
            display_name: self.display_name.clone(),
            color: String::new(),
            kind: PrincipalKind::Human as i32,
        }
    }

    /// Clamps a requested `SessionPolicy` to the grant (view-only <
    /// background-only < allow-activation).
    pub fn clamp_policy(&self, requested: i32) -> i32 {
        requested.min(self.policy)
    }
}

/// Why a ticket was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TicketError {
    /// Not a ticket at all.
    Malformed,
    /// Signature mismatch (tampered, or the token rotated).
    BadSignature,
    /// Past its expiry.
    Expired,
    /// Minted for a different scope.
    WrongScope,
}

impl std::fmt::Display for TicketError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Malformed => "malformed ticket",
            Self::BadSignature => "invalid ticket signature",
            Self::Expired => "ticket expired",
            Self::WrongScope => "ticket not valid for this endpoint",
        })
    }
}

impl std::error::Error for TicketError {}

/// The relay-verified account of a call.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RelayCaller {
    /// Account id (the assertion's `acct`).
    pub account: String,
    /// Verified email, when the relay shares it.
    pub email: Option<String>,
    /// Display name.
    pub name: Option<String>,
    /// `owner` or `shared` (an editor).
    pub role: String,
    /// The relay assertion's `iat` (seconds, relay clock). Tickets minted
    /// for the call carry it, so the relay can refuse one that predates a
    /// revoke of this account.
    pub issued_at: u64,
    /// Teams (or organizations) the relay admitted the account through;
    /// empty for the owner and a direct share. Share links to a team check
    /// these.
    pub teams: Vec<String>,
    /// A thread grant: the one Space this machine provides (its relay
    /// machine id) whose thread the account may reach, because that Space
    /// is shared with it; `role` is its role on that Space. Such a caller
    /// reaches `THREAD_GRANT_GRPC_METHODS` only.
    pub space: Option<String>,
}

/// Request extension set by the host's auth layer on every authorized gRPC call.
#[derive(Debug, Clone, Default)]
pub struct CallerIdentity {
    /// The decoded `x-cua-principal-bin`, if any.
    pub principal: Option<Principal>,
    /// True when the call presented the configured token.
    pub token_verified: bool,
    /// True when `principal` was asserted by an external authenticator
    /// (a relay-signed identity) or a viewer ticket: services must not let
    /// the request body override its id or display name.
    pub asserted: bool,
    /// Set when the call was authorized by a viewer ticket: services clamp
    /// what they do to the grant.
    pub viewer: Option<Arc<ViewerGrant>>,
    /// The relay-verified account of a relayed call.
    pub account: Option<RelayCaller>,
    /// A relayed call to a machine that does not share its desktop
    /// (`ExternalGrant::host_only` in cua-spacesd-server): `GetCapabilities` reports the
    /// desktop's features unsupported to it.
    pub host_only: bool,
}

/// Reads the [`CallerIdentity`] a request was authorized with.
pub fn caller<T>(request: &tonic::Request<T>) -> CallerIdentity {
    request
        .extensions()
        .get::<CallerIdentity>()
        .cloned()
        .unwrap_or_default()
}

/// A bundle of extra gRPC services and HTTP routes served on the driver port.
///
/// Lifecycle: the host builds its context, constructs providers (keeping a
/// [`ProviderHost`] if they need tickets or host state), and registers them.
/// At build time the host calls, in order, [`ServiceProvider::register`]
/// (once) and [`ServiceProvider::http_routes`] (once), and calls
/// [`ServiceProvider::capabilities`], [`ServiceProvider::displays`] and
/// [`ServiceProvider::health`] on every `GetCapabilities` / `Health`.
///
/// Rules:
/// - Every gRPC service added in `register` must be listed in
///   [`ServiceProvider::services`]; the host answers every desktop service no
///   provider claims with `FAILED_PRECONDITION`, and registering the same
///   service twice panics at build time.
/// - gRPC services are authenticated by the host before they run; read the
///   caller with [`caller`].
/// - HTTP routes are **not** authenticated by the host: they are side
///   channels that must validate a ticket
///   ([`ProviderHost::validate_request_ticket`]) themselves. Every path must
///   be listed in [`ServiceProvider::http_paths`] and must be one of the
///   paths in `cua_proto::metadata`.
pub trait ServiceProvider: Send + Sync + 'static {
    /// Features this provider implements (supported or not, with
    /// limitations). Entries override the host's defaults by name.
    fn capabilities(&self) -> Vec<Feature>;

    /// Adds this provider's tonic services to `routes`.
    fn register(
        &self,
        routes: tonic::service::Routes,
        host: &dyn ProviderHost,
    ) -> tonic::service::Routes;

    /// HTTP routes (for example the `/media` WebSocket), if any.
    fn http_routes(&self) -> Option<axum::Router>;

    /// Fully-qualified names (`cua.env.v1.StreamService`) of the gRPC
    /// services `register` adds.
    fn services(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Paths served by [`ServiceProvider::http_routes`].
    fn http_paths(&self) -> Vec<&'static str> {
        Vec::new()
    }

    /// Displays for `GetCapabilities.displays`.
    fn displays(&self) -> Vec<Display> {
        Vec::new()
    }

    /// Graphical session type for `GetCapabilities.display_server`.
    fn display_server(&self) -> Option<DisplayServer> {
        None
    }

    /// Per-component health for `Health` (and `/health`).
    fn health(&self) -> Vec<ComponentHealth> {
        Vec::new()
    }

    /// The cua-driver tool registry this provider already built, so the
    /// Driver service and `/mcp` share it instead of building a second one.
    fn tool_provider(&self) -> Option<Arc<dyn ToolProvider>> {
        None
    }
}

/// Host state a provider reads or updates while serving calls.
pub trait ProviderHost: Send + Sync + 'static {
    /// Mints a ticket for `scope` bound to `resource`; `issued` is the relay
    /// assertion time of the minting call, if relayed.
    fn mint_ticket_issued(
        &self,
        scope: TicketScope,
        resource: &str,
        principal: Option<&Principal>,
        issued: Option<u64>,
        ttl: Duration,
    ) -> (String, SystemTime);

    /// Validates a ticket string for `scope`.
    fn validate_ticket(
        &self,
        ticket: &str,
        scope: TicketScope,
    ) -> Result<TicketClaims, TicketError>;

    /// Finds and validates the ticket on an HTTP/WebSocket request (query
    /// `ticket=` or subprotocol `cua.ticket.<ticket>`). On success returns
    /// the claims and the subprotocol to echo, if any.
    fn validate_request_ticket(
        &self,
        uri: &http::Uri,
        headers: &http::HeaderMap,
        scope: TicketScope,
    ) -> Result<(TicketClaims, Option<String>), TicketError>;

    /// Changes whenever the credential behind tickets rotates: every ticket
    /// minted before is invalid.
    fn token_rotations(&self) -> tokio::sync::watch::Receiver<u64>;

    /// Changes whenever this machine's secrets were renewed; providers
    /// holding per-machine keys of their own regenerate them.
    fn machine_renewals(&self) -> tokio::sync::watch::Receiver<u64>;

    /// Reports the number of open media sessions.
    fn set_media_sessions(&self, count: u32);

    /// Whether `principal` may open an audio uplink.
    fn audio_uplink_allowed(&self, principal: Option<&Principal>) -> bool;

    /// Whether presence may probe the real cursor shape by briefly moving
    /// the idle pointer.
    fn cursor_probe(&self) -> bool;
}

/// Records an authorized screenshot once its handler knows the size asked
/// for (the host decides what and where to record).
pub trait ScreenshotRecorder: Send + Sync + 'static {
    /// `max_dimension`: the long edge asked for, 0 for full size.
    fn record(&self, max_dimension: u32);
}

/// Request extension the host sets on an authorized
/// `ComputerService.Screenshot` call it wants recorded.
#[derive(Clone)]
pub struct PendingScreenshot(pub Arc<dyn ScreenshotRecorder>);

impl std::fmt::Debug for PendingScreenshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PendingScreenshot")
    }
}

/// Records the screenshot `request` asks for (`ComputerService.Screenshot`
/// handlers call it first): a thumbnail or a screen read, by its size.
pub fn record_screenshot<T>(request: &tonic::Request<T>, max_dimension: u32) {
    if let Some(p) = request.extensions().get::<PendingScreenshot>() {
        p.0.record(max_dimension);
    }
}

/// Keeps a viewer inside its grant's `files_root`: the lexical path must be
/// under the root, and so must the canonical form of its deepest existing
/// ancestor (a symlink inside the root cannot lead out of it). The error is
/// the reason, for a `PermissionDenied` status.
pub fn confine(grant: &ViewerGrant, path: PathBuf) -> Result<PathBuf, String> {
    let Some(root) = grant.files_root.as_deref().map(Path::new) else {
        return Err("no file access was granted".into());
    };
    if !path.starts_with(root) {
        return Err(format!("{} is outside {}", path.display(), root.display()));
    }
    let mut probe = path.as_path();
    loop {
        match std::fs::canonicalize(probe) {
            Ok(real) => {
                if !real.starts_with(root) {
                    return Err(format!("{} leaves {}", path.display(), root.display()));
                }
                break;
            }
            Err(_) => match probe.parent() {
                Some(parent) => probe = parent,
                None => break,
            },
        }
    }
    Ok(path)
}
