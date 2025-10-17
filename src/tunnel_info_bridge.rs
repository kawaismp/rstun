//! Lightweight bridge for reporting tunnel state/log/traffic to an optional listener.
//!
//! This module provides the `TunnelInfoBridge` type, which can be used to send
//! serialized tunnel information (state, logs, traffic) to a listener function.
//! The listener can be installed by the user and, if set, will receive updates
//! whenever tunnel information is available.

use serde::Serialize;
use std::sync::Arc;
use parking_lot::Mutex;

#[derive(Serialize, Default, Clone)]
/// Traffic counters aggregated over time.
pub(crate) struct TunnelTraffic {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub tx_dgrams: u64,
    pub rx_dgrams: u64,
}

#[derive(Serialize)]
/// Discriminator for the type of info carried in TunnelInfo.
pub(crate) enum TunnelInfoType {
    TunnelState,
    TunnelLog,
    TunnelTraffic,
}

#[derive(Serialize)]
/// A serializable wrapper carrying a typed info payload for reporting.
pub(crate) struct TunnelInfo<T>
where
    T: ?Sized + Serialize,
{
    pub info_type: TunnelInfoType,
    pub data: Box<T>,
}

impl<T> TunnelInfo<T>
where
    T: ?Sized + Serialize,
{
    /// Create a new TunnelInfo with a specific type and payload.
    pub(crate) fn new(info_type: TunnelInfoType, data: Box<T>) -> Self {
        Self { info_type, data }
    }
}

#[derive(Clone)]
/// Posts serialized tunnel info to a user-provided listener, if installed.
pub(crate) struct TunnelInfoBridge {
    listener: Option<Arc<Mutex<dyn FnMut(&str) + 'static + Send + Sync>>>,
}

impl TunnelInfoBridge {
    /// Create a new, empty TunnelInfoBridge.
    pub(crate) fn new() -> Self {
        TunnelInfoBridge { listener: None }
    }

    /// Install a listener that will receive JSON-serialized TunnelInfo payloads.
    ///
    /// The listener is a mutable function pointer that will be called with a
    /// string slice (`&str`) argument containing the serialized TunnelInfo.
    pub(crate) fn set_listener(&mut self, listener: impl FnMut(&str) + 'static + Send + Sync) {
        self.listener = Some(Arc::new(Mutex::new(listener)));
    }

    /// Return whether a listener is active.
    pub(crate) fn has_listener(&self) -> bool {
        self.listener.is_some()
    }

    /// Serialize and post a TunnelInfo to the installed listener (if any).
    pub(crate) fn post_tunnel_info<T>(&self, data: TunnelInfo<T>)
    where
        T: ?Sized + Serialize,
    {
        if let Some(ref listener) = self.listener {
            if let Ok(json) = serde_json::to_string(&data) {
                listener.lock()(json.as_str());
            }
        }
    }
}
