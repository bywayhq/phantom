//! Opt-in NSS key logging for the TLS contexts of a connector.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use btls::ssl::SslContextBuilder;
use phantom_quic_btls::NssKeyLogSender;

/// The key-log queue of one TLS context, attached after the context is built.
///
/// The context's callback holds a clone, so every connector clone that shares
/// the context shares the slot. It keeps the first sender attached to it.
#[derive(Clone, Default)]
pub(crate) struct KeyLogSlot(Arc<OnceLock<NssKeyLogSender>>);

impl KeyLogSlot {
    /// Sends the context's secrets to this slot's sender, once one is attached.
    pub(crate) fn install(&self, builder: &mut SslContextBuilder) {
        let slot = self.clone();
        builder.set_keylog_callback(move |_ssl, line| {
            if let Some(sender) = slot.0.get() {
                sender.send(line);
            }
        });
    }

    pub(crate) fn attach(&self, sender: &NssKeyLogSender) {
        let _ = self.0.set(sender.clone());
    }
}

impl fmt::Debug for KeyLogSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("KeyLogSlot")
            .field("attached", &self.0.get().is_some())
            .finish()
    }
}
