//! Actual outer cache ownership before a pooled TLS handshake.

use std::{
    fmt,
    sync::{Arc, Mutex},
};

use super::{
    Acquisition, ConnectUdpError, ConnectUdpErrorKind, ConnectUdpProxyPool, ConnectorState, Entry,
    Http3Connector, HttpsProxyConnector, PoolKey, PoolState, SetupLease, TunnelLease, lock,
};

/// Pins one actual shared proxy connector before its first TLS use.
///
/// Prepare this value from the same base connectors and pool as the route.
/// Register its ticket-cache control before supplying it to a pooled route.
/// It neither authenticates a peer nor authorizes imported sessions.
/// Clearing the pool before setup selects this connector makes it stale.
/// Existing selected setup and active tunnels retain their original ownership.
pub struct PreparedConnectUdpOuter {
    key: PoolKey,
    connectors: Arc<Mutex<ConnectorState>>,
    pool: Arc<dyn PoolState>,
    connector: Connector,
}

enum Connector {
    Http2(Arc<HttpsProxyConnector>),
    Http3(Arc<Http3Connector>),
}

impl fmt::Debug for PreparedConnectUdpOuter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PreparedConnectUdpOuter")
            .finish_non_exhaustive()
    }
}

impl PreparedConnectUdpOuter {
    /// Returns a weak control for the actual prepared TCP or QUIC cache.
    /// Keeping the control does not retain the connector or its tickets.
    #[must_use]
    pub fn session_ticket_cache(&self) -> Option<crate::SessionTicketCache> {
        match &self.connector {
            Connector::Http2(connector) => connector.session_ticket_cache(),
            Connector::Http3(connector) => connector.session_ticket_cache(),
        }
    }

    pub(crate) fn validate(
        &self,
        pool: &ConnectUdpProxyPool,
        key: &PoolKey,
    ) -> Result<(), ConnectUdpError> {
        if !Arc::ptr_eq(&self.pool, &pool.inner) || self.key != *key {
            return Err(invalid_prepared());
        }
        self.validate_cache()
    }

    fn validate_entry(&self, entry: &Arc<Entry>) -> Result<(), ConnectUdpError> {
        if self.key != entry.key || !Arc::ptr_eq(&self.connectors, &entry.connectors) {
            return Err(invalid_prepared());
        }
        self.validate_cache()
    }

    fn validate_cache(&self) -> Result<(), ConnectUdpError> {
        let state = lock(&self.connectors);
        let current = match &self.connector {
            Connector::Http2(connector) => {
                state
                    .http2_connector
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, connector))
                    || state
                        .selected_http2
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, connector))
            }
            Connector::Http3(connector) => {
                state
                    .http3_connector
                    .as_ref()
                    .is_some_and(|current| Arc::ptr_eq(current, connector))
                    || state
                        .selected_http3
                        .as_ref()
                        .is_some_and(|current| Arc::ptr_eq(current, connector))
            }
        };
        if !current {
            return Err(invalid_prepared());
        }
        Ok(())
    }
}

impl ConnectUdpProxyPool {
    pub(crate) fn prepare_http2_selected(
        &self,
        key: PoolKey,
        base: &HttpsProxyConnector,
        owner: &crate::SessionTicketCacheOwner,
    ) -> Result<PreparedConnectUdpOuter, ConnectUdpError> {
        // Attachment is checked before either pool lock; registry callers must
        // finish cache selection before entering this method.
        let candidate = base
            .with_session_ticket_cache(owner)
            .map_err(|_| invalid_prepared())?;
        let entry = self.entry(key)?;
        let connector = {
            let mut state = lock(&entry.connectors);
            let current = state
                .selected_http2
                .get_or_insert_with(|| Arc::new(candidate));
            if !current
                .session_ticket_cache()
                .and_then(|cache| cache.upgrade())
                .is_some_and(|actual| actual.same_cache(owner))
            {
                return Err(conflicting_selected());
            }
            Arc::clone(current)
        };
        Ok(PreparedConnectUdpOuter {
            key: entry.key.clone(),
            connectors: Arc::clone(&entry.connectors),
            pool: Arc::clone(&self.inner),
            connector: Connector::Http2(connector),
        })
    }

    pub(crate) fn prepare_http3_selected(
        &self,
        key: PoolKey,
        base: &Http3Connector,
        owner: &crate::SessionTicketCacheOwner,
    ) -> Result<PreparedConnectUdpOuter, ConnectUdpError> {
        let candidate = base
            .with_session_ticket_cache(owner)
            .map_err(|_| invalid_prepared())?;
        let entry = self.entry(key)?;
        let connector = {
            let mut state = lock(&entry.connectors);
            let current = state
                .selected_http3
                .get_or_insert_with(|| Arc::new(candidate));
            if !current
                .session_ticket_cache()
                .and_then(|cache| cache.upgrade())
                .is_some_and(|actual| actual.same_cache(owner))
            {
                return Err(conflicting_selected());
            }
            Arc::clone(current)
        };
        Ok(PreparedConnectUdpOuter {
            key: entry.key.clone(),
            connectors: Arc::clone(&entry.connectors),
            pool: Arc::clone(&self.inner),
            connector: Connector::Http3(connector),
        })
    }
    pub(crate) fn prepare_http2(
        &self,
        key: PoolKey,
        base: &HttpsProxyConnector,
    ) -> Result<PreparedConnectUdpOuter, ConnectUdpError> {
        let entry = self.entry(key)?;
        let connector = {
            let mut state = lock(&entry.connectors);
            Arc::clone(
                state
                    .http2_connector
                    .get_or_insert_with(|| Arc::new(base.with_isolated_session_cache())),
            )
        };
        Ok(PreparedConnectUdpOuter {
            key: entry.key.clone(),
            connectors: Arc::clone(&entry.connectors),
            pool: Arc::clone(&self.inner),
            connector: Connector::Http2(connector),
        })
    }

    pub(crate) fn prepare_http3(
        &self,
        key: PoolKey,
        base: &Http3Connector,
    ) -> Result<PreparedConnectUdpOuter, ConnectUdpError> {
        let entry = self.entry(key)?;
        let connector = {
            let mut state = lock(&entry.connectors);
            Arc::clone(
                state
                    .http3_connector
                    .get_or_insert_with(|| Arc::new(base.with_isolated_session_cache())),
            )
        };
        Ok(PreparedConnectUdpOuter {
            key: entry.key.clone(),
            connectors: Arc::clone(&entry.connectors),
            pool: Arc::clone(&self.inner),
            connector: Connector::Http3(connector),
        })
    }

    pub(crate) async fn acquire_prepared(
        &self,
        key: PoolKey,
        prepared: &PreparedConnectUdpOuter,
    ) -> Result<Acquisition, ConnectUdpError> {
        prepared.validate(self, &key)?;
        let permit = self.admit().await?;
        let entry = self.entry(key)?;
        prepared.validate_entry(&entry)?;
        let lease = TunnelLease {
            entry,
            generation: 0,
            _permit: permit,
            _pool: Arc::clone(&self.inner),
        };
        let acquisition = Self::acquire_entry(lease).await?;
        acquisition.validate_prepared(prepared)?;
        Ok(acquisition)
    }
}

impl Acquisition {
    pub(crate) fn validate_prepared(
        &self,
        prepared: &PreparedConnectUdpOuter,
    ) -> Result<(), ConnectUdpError> {
        let entry = match self {
            Self::Setup(setup) => &setup.lease.as_ref().ok_or_else(invalid_prepared)?.entry,
            Self::Reuse { lease, .. } => &lease.entry,
        };
        prepared.validate_entry(entry)
    }
}

impl SetupLease {
    pub(crate) fn prepared_http2(
        &self,
        prepared: &PreparedConnectUdpOuter,
    ) -> Result<Arc<HttpsProxyConnector>, ConnectUdpError> {
        let lease = self.lease.as_ref().ok_or_else(invalid_prepared)?;
        prepared.validate_entry(&lease.entry)?;
        match &prepared.connector {
            Connector::Http2(connector) => Ok(Arc::clone(connector)),
            Connector::Http3(_) => Err(invalid_prepared()),
        }
    }

    pub(crate) fn prepared_http3(
        &self,
        prepared: &PreparedConnectUdpOuter,
    ) -> Result<Arc<Http3Connector>, ConnectUdpError> {
        let lease = self.lease.as_ref().ok_or_else(invalid_prepared)?;
        prepared.validate_entry(&lease.entry)?;
        match &prepared.connector {
            Connector::Http3(connector) => Ok(Arc::clone(connector)),
            Connector::Http2(_) => Err(invalid_prepared()),
        }
    }
}

pub(crate) fn invalid_prepared() -> ConnectUdpError {
    ConnectUdpError::new(
        ConnectUdpErrorKind::Configuration,
        "CONNECT-UDP prepared outer differs from the route or was cleared",
    )
}

fn conflicting_selected() -> ConnectUdpError {
    ConnectUdpError::new(
        ConnectUdpErrorKind::Configuration,
        "CONNECT-UDP outer pool already uses a different shared ticket store",
    )
}

#[cfg(test)]
mod tests;
