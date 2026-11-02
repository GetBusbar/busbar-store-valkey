// SPDX-License-Identifier: Apache-2.0
//! Observations for Valkey's timeout and TLS assertions; all I/O belongs to the real connector.
use busbar_contract::abi::mechanism::rendering::ReadNeed;
use busbar_contract::conn::{
    ConnCause, ConnError, ConnId, ConnWake, Conns, DeclaredConns, InstanceId, NeedId, OpenDesc,
    Piece,
};
use busbar_contract::transport::{ConnFacts, EgressTrust};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub(super) struct RecordedConnector {
    actual: Arc<dyn DeclaredConns>,
    timeouts: Mutex<Vec<u64>>,
    declared_timeouts: Mutex<HashMap<(InstanceId, NeedId), u64>>,
    security_failure: Mutex<Option<ConnCause>>,
}
impl std::fmt::Debug for RecordedConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecordedConnector").finish_non_exhaustive()
    }
}
impl RecordedConnector {
    pub(super) fn new(wake: ConnWake) -> Self {
        Self::with_trust(wake, EgressTrust::default())
    }
    pub(super) fn with_trust(wake: ConnWake, trust: EgressTrust) -> Self {
        Self {
            actual: super::valkey_io::host(wake, trust),
            timeouts: Mutex::new(Vec::new()),
            declared_timeouts: Mutex::new(HashMap::new()),
            security_failure: Mutex::new(None),
        }
    }
    pub(super) fn dial_timeouts(&self) -> Vec<u64> {
        self.timeouts.lock().unwrap().clone()
    }
    pub(super) fn security_failure(&self) -> Option<ConnCause> {
        self.security_failure.lock().unwrap().clone()
    }
    fn record_open(&self, owner: InstanceId, need: NeedId, timeout: u64) {
        // Observe the same zero-override fallback used by the production Connector; never alter it.
        let timeout = if timeout == 0 {
            self.declared_timeouts
                .lock()
                .unwrap()
                .get(&(owner, need))
                .copied()
                .unwrap_or(0)
        } else {
            timeout
        };
        self.timeouts.lock().unwrap().push(timeout);
    }
    fn observe_failure(&self, owner: InstanceId, conn: ConnId) {
        if let Some(cause) = self.actual.cause(owner, conn) {
            if cause.stage == busbar_contract::abi::host::conn::connector::CAUSE_SECURITY {
                *self.security_failure.lock().unwrap() = Some(cause);
            }
        }
    }
}
impl Conns for RecordedConnector {
    fn open(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
    ) -> Result<ConnId, ConnError> {
        self.record_open(owner, need, desc.timeout_ms);
        self.actual.open(owner, need, desc)
    }
    fn open_with_security(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        secure: bool,
    ) -> Result<ConnId, ConnError> {
        self.record_open(owner, need, desc.timeout_ms);
        self.actual.open_with_security(owner, need, desc, secure)
    }
    fn write(
        &self,
        owner: InstanceId,
        conn: ConnId,
        bytes: &[u8],
        end: bool,
        text: bool,
    ) -> Result<usize, ConnError> {
        self.actual.write(owner, conn, bytes, end, text)
    }
    fn read(
        &self,
        owner: InstanceId,
        conn: ConnId,
        ticket: u64,
        buf: &mut [u8],
    ) -> Result<Piece, ConnError> {
        self.actual.read(owner, conn, ticket, buf)
    }
    fn wait(&self, owner: InstanceId, set: &[ConnId], ticket: u64) -> Result<usize, ConnError> {
        self.actual.wait(owner, set, ticket)
    }
    fn facts(&self, owner: InstanceId, conn: ConnId) -> Result<ConnFacts, ConnError> {
        self.actual.facts(owner, conn)
    }
    fn close(&self, owner: InstanceId, conn: ConnId) -> Result<(), ConnError> {
        self.observe_failure(owner, conn);
        self.actual.close(owner, conn)
    }
}
impl DeclaredConns for RecordedConnector {
    fn declare(
        &self,
        owner: InstanceId,
        need: NeedId,
        spec: &ReadNeed,
        target: Option<&str>,
        trust: Option<&str>,
    ) -> Result<(), ConnError> {
        let result = self.actual.declare(owner, need, spec, target, trust);
        if result.is_ok() {
            self.declared_timeouts
                .lock()
                .unwrap()
                .insert((owner, need), spec.timeout_ms);
        }
        result
    }
    fn declared(&self, owner: InstanceId, need: NeedId) -> Option<Result<(), ConnError>> {
        self.actual.declared(owner, need)
    }
    fn open_request(
        &self,
        owner: InstanceId,
        need: NeedId,
        desc: &OpenDesc<'_>,
        secure: bool,
        dial_timeout_ms: u64,
    ) -> Result<ConnId, ConnError> {
        self.record_open(owner, need, dial_timeout_ms);
        self.actual
            .open_request(owner, need, desc, secure, dial_timeout_ms)
    }
    fn upgrade_secure(
        &self,
        owner: InstanceId,
        conn: ConnId,
        name: Option<&str>,
        trust: Option<&str>,
        verify_off: bool,
        ticket: u64,
    ) -> Result<(), ConnError> {
        let result = self
            .actual
            .upgrade_secure(owner, conn, name, trust, verify_off, ticket);
        self.observe_failure(owner, conn);
        result
    }
    fn landed(&self, owner: InstanceId, conn: ConnId, ticket: u64) -> Result<(), ConnError> {
        self.actual.landed(owner, conn, ticket)
    }
    fn framed(&self, owner: InstanceId, need: NeedId) -> bool {
        self.actual.framed(owner, need)
    }
    fn serves_scheme(&self, transport: &str) -> bool {
        self.actual.serves_scheme(transport)
    }
    fn cause(&self, owner: InstanceId, conn: ConnId) -> Option<ConnCause> {
        self.observe_failure(owner, conn);
        self.actual.cause(owner, conn)
    }
    fn hold_authority(&self, owner: InstanceId) {
        self.actual.hold_authority(owner)
    }
    fn forget(&self, owner: InstanceId) {
        self.actual.forget(owner);
        self.declared_timeouts
            .lock()
            .unwrap()
            .retain(|(at, _), _| *at != owner);
    }
}
