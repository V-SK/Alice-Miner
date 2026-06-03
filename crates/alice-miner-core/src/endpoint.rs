//! `core/endpoint` — the multi-endpoint failover data shapes ([`Transport`],
//! [`Endpoint`], [`EndpointPlan`]) shared by both lanes (PLAN §5 M4).
//!
//! ── ENDPOINT POLICY (CRITICAL honesty/security — PLAN §4 brief, §6 D-Q5) ─────
//! The PUBLIC client ships **ONLY `hk.aliceprotocol.org`** (the friend's HK
//! relay) in its default [`EndpointPlan`]. The Finland **core IP must NEVER be
//! baked into the client** — it is an operator-only override via the
//! `ALICE_MINER_ENDPOINTS_JSON` env var. The upstream pool + OUR collection
//! address are server-side on the relay and never appear here. A unit test
//! asserts the compiled/default endpoint set contains the relay host and NOT the
//! core IP / collection address / upstream pool.
//!
//! ── Transport (M4 scaffolding so M9/Reality is purely additive) ──────────────
//! [`Transport::Plaintext`] (T0, default, FET-exempt) and [`Transport::Tls`] (T1,
//! opportunistic `stratum+ssl`). The lane arg builders + [`EndpointPlan`] are
//! transport-aware; **Reality is NOT implemented here** — it is a later additive
//! variant that reuses this enum (PLAN M9).

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use crate::lane::{gpu_rvn, xmr, Lane};

/// Env var an OPERATOR sets to override the default [`EndpointPlan`] (e.g. to
/// point at the Finland core directly, or to add TLS fallbacks). A JSON array of
/// endpoint objects — see [`EndpointPlan::from_env_for`]. **Never** set in the
/// public client; the core IP lives ONLY here, never in compiled defaults.
pub const ENDPOINTS_ENV: &str = "ALICE_MINER_ENDPOINTS_JSON";

/// The wire transport for a stratum endpoint. M4 ships T0/T1; [`Transport`] is
/// the scaffolding that makes M9 (bundled Xray VLESS+Reality) a purely additive
/// `Reality` variant — the lane arg builders + [`EndpointPlan`] already branch on
/// it, so adding a third variant touches no call site's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// T0 — plain TCP stratum (`stratum+tcp://`). The default; FET-exempt
    /// (looks like ordinary mining traffic). The proven XMR path uses this.
    #[default]
    Plaintext,
    /// T1 — opportunistic TLS stratum (`stratum+ssl://`). Used only when an
    /// endpoint is explicitly declared `tls` (operator override). The relay must
    /// terminate TLS on that port; we do NOT downgrade-probe.
    Tls,
}

impl Transport {
    /// The stratum URL scheme for this transport (used by the GPU lane's `-P`/`-o`
    /// URL forms). `Plaintext` → `stratum+tcp`, `Tls` → `stratum+ssl`.
    pub fn stratum_scheme(self) -> &'static str {
        match self {
            Transport::Plaintext => "stratum+tcp",
            Transport::Tls => "stratum+ssl",
        }
    }

    /// A short, honest UI/label token.
    pub fn label(self) -> &'static str {
        match self {
            Transport::Plaintext => "tcp",
            Transport::Tls => "tls",
        }
    }
}

/// One ordered stratum endpoint: where to connect + how. The host/port are the
/// PUBLIC relay (or, under an operator override, whatever the operator declares —
/// e.g. the core). Cloneable + serialisable; carries no secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Endpoint {
    /// The stratum host (the public client ships only `hk.aliceprotocol.org`).
    pub host: String,
    /// The stratum port (3333 XMR / 8888 RVN on the relay).
    pub port: u16,
    /// The wire transport (defaults to plaintext when omitted in JSON).
    #[serde(default)]
    pub transport: Transport,
}

impl Endpoint {
    /// A plaintext endpoint (the common case).
    pub fn plaintext(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            transport: Transport::Plaintext,
        }
    }

    /// A TLS endpoint (operator override only).
    pub fn tls(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
            transport: Transport::Tls,
        }
    }

    /// `host:port` (the form xmrig's `-o` and the dashboard label want).
    pub fn host_port(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }

    /// The full stratum URL for this endpoint (the GPU lane's URL forms):
    /// `stratum+tcp://host:port` (or `+ssl`). No credentials.
    pub fn stratum_url(&self) -> String {
        format!("{}://{}:{}", self.transport.stratum_scheme(), self.host, self.port)
    }
}

/// An ordered set of stratum endpoints with a failover cursor (PLAN §5 M4).
///
/// The cursor names the endpoint the lane is CURRENTLY targeting. Layer A passes
/// the miner ALL endpoints (xmrig's multiple `-o`, kawpowminer's multiple `-P`)
/// so the miner itself fails over fast; Layer B (the supervisor's no-progress
/// watchdog) advances [`EndpointPlan::cursor`] and restarts the child pointed at
/// the next endpoint when the miner makes no progress (see [`crate::supervise`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EndpointPlan {
    /// Ordered endpoints, primary first. Always non-empty (constructors enforce).
    endpoints: Vec<Endpoint>,
    /// Index of the endpoint currently targeted (Layer-B failover cursor).
    cursor: usize,
}

impl EndpointPlan {
    /// Build a plan from an ordered, NON-empty endpoint list. Returns `Err` for an
    /// empty list (a lane must always have at least one endpoint to target).
    pub fn new(endpoints: Vec<Endpoint>) -> Result<Self, String> {
        if endpoints.is_empty() {
            return Err("an EndpointPlan needs at least one endpoint".into());
        }
        Ok(Self { endpoints, cursor: 0 })
    }

    /// A single-endpoint plan (the trivial / no-failover case).
    pub fn single(endpoint: Endpoint) -> Self {
        Self {
            endpoints: vec![endpoint],
            cursor: 0,
        }
    }

    /// The default endpoint plan for `lane`, applying the
    /// `ALICE_MINER_ENDPOINTS_JSON` operator override if present (else the
    /// compiled relay-only default). The ONE call the engine uses.
    pub fn for_lane(lane: Lane) -> Self {
        Self::from_env_for(lane, std::env::var(ENDPOINTS_ENV).ok().as_deref())
    }

    /// The compiled DEFAULT plan for `lane` — **relay only**, plaintext. This is
    /// the set shipped in the public client. It contains ONLY
    /// `hk.aliceprotocol.org` on the lane's client-facing port (3333 XMR /
    /// 8888 RVN) and NEVER the core IP / collection address / upstream pool
    /// (asserted by [`tests::default_plan_is_relay_only_no_core_ip`]).
    pub fn default_for_lane(lane: Lane) -> Self {
        let (host, port) = match lane {
            Lane::Xmr => (xmr::ALICE_POOL_HOST, xmr::ALICE_POOL_PORT),
            Lane::GpuRvn => (gpu_rvn::ALICE_POOL_HOST, gpu_rvn::ALICE_POOL_PORT),
        };
        Self::single(Endpoint::plaintext(host, port))
    }

    /// Resolve a plan for `lane` from an optional operator override JSON string
    /// (the `ALICE_MINER_ENDPOINTS_JSON` value). When `override_json` is present
    /// and parses to a non-empty endpoint array, it REPLACES the default (so an
    /// operator can point at the core directly or add TLS fallbacks); otherwise
    /// the compiled relay-only [`Self::default_for_lane`] is used.
    ///
    /// The JSON shape is an array of objects, e.g.
    /// `[{"host":"hk.aliceprotocol.org","port":3333},
    ///   {"host":"203.0.113.10","port":4444,"transport":"plaintext"}]`.
    /// A malformed / empty override fails OPEN to the safe relay-only default
    /// (never a crash, never an empty plan).
    pub fn from_env_for(lane: Lane, override_json: Option<&str>) -> Self {
        if let Some(raw) = override_json {
            let raw = raw.trim();
            if !raw.is_empty() {
                match serde_json::from_str::<Vec<Endpoint>>(raw) {
                    Ok(eps) if !eps.is_empty() => {
                        // Operator override accepted (may legitimately include the
                        // core IP — that is exactly why this is operator-only).
                        return Self {
                            endpoints: eps,
                            cursor: 0,
                        };
                    }
                    _ => {
                        // Malformed or empty → fall through to the safe default.
                    }
                }
            }
        }
        Self::default_for_lane(lane)
    }

    /// The endpoint currently targeted (the cursor position). Never panics —
    /// the cursor is always in range (constructors keep the list non-empty and
    /// [`Self::advance`] wraps).
    pub fn current(&self) -> &Endpoint {
        &self.endpoints[self.cursor.min(self.endpoints.len() - 1)]
    }

    /// The cursor index (which endpoint is active).
    pub fn cursor(&self) -> usize {
        self.cursor
    }

    /// How many endpoints the plan holds.
    pub fn len(&self) -> usize {
        self.endpoints.len()
    }

    pub fn is_empty(&self) -> bool {
        self.endpoints.is_empty()
    }

    /// Whether a failover is even possible (more than one endpoint). A
    /// single-endpoint plan can't rotate — Layer B leaves it to Layer A / the
    /// miner's own reconnect, and the watchdog simply restarts in place.
    pub fn can_failover(&self) -> bool {
        self.endpoints.len() > 1
    }

    /// The ordered endpoints (primary first), for Layer-A arg building.
    pub fn endpoints(&self) -> &[Endpoint] {
        &self.endpoints
    }

    /// The endpoints in **failover order starting from the current cursor** — the
    /// list the miner should receive so its OWN fast failover (Layer A) tries the
    /// active endpoint first, then the rest in order, wrapping. For a
    /// single-endpoint plan this is just that endpoint.
    pub fn ordered_from_cursor(&self) -> Vec<Endpoint> {
        let n = self.endpoints.len();
        (0..n)
            .map(|i| self.endpoints[(self.cursor + i) % n].clone())
            .collect()
    }

    /// Advance the failover cursor to the next endpoint (wraps to 0 after the
    /// last). Returns the now-current endpoint. Used by Layer B when the
    /// no-progress watchdog fires.
    pub fn advance(&mut self) -> &Endpoint {
        if !self.endpoints.is_empty() {
            self.cursor = (self.cursor + 1) % self.endpoints.len();
        }
        self.current()
    }

    /// Reset the cursor to the primary endpoint (e.g. on a fresh user-initiated
    /// Start).
    pub fn reset(&mut self) {
        self.cursor = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE ENDPOINT-HONESTY GATE (PLAN §4 brief, §6 D-Q5): the compiled DEFAULT
    /// plan for EVERY lane must contain the relay host and must NOT contain the
    /// Finland core IP, OUR collection address, or any upstream-pool host. The
    /// core IP is operator-only (env), never baked in.
    #[test]
    fn default_plan_is_relay_only_no_core_ip() {
        for lane in [Lane::Xmr, Lane::GpuRvn] {
            let plan = EndpointPlan::default_for_lane(lane);
            // Exactly one endpoint, and it is the public relay.
            assert_eq!(plan.len(), 1, "default plan must be relay-only (one endpoint)");
            assert_eq!(plan.current().host, "hk.aliceprotocol.org");
            assert_eq!(plan.current().transport, Transport::Plaintext);

            // Serialize the WHOLE plan and scan for forbidden strings.
            let json = serde_json::to_string(&plan).expect("serialize plan");
            // (a) The Finland core IP must NEVER appear in the compiled default.
            assert!(
                !json.contains("203.0.113.10"),
                "the core IP must never be baked into the client default: {json}"
            );
            // (b) OUR collection wallet (XMR Monero-mainnet prefix / RVN 'R…') must
            //     not appear.
            assert!(
                !json.contains("46knTVDfa5CMtFLvVuFdHWPSv7FCnfSbQ"),
                "an XMR collection address leaked into the default plan: {json}"
            );
            // (c) No upstream pool host marker.
            assert!(
                !json.contains("pool.") && !json.contains(".pool"),
                "an upstream pool host leaked into the default plan: {json}"
            );
            // (d) The relay IS present (the one allowed host).
            assert!(json.contains("hk.aliceprotocol.org"));
        }
    }

    /// `for_lane` with NO override env yields the relay-only default (the public
    /// client's behaviour) — even if some stale value is around, an EMPTY/absent
    /// override resolves to the default.
    #[test]
    fn no_override_resolves_to_relay_only_default() {
        for lane in [Lane::Xmr, Lane::GpuRvn] {
            let plan = EndpointPlan::from_env_for(lane, None);
            assert_eq!(plan.len(), 1);
            assert_eq!(plan.current().host, "hk.aliceprotocol.org");
            // Empty string also falls open to the default.
            let plan2 = EndpointPlan::from_env_for(lane, Some("   "));
            assert_eq!(plan2.current().host, "hk.aliceprotocol.org");
        }
    }

    /// The OPERATOR override (env) REPLACES the default and MAY carry the core IP
    /// — that's the whole point of keeping it operator-only. A multi-endpoint
    /// override is parsed in order and is failover-capable.
    #[test]
    fn operator_override_replaces_default_and_may_carry_core() {
        let json = r#"[
            {"host":"hk.aliceprotocol.org","port":3333},
            {"host":"203.0.113.10","port":4444,"transport":"plaintext"}
        ]"#;
        let plan = EndpointPlan::from_env_for(Lane::Xmr, Some(json));
        assert_eq!(plan.len(), 2);
        assert!(plan.can_failover());
        assert_eq!(plan.current().host, "hk.aliceprotocol.org");
        assert_eq!(plan.current().port, 3333);
        // Advancing reaches the operator's core override.
        let next = plan_advance_clone(&plan);
        assert_eq!(next.host, "203.0.113.10");
        assert_eq!(next.port, 4444);
    }

    /// A malformed / empty override fails OPEN to the safe relay-only default
    /// (never a crash, never an empty plan).
    #[test]
    fn malformed_override_fails_open_to_default() {
        for bad in ["not json", "[]", "{}", "[{\"host\":\"x\"}]" /* missing port */] {
            let plan = EndpointPlan::from_env_for(Lane::Xmr, Some(bad));
            assert_eq!(
                plan.current().host,
                "hk.aliceprotocol.org",
                "bad override {bad:?} must fall open to the relay default"
            );
        }
    }

    #[test]
    fn cursor_advances_and_wraps() {
        let mut plan = EndpointPlan::new(vec![
            Endpoint::plaintext("a.example", 1),
            Endpoint::plaintext("b.example", 2),
            Endpoint::plaintext("c.example", 3),
        ])
        .unwrap();
        assert_eq!(plan.cursor(), 0);
        assert_eq!(plan.current().host, "a.example");
        assert_eq!(plan.advance().host, "b.example");
        assert_eq!(plan.cursor(), 1);
        assert_eq!(plan.advance().host, "c.example");
        assert_eq!(plan.advance().host, "a.example"); // wraps
        assert_eq!(plan.cursor(), 0);
        plan.reset();
        assert_eq!(plan.cursor(), 0);
    }

    #[test]
    fn ordered_from_cursor_rotates_the_list() {
        let mut plan = EndpointPlan::new(vec![
            Endpoint::plaintext("a.example", 1),
            Endpoint::plaintext("b.example", 2),
            Endpoint::plaintext("c.example", 3),
        ])
        .unwrap();
        // At cursor 0: a, b, c.
        let order: Vec<String> = plan.ordered_from_cursor().iter().map(|e| e.host.clone()).collect();
        assert_eq!(order, ["a.example", "b.example", "c.example"]);
        // After one advance (cursor 1): b, c, a.
        plan.advance();
        let order: Vec<String> = plan.ordered_from_cursor().iter().map(|e| e.host.clone()).collect();
        assert_eq!(order, ["b.example", "c.example", "a.example"]);
    }

    #[test]
    fn transport_schemes_and_urls() {
        assert_eq!(Transport::Plaintext.stratum_scheme(), "stratum+tcp");
        assert_eq!(Transport::Tls.stratum_scheme(), "stratum+ssl");
        let p = Endpoint::plaintext("hk.aliceprotocol.org", 8888);
        assert_eq!(p.stratum_url(), "stratum+tcp://hk.aliceprotocol.org:8888");
        assert_eq!(p.host_port(), "hk.aliceprotocol.org:8888");
        let t = Endpoint::tls("hk.aliceprotocol.org", 8889);
        assert_eq!(t.stratum_url(), "stratum+ssl://hk.aliceprotocol.org:8889");
    }

    #[test]
    fn single_endpoint_plan_cannot_failover() {
        let plan = EndpointPlan::single(Endpoint::plaintext("hk.aliceprotocol.org", 3333));
        assert!(!plan.can_failover());
        assert_eq!(plan.ordered_from_cursor().len(), 1);
    }

    #[test]
    fn empty_plan_is_rejected() {
        assert!(EndpointPlan::new(vec![]).is_err());
    }

    /// A transport defaulting helper: JSON without a `transport` key parses as
    /// plaintext (so operators can write the minimal `{host,port}` form).
    #[test]
    fn endpoint_json_defaults_transport_to_plaintext() {
        let e: Endpoint = serde_json::from_str(r#"{"host":"h","port":3333}"#).unwrap();
        assert_eq!(e.transport, Transport::Plaintext);
        let e2: Endpoint = serde_json::from_str(r#"{"host":"h","port":3333,"transport":"tls"}"#).unwrap();
        assert_eq!(e2.transport, Transport::Tls);
    }

    // Test helper: advance a *clone* so the assertion reads naturally without
    // mutating the plan under test in the prior assertions.
    fn plan_advance_clone(plan: &EndpointPlan) -> Endpoint {
        let mut p = plan.clone();
        p.advance().clone()
    }
}
