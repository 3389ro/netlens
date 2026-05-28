#ifndef NETLENS_SECURITY_ADVISOR_H
#define NETLENS_SECURITY_ADVISOR_H

// v1.3.2 — Heuristic security findings.
//
// Walks a fully-fingerprinted ScanResult and emits a small set of
// "indicative" security findings: end-of-life lifecycle hits and a
// curated list of high-impact CVEs (RCE + credential-takeover only,
// no DoS / information-disclosure / configuration-tweak CVEs).
//
// The matcher reads ONLY what's already on ScanResult (vendor,
// deviceType, port list, fingerprint product+version). It never
// touches the network — no follow-up probe. False positives are
// possible (a banner-string match doesn't prove the host hasn't been
// patched in place; an unmodified Apache 2.4.49 banner can come from
// a backport that fixes the CVE) — the UI surfaces this caveat as a
// disclaimer banner alongside the findings list.
//
// Output is written to `host.securityFindings` as a multi-line TAB-
// separated string:
//     "<severity>\t<id>\t<title>\t<url>\n..."
// Rows are pre-ordered by severity (critical → high → medium → low)
// so the consumer can render top-down with no extra sorting.

#include "../Models.h"

namespace lanscope {

class SecurityAdvisor {
public:
    /// Analyse a fully-probed host and populate `host.securityFindings`.
    /// Idempotent; safe to call multiple times on the same host (each
    /// call replaces the prior result). No-op for offline hosts.
    static void analyze(ScanResult& host);
};

}  // namespace lanscope

#endif // NETLENS_SECURITY_ADVISOR_H
