# Threat model

## Scope and assets

TraceGuard runs as a single-user offline command-line program. Its assets are imported telemetry, investigation notes, case decisions, and generated reports. Input logs are untrusted; the local operating system, Python interpreter, source tree, and browser are trusted dependencies.

## Trust boundaries and controls

| Boundary | Risk | Current control | Residual limitation |
| --- | --- | --- | --- |
| JSONL to parser | Malformed input or resource exhaustion | File/row limits, schema validation, bounded names | Limits do not guarantee protection on constrained hosts |
| Parser to SQLite | Injection or inconsistent imports | Parameterized SQL, validation before insertion, transactions | Host users with file access can alter the database |
| Data to HTML | Script injection via log fields or notes | JSON delimiter escaping, HTML escaping, CSP | No independent penetration test; browser is trusted |
| Files to recipients | Disclosure of telemetry or notes | Offline operation, generated files excluded from Git | Reports contain data; sharing is the operator's responsibility |
| Events to alerts | Misleading or incomplete detection | Explicit thresholds, evidence IDs, documented hypotheses | Evasion, missing events, NAT, timing ambiguity, and false positives remain |

## Operational assumptions

- Logs come from authorized sources with sufficiently synchronized clocks.
- Operators check the schema conversion and timestamp meaning.
- One operator writes a workspace at a time.
- The machine provides filesystem permissions, backups, and disk encryption.
- File hashes provide stable identifiers, not authenticity or tamper evidence.

## Out of scope

Endpoint protection, malware execution, network capture, exploitation, credential testing, automated containment, production SIEM scale, tenant isolation, and forensic chain of custody are outside this prototype's scope. Do not treat an alert as proof of an intrusion or an absence of alerts as proof of safety.
