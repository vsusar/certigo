# Custom X.509 Extension Display

## Overview

Added support for reading and displaying custom or non-standard extensions from X.509 certificates. Previously, certigo only surfaced a fixed set of well-known extensions (Key Usage, SANs, Basic Constraints, etc.). Any extension not explicitly handled was silently dropped. Now, all remaining extensions are collected and shown in both verbose text output and JSON output.

## Changed Files

### `lib/oids.go`

Added `describeExtensionOid(oid asn1.ObjectIdentifier) string`.

Returns a human-readable name for ~30 well-known extension OIDs (e.g. `2.5.29.32` → `"Certificate Policies"`). Returns an empty string for unrecognized OIDs so the raw dotted OID is shown as-is.

---

### `lib/encoder.go`

Three additions:

**`simpleExtension` struct** — represents one raw extension for serialization:

| Field | Type | Description |
|---|---|---|
| `oid` | `string` | Dotted-decimal OID string |
| `name` | `string` | Human-readable name (omitted if unknown) |
| `critical` | `bool` | Whether the extension is marked critical (omitted if false) |
| `value` | `string` | Extension value as a decoded string or hex fallback |

**`knownExtensionOIDs` map** — the set of OIDs already surfaced through dedicated `simpleCertificate` fields (Key Usage, SANs, Basic Constraints, Name Constraints, Authority/Subject Key ID, Extended Key Usage, Authority Info Access, CT SCT List). Extensions matching these OIDs are skipped to avoid duplication.

**`formatExtensionValue(data []byte) string`** — attempts to decode the raw DER value as an ASN.1 string type (UTF8String, IA5String, PrintableString, etc.). Falls back to a lowercase hex string if decoding fails.

**`simpleCertificate` struct** — added `Extensions []simpleExtension` field (JSON key `"extensions"`).

**`createSimpleCertificate`** — after populating all existing fields, iterates over `cert.Extensions`, skips known OIDs, and appends the rest to `out.Extensions`.

---

### `lib/display.go`

Added a `Custom Extensions:` block to the verbose text template, rendered only when extensions are present:

```
Custom Extensions:
    1.2.3.4.5 (Some Extension Name) [critical]:
        <decoded value or hex>
```

The `[critical]` marker is only shown for extensions flagged as critical.

---

## Example Output

**Verbose text (`certigo dump --verbose`):**

```
Custom Extensions:
    2.5.29.32 (Certificate Policies):
        300a3008060667810c010201
    2.5.29.31 (CRL Distribution Points):
        302d302ba029a027...
```

**JSON (`certigo dump --json`):**

```json
"extensions": [
  {
    "oid": "2.5.29.32",
    "name": "Certificate Policies",
    "value": "300a3008060667810c010201"
  },
  {
    "oid": "2.5.29.31",
    "name": "CRL Distribution Points",
    "value": "302d302ba029a027..."
  }
]
```

## Notes

- Extensions already rendered via dedicated fields are excluded from the `extensions` list.
- Values that decode cleanly as ASN.1 string types are shown as plain text; all others are shown as hex.
- Custom extensions appear in verbose mode only for text output. The JSON output always includes them regardless of verbosity.
