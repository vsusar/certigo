// Copyright 2025 Block, Inc.
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lib

import "encoding/asn1"

// OidDescription returns a human-readable name, a short acronym from RFC1485, a snake_case slug suitable as a json key,
// and a boolean describing whether multiple copies can appear on an X509 cert.
type OidDescription struct {
	Name     string
	Short    string
	Slug     string
	Multiple bool
}

func describeOid(oid asn1.ObjectIdentifier) OidDescription {
	raw := oid.String()
	// Multiple should be true for any types that are []string in x509.pkix.Name. When in doubt, set it to true.
	names := map[string]OidDescription{
		"2.5.4.3":                    {"CommonName", "CN", "common_name", false},
		"2.5.4.5":                    {"EV Incorporation Registration Number", "", "ev_registration_number", false},
		"2.5.4.6":                    {"Country", "C", "country", true},
		"2.5.4.7":                    {"Locality", "L", "locality", true},
		"2.5.4.8":                    {"Province", "ST", "province", true},
		"2.5.4.9":                    {"Street", "", "street", true},
		"2.5.4.10":                   {"Organization", "O", "organization", true},
		"2.5.4.11":                   {"Organizational Unit", "OU", "organizational_unit", true},
		"2.5.4.15":                   {"Business Category", "", "business_category", true},
		"2.5.4.17":                   {"Postal Code", "", "postalcode", true},
		"1.2.840.113549.1.9.1":       {"Email Address", "", "email_address", true},
		"1.3.6.1.4.1.311.60.2.1.1":   {"EV Incorporation Locality", "", "ev_locality", true},
		"1.3.6.1.4.1.311.60.2.1.2":   {"EV Incorporation Province", "", "ev_province", true},
		"1.3.6.1.4.1.311.60.2.1.3":   {"EV Incorporation Country", "", "ev_country", true},
		"0.9.2342.19200300.100.1.1":  {"User ID", "UID", "user_id", true},
		"0.9.2342.19200300.100.1.25": {"Domain Component", "DC", "domain_component", true},
	}
	if description, ok := names[raw]; ok {
		return description
	}
	return OidDescription{raw, "", raw, true}
}

func oidShort(oid asn1.ObjectIdentifier) string {
	return describeOid(oid).Short
}

func oidName(oid asn1.ObjectIdentifier) string {
	return describeOid(oid).Name
}

// describeExtensionOid returns a human-readable name for well-known X.509 extension OIDs,
// or an empty string if the OID is not recognized.
func describeExtensionOid(oid asn1.ObjectIdentifier) string {
	names := map[string]string{
		"2.5.29.9":                  "Subject Directory Attributes",
		"2.5.29.14":                 "Subject Key Identifier",
		"2.5.29.15":                 "Key Usage",
		"2.5.29.16":                 "Private Key Usage Period",
		"2.5.29.17":                 "Subject Alternative Name",
		"2.5.29.18":                 "Issuer Alternative Name",
		"2.5.29.19":                 "Basic Constraints",
		"2.5.29.20":                 "CRL Number",
		"2.5.29.21":                 "Reason Code",
		"2.5.29.23":                 "Hold Instruction Code",
		"2.5.29.24":                 "Invalidity Date",
		"2.5.29.27":                 "Delta CRL Indicator",
		"2.5.29.28":                 "Issuing Distribution Point",
		"2.5.29.29":                 "Certificate Issuer",
		"2.5.29.30":                 "Name Constraints",
		"2.5.29.31":                 "CRL Distribution Points",
		"2.5.29.32":                 "Certificate Policies",
		"2.5.29.33":                 "Policy Mappings",
		"2.5.29.35":                 "Authority Key Identifier",
		"2.5.29.36":                 "Policy Constraints",
		"2.5.29.37":                 "Extended Key Usage",
		"2.5.29.46":                 "Freshest CRL",
		"2.5.29.54":                 "Inhibit Any Policy",
		"1.3.6.1.5.5.7.1.1":        "Authority Information Access",
		"1.3.6.1.5.5.7.1.3":        "QC Statements",
		"1.3.6.1.5.5.7.1.11":       "Subject Information Access",
		"1.3.6.1.4.1.11129.2.4.2":  "Certificate Transparency SCT List",
	}
	return names[oid.String()]
}
