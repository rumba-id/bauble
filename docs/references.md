# LDAP RFC References

A broad reference tree of LDAP-related RFCs from the IETF RFC Editor, organized by
dependency. This is reference material, not the conformance scope: only the RFCs
listed under Scope in the README are tested by bauble. Run `bauble coverage` for the
current per-RFC requirement coverage.

## Core Protocol Stack

These RFCs form the foundation of LDAPv3 and must be implemented for basic conformance.

### RFC 4510 — LDAP: Technical Specification Road Map

Umbrella document describing the LDAP protocol suite structure.

### RFC 4511 — LDAP: The Protocol

Core protocol specification. Defines BIND, SEARCH, COMPARE, ADD, DELETE, MODIFY, MODIFY DN, and
extended operations.

### RFC 4512 — LDAP: Directory Information Models

Defines the directory information model (DIM), object classes, attribute types, and the X.500
information model adapted for LDAP.

### RFC 4513 — LDAP: Authentication Methods and Security Mechanisms

Defines authentication methods (SIMPLE, SASL mechanisms) and security mechanisms (TLS, SASL).

### RFC 4514 — LDAP: String Representation of Distinguished Names

Defines the UTF-8 string representation of DNs (replaces RFC 2253).

### RFC 4515 — LDAP: String Representation of Search Filters

Defines the string representation of search filters (replaces RFC 2254).

### RFC 4516 — LDAP: Uniform Resource Locator

Defines the LDAP URL format (replaces RFC 2255).

### RFC 4517 — LDAP: Syntaxes and Matching Rules

Defines syntaxes and matching rules (replaces RFC 2252).

### RFC 4518 — LDAP: Internationalized String Preparation

Defines string preparation for internationalized names (IDNA, SASL).

### RFC 4519 — LDAP: Schema for User Applications

Defines the inetOrgPerson and related object classes for user applications.

### RFC 4520 — BCP 64: IANA Considerations for LDAP

IANA registration procedures for LDAP-related parameters.

### RFC 4521 — BCP 118: Considerations for LDAP Extensions

Guidelines for defining new LDAP extensions.

## Transport and Security

### RFC 2830 — LDAPv3: Extension for Transport Layer Security

TLS binding for LDAP (LDAPS on port 636).

### RFC 3045 — Storing Vendor Information in the LDAP root DSE

Defines the vendor-specific operational attributes in the Root DSE.

### RFC 3062 — LDAP Password Modify Extended Operation

Extended operation for changing passwords.

### RFC 4532 — LDAP "Who am I?" Operation

Extended operation to determine the identity of the bound user.

## Directory Operations and Controls

### RFC 2696 — LDAP Control Extension for Simple Paged Results Manipulation

Paged results control for retrieving large result sets.

### RFC 2891 — LDAP Control Extension for Server Side Sorting of Search Results

Server-side sorting control.

### RFC 3088 — OpenLDAP Root Service (experimental LDAP referral service)

Experimental referral service.

### RFC 3296 — Named Subordinate References in LDAP Directories

Referral handling for subordinate references.

### RFC 3674 — Feature Discovery in LDAP

Root DSE feature discovery controls.

### RFC 3771 — The LDAP Intermediate Response Message

Intermediate response handling.

### RFC 3829 — LDAP Authorization Identity Request and Response Controls

Authorization identity controls.

### RFC 3876 — Returning Matched Values with LDAPv3

Matched values return control.

### RFC 3909 — LDAP Cancel Operation

Operation cancellation.

### RFC 4370 — LDAP Proxied Authorization Control

Proxied authorization control.

### RFC 4373 — LDAP Bulk Update/Replication Protocol (LBURP)

Bulk update protocol.

### RFC 4522 — LDAP: The Binary Encoding Option

Binary encoding option for LDAP messages.

### RFC 4525 — LDAP Modify-Increment Extension

Modify-increment extended operation.

### RFC 4526 — LDAP Absolute True and False Filters

Absolute true/false filter control.

### RFC 4527 — LDAP Read Entry Controls

Read entry controls.

### RFC 4528 — LDAP Assertion Control

Assertion control.

### RFC 4529 — Requesting Attributes by Object Class in LDAP

Object class attribute request control.

### RFC 4530 — LDAP entryUUID Operational Attribute

entryUUID operational attribute.

### RFC 4531 — LDAP Turn Operation

Turn operation.

### RFC 4533 — LDAP Content Synchronization Operation

Content synchronization operation.

### RFC 4876 — A Configuration Profile Schema for LDAP-Based Agents

Configuration profile schema.

### RFC 6171 — LDAP Don't Use Copy Control

"Don't use copy" control.

## Schema and Data Models

### RFC 2252 — LDAP: Attribute Syntax Definitions

Attribute syntax definitions (replaced by RFC 4517).

### RFC 2253 — LDAP: UTF-8 String Representation of Distinguished Names

DN string representation (replaced by RFC 4514).

### RFC 2254 — The String Representation of LDAP Search Filters

Filter string representation (replaced by RFC 4515).

### RFC 2255 — The LDAP URL Format

LDAP URL format (replaced by RFC 4516).

### RFC 2256 — A Summary of the X.500(96) User Schema for use with LDAPv3

X.500 user schema summary.

### RFC 2307 — An Approach for Using LDAP as a Network Information Service

NIS mapping for LDAP.

### RFC 2559 — Internet X.509 PKI Operational Protocols - LDAPv2

X.509 PKI operational protocols over LDAPv2.

### RFC 2587 — Internet X.509 PKI LDAPv2 Schema

X.509 PKI schema for LDAP.

### RFC 2589 — LDAPv3: Extensions for Dynamic Directory Services

Dynamic directory service extensions.

### RFC 2596 — Use of Language Codes in LDAP

Language tag support.

### RFC 2649 — An LDAP Control and Schema for Holding Operation Signatures

Operation signature control.

### RFC 2657 — LDAPv2 Client vs. the Index Mesh

LDAPv2 client/index mesh relationship.

### RFC 2713 — Schema for Representing Java Objects in an LDAP Directory

Java object schema.

### RFC 2714 — Schema for Representing CORBA Object References in an LDAP Directory

CORBA object reference schema.

### RFC 2739 — Calendar Attributes for vCard and LDAP

Calendar attributes.

### RFC 2798 — Definition of the inetOrgPerson LDAP Object Class

inetOrgPerson object class.

### RFC 3045 — Storing Vendor Information in the LDAP root DSE

Root DSE vendor information.

### RFC 3112 — LDAP Authentication Password Schema

Password schema.

### RFC 3254 — Definitions for talking about directories

Directory terminology.

### RFC 3377 — LDAPv3: Technical Specification

LDAPv3 technical specification.

### RFC 3383 — IANA Considerations for LDAP

IANA considerations.

### RFC 3384 — LDAPv3 Replication Requirements

Replication requirements.

### RFC 3494 — LDAPv2 to Historic Status

LDAPv2 historic status.

### RFC 3642 — Common Elements of GSER Encodings

Generic String Encoding Rules.

### RFC 3650 — Handle System Overview

Handle System (not LDAP-specific, but related).

### RFC 3663 — Domain Administrative Data in LDAP

Domain administrative data.

### RFC 3671 — Collective Attributes in LDAP

Collective attributes.

### RFC 3672 — Subentries in LDAP

Subentries.

### RFC 3673 — LDAPv3: All Operational Attributes

Operational attributes.

### RFC 3687 — LDAP and X.500 Component Matching Rules

Component matching rules.

### RFC 3698 — LDAP: Additional Matching Rules

Additional matching rules.

### RFC 3703 — Policy Core LDAP Schema

Policy core schema.

### RFC 3712 — LDAP: Schema for Printer Services

Printer services schema.

### RFC 3727 — ASN.1 Module Definition for the LDAP and X.500 Component Matching Rules

ASN.1 module definitions.

### RFC 4104 — Policy Core Extension LDAP Schema (PCELS)

Policy core extension schema.

### RFC 4403 — LDAP Schema for UDDIv3

UDDIv3 schema.

### RFC 5020 — LDAP entryDN Operational Attribute

entryDN operational attribute.

### RFC 5803 — LDAP Schema for SCRAM Secrets

SCRAM secrets schema.

### RFC 5805 — LDAP Transactions

Transaction support.

### RFC 6134 — Sieve Extension: Externally Stored Lists

Sieve extension (not LDAP-specific).

### RFC 6880 — An Information Model for Kerberos Version 5

Kerberos information model (not LDAP-specific).

### RFC 7612 — LDAP: Schema for Printer Services

Printer services schema (updated).

### RFC 8284 — LDAP Schema for Supporting XMPP in White Pages

XMPP white pages schema.

## Legacy / Historic

### RFC 1488 — The X.500 String Representation of Standard Attribute Syntaxes

Legacy attribute syntax representation.

### RFC 1558 — A String Representation of LDAP Search Filters

Legacy filter representation.

### RFC 1778 — The String Representation of Standard Attribute Syntaxes

Legacy syntax representation.

### RFC 1823 — The LDAP Application Program Interface

Legacy LDAP API specification.

### RFC 1959 — An LDAP URL Format

Legacy LDAP URL format.

### RFC 1960 — A String Representation of LDAP Search Filters

Legacy filter representation.

### RFC 2164 — Use of an X.500/LDAP directory to support MIXER address mapping

MIXER address mapping.

### RFC 2247 — Using Domains in LDAP/X.500 Distinguished Names

Domain handling in DNs.

### RFC 2696 — LDAP Control Extension for Simple Paged Results Manipulation

Paged results.

### RFC 2820 — Access Control Requirements for LDAP

Access control requirements.

### RFC 2829 — Authentication Methods for LDAP

Authentication methods.

### RFC 2849 — The LDAP Data Interchange Format (LDIF) - Technical Specification

LDIF specification.

### RFC 2926 — Conversion of LDAP Schemas to and from SLP Templates

LDAP/SLP schema conversion.

### RFC 2927 — MIME Directory Profile for LDAP Schema

MIME directory profile.

### RFC 2985 — PKCS #9: Selected Object Classes and Attribute Types Version 2.0

PKCS #9 object classes.

### RFC 3944 — H.350 Directory Services

H.350 directory services.

## Dependencies

```text
RFC 4510 (umbrella)
├── RFC 4511 (protocol)
│   ├── RFC 2830 (TLS)
│   ├── RFC 3062 (password modify)
│   ├── RFC 2696 (paged results)
│   ├── RFC 2891 (sorting)
│   ├── RFC 3771 (intermediate response)
│   ├── RFC 3829 (authorization identity)
│   ├── RFC 3876 (matched values)
│   ├── RFC 3909 (cancel)
│   ├── RFC 4370 (proxied authorization)
│   ├── RFC 4522 (binary encoding)
│   ├── RFC 4525 (modify-increment)
│   ├── RFC 4526 (absolute filters)
│   ├── RFC 4527 (read entry)
│   ├── RFC 4528 (assertion)
│   ├── RFC 4529 (object class attributes)
│   ├── RFC 4530 (entryUUID)
│   ├── RFC 4531 (turn)
│   ├── RFC 4532 (who am I)
│   └── RFC 4533 (sync)
├── RFC 4512 (directory model)
│   ├── RFC 4519 (user schema)
│   ├── RFC 2256 (X.500 user schema)
│   ├── RFC 2307 (NIS mapping)
│   ├── RFC 2559 (X.509 PKI)
│   ├── RFC 2587 (X.509 PKI schema)
│   ├── RFC 2589 (dynamic services)
│   ├── RFC 2713 (Java objects)
│   ├── RFC 2714 (CORBA objects)
│   ├── RFC 2739 (calendar)
│   ├── RFC 2798 (inetOrgPerson)
│   ├── RFC 3112 (password schema)
│   ├── RFC 3384 (replication)
│   ├── RFC 3663 (domain admin)
│   ├── RFC 3671 (collective attributes)
│   ├── RFC 3672 (subentries)
│   ├── RFC 3673 (operational attributes)
│   ├── RFC 3687 (matching rules)
│   ├── RFC 3698 (additional matching rules)
│   ├── RFC 3703 (policy core)
│   ├── RFC 3712 (printer schema)
│   ├── RFC 3727 (ASN.1 modules)
│   ├── RFC 4104 (policy core extension)
│   ├── RFC 4403 (UDDIv3)
│   ├── RFC 5020 (entryDN)
│   ├── RFC 5803 (SCRAM)
│   ├── RFC 7612 (printer schema)
│   └── RFC 8284 (XMPP)
├── RFC 4513 (authentication)
│   ├── RFC 2829 (auth methods)
│   ├── RFC 3045 (vendor info)
│   └── RFC 4532 (who am I)
├── RFC 4514 (DN representation)
│   └── RFC 2253 (legacy DN)
├── RFC 4515 (filter representation)
│   └── RFC 2254 (legacy filter)
├── RFC 4516 (URL format)
│   └── RFC 2255 (legacy URL)
├── RFC 4517 (syntaxes and matching rules)
│   └── RFC 2252 (legacy syntax)
├── RFC 4518 (string preparation)
├── RFC 4520 (IANA considerations)
├── RFC 4521 (extension considerations)
└── RFC 3383 (IANA considerations)
```

## Notes

- RFCs marked as "replaced by" are historic and superseded by their modern equivalents.
- The core protocol stack (RFC 4510–4519) represents the minimum set for LDAPv3 conformance.
- Extended operations and controls are optional but recommended for Standard Profile conformance.
- Schema RFCs define object classes and attribute types that may be required by specific profiles.
