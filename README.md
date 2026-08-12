# bauble

An open-source, implementation-independent LDAP RFC conformance test suite.

## Overview

Bauble is a Python-based test suite that verifies LDAP server compliance with the core LDAPv3 RFCs. It is modeled on the principles of the VSLDAP test suite from The Open Group, but is fully open-source and server-independent.

## Author

Daniel S. Reichenbach
## Scope

The suite targets the following RFCs:

- **RFC 4510** — LDAP: The Protocol Specification (umbrella)
- **RFC 4511** — LDAP: The Protocol
- **RFC 4512** — LDAP: Attribute Syntax Definitions
- **RFC 4514** — LDAP: UTF-8 String Representation of Distinguished Names
- **RFC 4515** — LDAP: String Representation of LDAP Search Filters
- **RFC 4516** — LDAP: The LDAP URL Format

## Profiles

The test suite is organized into two profiles, mirroring the LDAP Certified Product Standard:

### Base Profile

Covers the essential, mandatory LDAP features:

- Simple bind
- Search, add, delete, modify, modify DN operations
- Operation over TCP and SSL/TLS
- Core protocol operations from RFC 4511

### Standard Profile

Builds upon the Base Profile and tests advanced features:

- Root DSE
- Alias dereferencing
- Operational attributes
- Controls and extended operations
- Referrals and continuation references
- Common object classes and attribute types

## Usage

```bash
# Install dependencies
uv sync

# Run all tests against a target server
uv run pytest --server ldap://localhost:389

# Run only Base profile tests
uv run pytest --profile base

# Run only Standard profile tests
uv run pytest --profile standard
```

## Architecture

```
src/bauble/
  ├── __init__.py
  ├── client.py          # LDAP connection management
  ├── assertions.py      # RFC-based test assertions
  ├── base_profile.py    # Base profile test cases
  ├── standard_profile.py # Standard profile test cases
  └── runner.py          # Test harness and CLI

tests/
  ├── conftest.py
  ├── test_base_profile.py
  └── test_standard_profile.py
```

## Reference Materials

This project is based on:

- **VSLDAP Test Assertions** — The Open Group's public test assertion documentation
- **RFC 4510–4519** — The LDAPv3 protocol suite
- **ldap3** — Python LDAP client library (LGPL v3)
- **sldap3** — Python LDAP server library (LGPL v3)

## License

MIT License — see [LICENSE](LICENSE) for details.
