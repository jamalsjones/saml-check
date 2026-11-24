# SAML check

[![Tests](https://github.com/jamalsjones/saml-check/actions/workflows/test.yml/badge.svg)](https://github.com/jamalsjones/saml-check/actions/workflows/test.yml)

Paste a SAML response, assertion, AuthnRequest or metadata and see why a sign-in failed or what an identity provider is getting wrong. Every finding cites the section of the SAML 2.0 specifications (Core, Profiles, Bindings, Metadata, Security Considerations) or the RFC it comes from.

**Use it in the browser:** [jamalsjones.github.io/saml-check](https://jamalsjones.github.io/saml-check/). It's checked in the page; nothing is uploaded.

It takes whatever you have: raw XML, the base64 `SAMLResponse` your browser posted (HTTP-POST binding), a deflated `SAMLRequest` from a redirect URL (HTTP-Redirect binding), or a whole URL or form body containing one.

## What it checks

| Area | Flags |
|---|---|
| Why sign-in failed | a non-success status (with the IdP's message), expired or not-yet-valid assertions, clock skew, an Audience that isn't your entity ID, a Recipient or Destination that isn't your ACS URL, an unexpected Issuer |
| Signatures | nothing signed, signatures that point at a different element, SHA-1 signatures and digests, XSLT or XPath transforms, a reminder to verify with the metadata certificate rather than one in the message |
| Attacks | signature wrapping (assertions hidden in other elements, duplicate IDs, misplaced signatures), comments inside NameID (the comment-truncation bug), DOCTYPEs and custom entities (XXE), missing Recipient or Destination (replay at another app), long-lived assertions, IdP-initiated responses |
| Encryption | RSA 1.5 key transport and AES-CBC on encrypted assertions |
| Certificates | expired, expiring soon, not yet valid, RSA keys under 2048 bits, SHA-1-signed |
| Metadata | expired `validUntil`, plain-HTTP endpoints, no SAML 2.0 support, no signing key, a single signing key with no rollover, SPs that don't require signed assertions, IdPs that don't require signed requests, ACS on the Redirect binding |

Each finding is an **error** (this breaks or is unsafe), a **warning** (fix it) or a **note** (worth knowing). For messages, the page also lists what's inside: issuer, NameID, audience, validity window, sign-in method, attributes and certificates.

It doesn't verify signatures or decrypt assertions. That needs keys and is your service provider's job, so a message can pass every check here and still be forged. The XML reader is deliberately small and never expands DTDs or entities; it's a linter, not a schema validator.

## In a pipeline

`saml-check.js` is one file with no dependencies, shared by the page and the command line. The most useful scheduled job is a metadata check: it catches a signing certificate before it expires and takes SSO down. It exits 1 on errors.

```bash
node saml-check.js https://login.example.com/saml/metadata --cert-days 45
node saml-check.js response.xml --sp https://app.example.com/saml --acs https://app.example.com/saml/acs
pbpaste | node saml-check.js --json
```

| Option | |
|---|---|
| `--sp entityID` | your service provider's entity ID (checks Audience) |
| `--acs url` | your assertion consumer service URL (checks Destination and Recipient) |
| `--idp entityID` | the identity provider you trust (checks Issuer) |
| `--skew 180` | clock skew in seconds |
| `--max-minutes 60` | warn when an assertion is valid for longer |
| `--cert-days 30` | warn when a certificate expires within this many days |
| `--now time` | check as if it were this time, for a saved message |
| `--fail-on warn` | also fail on warnings |
| `--json` | print the full result |

`examples/` has a clean and a flawed response and three metadata files to compare. The certificates in them are real, generated for these samples; the companies and people are invented.

## A note on what you paste

A SAML response holds a person's identity and attributes, and until it expires it's a credential for that app. The page keeps it in your browser, but don't paste live responses into tools you don't control, and prefer expired ones or test accounts when you share them.

## Make it yours

Fork it and set the defaults at the top of `saml-check.js` to your standards: clock skew, assertion lifetime, certificate warning window. Each check is a few lines; add a test in `test/` and run `npm test` (Node 18 or later, nothing to install). To host your own copy, turn on GitHub Pages for your fork.

## Related

- [JWT lint](https://github.com/jamalsjones/jwt-lint) and [OIDC config check](https://github.com/jamalsjones/oidc-config-check): the same idea for OAuth and OpenID Connect.
- [Leaver check](https://github.com/jamalsjones/leaver-check): find accounts that outlived the people who owned them.

## Author

Jamal Jones. Fifteen years leading enterprise identity. More at [jamalsjones.com](https://www.jamalsjones.com).

MIT licensed.
