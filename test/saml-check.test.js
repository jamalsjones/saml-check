const test = require("node:test");
const assert = require("node:assert");
const fs = require("node:fs");
const path = require("node:path");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");
const { check, decode, run, parseCert } = require("../saml-check.js");

const ex = (n) => fs.readFileSync(path.join(__dirname, "..", "examples", n), "utf8");
const NOW = "2026-11-20T15:01:00Z";
const SP = { now: NOW, spEntityId: "https://payroll.example.com/saml", acsUrl: "https://payroll.example.com/saml/acs", idpEntityId: "https://login.example.com" };
const ids = (r) => r.findings.map((f) => f.id);
const good = ex("response-good.xml");

test("the good response has nothing to report except the KeyInfo reminder", () => {
  const r = check(good, SP);
  assert.deepStrictEqual(ids(r), ["keyinfo-cert"]);
  assert.strictEqual(r.facts.nameId, "priya.nair@northpeak.example");
  assert.deepStrictEqual(r.facts.audience, ["https://payroll.example.com/saml"]);
  assert.strictEqual(r.facts.attributes.length, 3);
});

test("the flawed response catches each planted problem", () => {
  const got = ids(check(ex("response-flawed.xml"), SP));
  for (const id of ["comment-in-text", "cert-expired", "cert-weak-key", "no-destination", "recipient-mismatch", "audience-mismatch", "sig-sha1", "digest-sha1", "long-lived", "only-response-signed", "unsolicited", "authn-context", "response-issuer-mismatch", "issuer-mismatch"]) {
    assert.ok(got.includes(id), "expected " + id + " in " + got.join(","));
  }
});

test("timing: expired, not yet valid, issued in the future, skew", () => {
  assert.ok(ids(check(good, { ...SP, now: "2026-11-20T15:20:00Z" })).includes("expired"));
  assert.ok(ids(check(good, { ...SP, now: "2026-11-20T15:20:00Z" })).includes("scd-expired"));
  assert.ok(ids(check(good, { ...SP, now: "2026-11-20T14:50:00Z" })).includes("not-yet-valid"));
  assert.ok(ids(check(good, { ...SP, now: "2026-11-20T14:50:00Z" })).includes("issued-future"));
  assert.ok(!ids(check(good, { ...SP, now: "2026-11-20T15:06:30Z" })).includes("expired")); // within 180s skew
});

test("DOCTYPE and custom entities are errors and never expanded", () => {
  const xxe = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>' + good.replace(/^<\?xml[^>]*>/, "").replace("Finance", "&x;");
  const r = check(xxe, SP);
  assert.ok(ids(r).includes("doctype"));
  assert.ok(ids(r).includes("entities"));
  assert.ok(r.facts.attributes.some((a) => a.values.includes("&x;")));
});

test("signature wrapping shapes", () => {
  // A second, unsigned assertion hidden in Extensions
  const hidden = good.replace("<samlp:Status>", '<samlp:Extensions><saml:Assertion ID="_evil" Version="2.0"/></samlp:Extensions><samlp:Status>');
  assert.ok(ids(check(hidden, SP)).includes("assertion-hidden"));
  // The signature points at a different element
  const moved = good.replace('URI="#_a91c4e7d2f8b6"', 'URI="#_r7f3a9c1e2b4d"');
  const r = check(moved, SP);
  assert.ok(ids(r).includes("sig-ref-mismatch"));
  assert.ok(ids(r).includes("unsigned"));
  // Duplicate IDs
  assert.ok(ids(check(good.replace('ID="_r7f3a9c1e2b4d"', 'ID="_a91c4e7d2f8b6"'), SP)).includes("duplicate-id"));
  // Two assertions
  const two = good.replace("</samlp:Response>", '<saml:Assertion ID="_b2" Version="2.0" IssueInstant="2026-11-20T15:00:00Z"/></samlp:Response>');
  assert.ok(ids(check(two, SP)).includes("many-assertions"));
});

test("XSLT transforms are errors", () => {
  const x = good.replace('<ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>', '<ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xslt-19991116"/>');
  assert.ok(ids(check(x, SP)).includes("transform"));
});

test("a failed status is reported with its message", () => {
  const f = good.replace('<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>', '<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode><samlp:StatusMessage>User not assigned to app</samlp:StatusMessage>');
  const r = check(f, SP);
  const m = r.findings.find((x) => x.id === "status-failed").message;
  assert.match(m, /Responder \/ RequestDenied/);
  assert.match(m, /User not assigned/);
});

test("metadata: legacy IdP, modern IdP and SP", () => {
  const legacy = ids(check(ex("idp-metadata-legacy.xml"), SP));
  for (const id of ["cert-expired", "cert-weak-key", "md-expired", "endpoint-http", "idp-unsigned-requests"]) assert.ok(legacy.includes(id), id);
  assert.strictEqual(check(ex("idp-metadata.xml"), SP).summary.error, 0);
  assert.strictEqual(check(ex("idp-metadata.xml"), SP).summary.warn, 0);
  const sp = check(ex("sp-metadata.xml"), SP);
  assert.strictEqual(sp.summary.error + sp.summary.warn, 0);
  assert.ok(ids(check(ex("sp-metadata.xml").replace('WantAssertionsSigned="true"', ""), SP)).includes("sp-assertions-unsigned"));
});

test("a certificate close to expiry warns", () => {
  assert.ok(ids(check(ex("idp-metadata.xml"), { now: "2035-12-15T00:00:00Z" })).includes("cert-expiring"));
});

test("certificate parsing", () => {
  const b64 = ex("sp-metadata.xml").match(/<ds:X509Certificate>([^<]+)</)[1];
  const c = parseCert(b64);
  assert.strictEqual(c.subject, "app.example.com");
  assert.strictEqual(c.keyType, "EC P-256");
  assert.strictEqual(new Date(c.notAfter).toISOString(), "2036-01-01T00:00:00.000Z");
});

test("AuthnRequest checks", () => {
  const req = '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_q1" Version="2.0" IssueInstant="2026-11-20T15:00:00Z" AssertionConsumerServiceURL="http://payroll.example.com/saml/acs" IsPassive="true" ForceAuthn="true"><saml:Issuer>https://payroll.example.com/saml</saml:Issuer></samlp:AuthnRequest>';
  const got = ids(check(req, SP));
  for (const id of ["acs-http", "acs-mismatch", "passive-force", "acs-unsigned"]) assert.ok(got.includes(id), id);
});

test("decode: POST binding, Redirect binding, URL-encoded, query string", async () => {
  const b64 = Buffer.from(good).toString("base64");
  assert.match((await decode(b64)).via, /POST/);
  const deflated = zlib.deflateRawSync(Buffer.from(good)).toString("base64");
  const d = await decode("https://login.example.com/sso?SAMLRequest=" + encodeURIComponent(deflated) + "&RelayState=x");
  assert.match(d.via, /Redirect/);
  assert.ok(d.xml.startsWith("<?xml"));
  assert.match((await decode("SAMLResponse=" + encodeURIComponent(b64))).via, /POST/);
  const bad = await run("not saml at all!", SP);
  assert.strictEqual(bad.findings[0].id, "decode");
});

test("malformed XML", () => {
  assert.strictEqual(check("<a><b></a>", SP).findings[0].id, "xml");
});

test("CLI exit codes", () => {
  const bin = path.join(__dirname, "..", "saml-check.js");
  const f = (n) => path.join(__dirname, "..", "examples", n);
  assert.match(execFileSync("node", [bin, f("response-good.xml"), "--now", NOW, "--sp", SP.spEntityId, "--acs", SP.acsUrl]).toString(), /0 errors/);
  assert.throws(() => execFileSync("node", [bin, f("response-flawed.xml"), "--now", NOW], { stdio: "pipe" }), (e) => e.status === 1);
  const out = execFileSync("node", [bin, "--json", "--now", NOW], { input: Buffer.from(good).toString("base64") }).toString();
  assert.strictEqual(JSON.parse(out).kind, "Response");
});
