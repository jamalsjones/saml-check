#!/usr/bin/env node
/*
 * saml-check: reviews a SAML 2.0 response, assertion, AuthnRequest or
 * metadata document against the SAML 2.0 core and profiles specifications,
 * the SAML V2.0 security considerations, and the attacks SAML deployments
 * keep running into (signature wrapping, comment truncation, XXE, replay).
 *
 * One file, no dependencies. It works three ways:
 *   - in a browser, as a plain <script> (it sets window.SamlCheck)
 *   - in Node, as a module: const { check, decode } = require("./saml-check.js")
 *   - in Node, as a command: node saml-check.js <file | -> [options]
 *
 * It reads the XML. It doesn't verify signatures or decrypt anything: that
 * needs keys and is your service provider's job. A response can pass every
 * check here and still be forged. Use it to see why a sign-in failed, or to
 * review what an identity provider sends and advertises.
 *
 * The XML reader here is deliberately small. It's a linter, not a schema
 * validator, and it never expands DTDs or external entities.
 *
 * MIT License. https://github.com/jamalsjones/saml-check
 */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.SamlCheck = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  var CORE = "SAML 2.0 Core";
  var PROF = "SAML 2.0 Profiles";
  var BIND = "SAML 2.0 Bindings";
  var META = "SAML 2.0 Metadata";
  var SEC = "SAML 2.0 Security Considerations";

  // ---- Bytes and base64 ------------------------------------------------------

  function b64ToBytes(s) {
    var clean = String(s).replace(/\s+/g, "");
    if (!/^[A-Za-z0-9+/=_-]+$/.test(clean)) return null;
    clean = clean.replace(/-/g, "+").replace(/_/g, "/");
    while (clean.length % 4) clean += "=";
    try {
      if (typeof Buffer !== "undefined") return new Uint8Array(Buffer.from(clean, "base64"));
      var bin = atob(clean);
      var out = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
      return out;
    } catch (e) {
      return null;
    }
  }

  function utf8(bytes) {
    return new TextDecoder("utf-8").decode(bytes);
  }

  function inflateRaw(bytes) {
    if (typeof require !== "undefined" && typeof window === "undefined") {
      try {
        return Promise.resolve(new Uint8Array(require("zlib").inflateRawSync(Buffer.from(bytes))));
      } catch (e) {
        return Promise.resolve(null);
      }
    }
    if (typeof DecompressionStream === "undefined") return Promise.resolve(null);
    try {
      var stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
      return new Response(stream)
        .arrayBuffer()
        .then(function (b) {
          return new Uint8Array(b);
        })
        .catch(function () {
          return null;
        });
    } catch (e) {
      return Promise.resolve(null);
    }
  }

  // Accepts raw XML, base64 (HTTP-POST binding), base64 of deflated XML
  // (HTTP-Redirect binding), URL-encoded values, or a whole query string or URL.
  function decode(input) {
    var s = String(input || "").trim();
    if (!s) return Promise.resolve({ xml: "", via: "empty" });
    if (s[0] === "<") return Promise.resolve({ xml: s, via: "XML" });

    var m = s.match(/(?:^|[?&\s])(SAMLResponse|SAMLRequest)=([^&\s]+)/);
    if (m) s = m[2];
    if (/%[0-9A-Fa-f]{2}/.test(s)) {
      try {
        s = decodeURIComponent(s.replace(/\+/g, "%20"));
      } catch (e) {
        /* leave it */
      }
    }
    var bytes = b64ToBytes(s);
    if (!bytes) return Promise.resolve({ xml: null, via: "unknown", error: "This isn't XML, base64, or a SAMLResponse / SAMLRequest value." });
    var text = utf8(bytes).replace(/^\uFEFF/, "").trim();
    if (text[0] === "<") return Promise.resolve({ xml: text, via: "base64 (HTTP-POST binding)" });
    return inflateRaw(bytes).then(function (inflated) {
      if (inflated) {
        var t = utf8(inflated).trim();
        if (t[0] === "<") return { xml: t, via: "base64 + deflate (HTTP-Redirect binding)" };
      }
      return { xml: null, via: "unknown", error: "Decoded the base64, but it isn't XML and doesn't inflate to XML." };
    });
  }

  // ---- A small XML reader ----------------------------------------------------

  var ENT = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

  function unescapeXml(s, info) {
    return s.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|[A-Za-z_][\w.-]*);/g, function (all, e) {
      if (e[0] === "#") return String.fromCodePoint(e[1] === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
      if (ENT[e]) return ENT[e];
      if (info) info.customEntities.push(e);
      return all; // never expanded
    });
  }

  function parseXml(text) {
    var info = { doctype: null, customEntities: [] };
    var doc = { type: "document", children: [] };
    var stack = [doc];
    var i = 0;
    var n = text.length;
    var tagRe = /<([^\s/>]+)/y;
    var attrRe = /\s*([^\s=/>]+)\s*=\s*(?:"([^"]*)"|'([^']*)')/y;
    var endRe = /\s*(\/?)>/y;
    function top() {
      return stack[stack.length - 1];
    }
    function append(node) {
      node.parent = top();
      top().children.push(node);
    }
    while (i < n) {
      if (text.startsWith("<!--", i)) {
        var ce = text.indexOf("-->", i + 4);
        if (ce < 0) throw new Error("A comment is never closed.");
        append({ type: "comment", value: text.slice(i + 4, ce) });
        i = ce + 3;
      } else if (text.startsWith("<![CDATA[", i)) {
        var cd = text.indexOf("]]>", i + 9);
        if (cd < 0) throw new Error("A CDATA section is never closed.");
        append({ type: "text", value: text.slice(i + 9, cd) });
        i = cd + 3;
      } else if (text.startsWith("<!DOCTYPE", i) || text.startsWith("<!doctype", i)) {
        var j = i + 9;
        var depth = 0;
        for (; j < n; j++) {
          var c = text[j];
          if (c === "[") depth++;
          else if (c === "]") depth--;
          else if (c === ">" && depth <= 0) break;
        }
        info.doctype = text.slice(i, j + 1);
        i = j + 1;
      } else if (text.startsWith("<?", i)) {
        var pe = text.indexOf("?>", i);
        if (pe < 0) throw new Error("A processing instruction is never closed.");
        i = pe + 2;
      } else if (text.startsWith("</", i)) {
        var ee = text.indexOf(">", i);
        if (ee < 0) throw new Error("A closing tag is never finished.");
        var name = text.slice(i + 2, ee).trim();
        var open = top();
        if (open.type !== "element" || open.name !== name) throw new Error("</" + name + "> doesn't match " + (open.name ? "<" + open.name + ">" : "anything") + ".");
        stack.pop();
        i = ee + 1;
      } else if (text[i] === "<") {
        tagRe.lastIndex = i;
        var tm = tagRe.exec(text);
        if (!tm) throw new Error("Unreadable tag near character " + i + ".");
        var el = { type: "element", name: tm[1], attrs: {}, children: [] };
        el.local = tm[1].indexOf(":") >= 0 ? tm[1].split(":")[1] : tm[1];
        el.prefix = tm[1].indexOf(":") >= 0 ? tm[1].split(":")[0] : "";
        var p = tagRe.lastIndex;
        for (;;) {
          attrRe.lastIndex = p;
          var am = attrRe.exec(text);
          if (!am) break;
          el.attrs[am[1]] = unescapeXml(am[2] !== undefined ? am[2] : am[3], info);
          p = attrRe.lastIndex;
        }
        endRe.lastIndex = p;
        var em = endRe.exec(text);
        if (!em) throw new Error("The tag <" + el.name + "> isn't closed properly.");
        append(el);
        if (!em[1]) stack.push(el);
        i = endRe.lastIndex;
      } else {
        var lt = text.indexOf("<", i);
        if (lt < 0) lt = n;
        var raw = text.slice(i, lt);
        if (raw.trim() || top().type === "element") append({ type: "text", value: unescapeXml(raw, info) });
        i = lt;
      }
    }
    if (stack.length > 1) throw new Error("<" + top().name + "> is never closed.");
    var rootEl = doc.children.filter(function (c) {
      return c.type === "element";
    })[0];
    if (!rootEl) throw new Error("There's no XML element in this.");
    return { root: rootEl, info: info };
  }

  function kids(el, local) {
    return (el.children || []).filter(function (c) {
      return c.type === "element" && (!local || c.local === local);
    });
  }
  function kid(el, local) {
    return kids(el, local)[0] || null;
  }
  function all(el, local, out) {
    out = out || [];
    (el.children || []).forEach(function (c) {
      if (c.type !== "element") return;
      if (!local || c.local === local) out.push(c);
      all(c, local, out);
    });
    return out;
  }
  function text(el) {
    if (!el) return "";
    return (el.children || [])
      .filter(function (c) {
        return c.type === "text";
      })
      .map(function (c) {
        return c.value;
      })
      .join("")
      .trim();
  }
  function hasComment(el) {
    return (el.children || []).some(function (c) {
      return c.type === "comment";
    });
  }
  function path(el) {
    var parts = [];
    for (var e = el; e && e.type === "element"; e = e.parent) parts.unshift(e.local);
    return parts.join(" > ");
  }
  function ancestor(el, local) {
    for (var e = el.parent; e && e.type === "element"; e = e.parent) if (e.local === local) return e;
    return null;
  }

  // ---- A small DER reader, for X.509 certificates ----------------------------

  function derRead(b, pos) {
    var tag = b[pos];
    var len = b[pos + 1];
    var off = pos + 2;
    if (len & 0x80) {
      var nb = len & 0x7f;
      len = 0;
      for (var k = 0; k < nb; k++) len = len * 256 + b[off + k];
      off += nb;
    }
    return { tag: tag, start: off, end: off + len, next: off + len };
  }
  function derChildren(b, node) {
    var out = [];
    var p = node.start;
    while (p < node.end) {
      var c = derRead(b, p);
      out.push(c);
      p = c.next;
    }
    return out;
  }
  function oid(b, node) {
    var s = [];
    var first = b[node.start];
    s.push(Math.floor(first / 40), first % 40);
    var v = 0;
    for (var p = node.start + 1; p < node.end; p++) {
      v = v * 128 + (b[p] & 0x7f);
      if (!(b[p] & 0x80)) {
        s.push(v);
        v = 0;
      }
    }
    return s.join(".");
  }
  function derTime(b, node) {
    var s = "";
    for (var p = node.start; p < node.end; p++) s += String.fromCharCode(b[p]);
    var y, rest;
    if (node.tag === 0x17) {
      y = +s.slice(0, 2);
      y += y < 50 ? 2000 : 1900;
      rest = s.slice(2);
    } else {
      y = +s.slice(0, 4);
      rest = s.slice(4);
    }
    return Date.UTC(y, +rest.slice(0, 2) - 1, +rest.slice(2, 4), +rest.slice(4, 6), +rest.slice(6, 8), +rest.slice(8, 10) || 0);
  }

  var SIG_OIDS = {
    "1.2.840.113549.1.1.4": "md5WithRSA",
    "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.113549.1.1.11": "sha256WithRSA",
    "1.2.840.113549.1.1.12": "sha384WithRSA",
    "1.2.840.113549.1.1.13": "sha512WithRSA",
    "1.2.840.113549.1.1.10": "RSASSA-PSS",
    "1.2.840.10045.4.1": "ecdsaWithSHA1",
    "1.2.840.10045.4.3.2": "ecdsaWithSHA256",
    "1.2.840.10045.4.3.3": "ecdsaWithSHA384",
    "1.2.840.10045.4.3.4": "ecdsaWithSHA512",
    "1.3.101.112": "Ed25519",
  };
  var CURVES = { "1.2.840.10045.3.1.7": ["P-256", 256], "1.3.132.0.34": ["P-384", 384], "1.3.132.0.35": ["P-521", 521] };

  function parseCert(b64) {
    var b = b64ToBytes(b64);
    if (!b || b[0] !== 0x30) return null;
    try {
      var cert = derRead(b, 0);
      var parts = derChildren(b, cert);
      var tbs = derChildren(b, parts[0]);
      var idx = tbs[0].tag === 0xa0 ? 1 : 0; // skip explicit version
      var sigAlg = oid(b, derChildren(b, tbs[idx + 1])[0]);
      var subject = tbs[idx + 4];
      var validity = derChildren(b, tbs[idx + 3]);
      var spki = derChildren(b, tbs[idx + 5]);
      var algParts = derChildren(b, spki[0]);
      var keyAlg = oid(b, algParts[0]);
      var keyType = "unknown";
      var keyBits = null;
      if (keyAlg === "1.2.840.113549.1.1.1") {
        keyType = "RSA";
        var bit = spki[1];
        var rsa = derRead(b, bit.start + 1);
        var mod = derChildren(b, rsa)[0];
        var len = mod.end - mod.start;
        if (b[mod.start] === 0) len--;
        keyBits = len * 8;
      } else if (keyAlg === "1.2.840.10045.2.1") {
        keyType = "EC";
        var curve = CURVES[oid(b, algParts[1])];
        keyBits = curve ? curve[1] : null;
        if (curve) keyType = "EC " + curve[0];
      } else if (keyAlg === "1.3.101.112") {
        keyType = "Ed25519";
        keyBits = 256;
      }
      var cn = null;
      derChildren(b, subject).forEach(function (set) {
        derChildren(b, set).forEach(function (atv) {
          var pair = derChildren(b, atv);
          if (oid(b, pair[0]) === "2.5.4.3") cn = utf8(b.subarray(pair[1].start, pair[1].end));
        });
      });
      return {
        subject: cn,
        notBefore: derTime(b, validity[0]),
        notAfter: derTime(b, validity[1]),
        signatureAlgorithm: SIG_OIDS[sigAlg] || sigAlg,
        keyType: keyType,
        keyBits: keyBits,
      };
    } catch (e) {
      return null;
    }
  }

  // ---- Algorithms ------------------------------------------------------------

  var WEAK_SIG = /#(rsa-sha1|dsa-sha1|hmac-sha1)$|rsa-md5|ecdsa-sha1/;
  var WEAK_DIGEST = /#sha1$|#md5$/;
  var OK_TRANSFORMS = [
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature",
    "http://www.w3.org/2001/10/xml-exc-c14n#",
    "http://www.w3.org/2001/10/xml-exc-c14n#WithComments",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
    "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments",
    "http://www.w3.org/2006/12/xml-c14n11",
  ];
  var BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
  var SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";
  var PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

  function shortAlg(uri) {
    return String(uri || "").replace(/^.*#/, "");
  }

  // ---- Checks ----------------------------------------------------------------

  var DEFAULTS = {
    spEntityId: null, // your service provider's entity ID: what Audience should say
    acsUrl: null, // your assertion consumer service URL: what Destination and Recipient should say
    idpEntityId: null, // the identity provider you trust: what Issuer should say
    skewSeconds: 180, // clock skew allowed on time checks
    maxAssertionMinutes: 60, // warn when an assertion is valid for longer than this
    certWarnDays: 30, // warn when a certificate expires within this many days
    now: null, // a date or milliseconds; defaults to now
  };

  function check(xml, options) {
    var opts = {};
    var k;
    for (k in DEFAULTS) opts[k] = DEFAULTS[k];
    if (options) for (k in options) if (options[k] !== undefined && options[k] !== null && options[k] !== "") opts[k] = options[k];
    var now = opts.now == null ? Date.now() : typeof opts.now === "number" ? opts.now : Date.parse(opts.now);
    var skew = Number(opts.skewSeconds) * 1000;

    var findings = [];
    var facts = { kind: null, issuer: null, nameId: null, nameIdFormat: null, audience: [], notBefore: null, notOnOrAfter: null, attributes: [], certificates: [] };
    var result = { kind: null, facts: facts, findings: findings, summary: null };
    function add(level, id, where, message, ref) {
      findings.push({ level: level, id: id, where: where || null, message: message, ref: ref || null });
    }

    var parsed;
    try {
      parsed = parseXml(String(xml || ""));
    } catch (e) {
      add("error", "xml", null, "This isn't well-formed XML: " + e.message);
      return finish(result);
    }
    var root = parsed.root;
    result.kind = facts.kind = root.local;

    // ---- Document-level: DTDs, entities, IDs, signatures, comments ----------

    if (parsed.info.doctype) {
      add("error", "doctype", null, "The document has a DOCTYPE. SAML messages must not, and a parser that honours it can be made to read local files or exhaust memory (XXE, entity expansion). Reject any message with one.", SEC + " §6.4; " + BIND + " §3.1");
    }
    if (parsed.info.customEntities.length) {
      add("error", "entities", null, "The document uses entities that aren't standard XML (" + unique(parsed.info.customEntities).join(", ") + "). They weren't expanded here; a parser that expands them is open to XXE.", SEC + " §6.4");
    }

    var ids = {};
    all({ children: [root] }).forEach(function (el) {
      var id = el.attrs.ID || el.attrs.AssertionID || el.attrs.Id;
      if (!id) return;
      if (ids[id]) add("error", "duplicate-id", el.local, "Two elements share the ID \"" + id + "\" (" + ids[id].local + " and " + el.local + "). A signature that points at that ID could be checked against one and the other could be read. This is how signature-wrapping attacks work.", SEC + " §6.4.2");
      else ids[id] = el;
    });

    var signedBy = [];
    var SIGNABLE = ["Response", "Assertion", "AuthnRequest", "LogoutRequest", "LogoutResponse", "EntityDescriptor", "EntitiesDescriptor", "ArtifactResolve", "ArtifactResponse"];
    all({ children: [root] }, "Signature").forEach(function (sig) {
      var parent = sig.parent;
      var si = kid(sig, "SignedInfo");
      var ref = si && kid(si, "Reference");
      var uri = ref ? ref.attrs.URI : undefined;
      var where = parent && parent.local ? parent.local : "document";
      if (!parent || SIGNABLE.indexOf(parent.local) === -1) {
        add("error", "sig-misplaced", path(sig), "A signature sits inside " + where + ", which isn't something SAML signs. Signatures out of place are a sign of a wrapping attack.", SEC + " §6.4.2");
        return;
      }
      if (si && kids(si, "Reference").length > 1) {
        add("warn", "sig-multi-ref", where, "The signature on " + where + " covers more than one reference. SAML signatures should cover exactly the element they sit in.", CORE + " §5.4.2");
      }
      var ownId = parent.attrs.ID || parent.attrs.AssertionID;
      if (uri === "" || uri === undefined) {
        add("warn", "sig-empty-uri", where, "The signature on " + where + " references the whole document (URI=\"\") instead of the element's ID. SAML requires the reference to name the signed element's ID.", CORE + " §5.4.2");
      } else if (uri !== "#" + ownId) {
        add("error", "sig-ref-mismatch", where, "The signature inside " + where + " points to " + uri + ", but this " + where + "'s ID is " + (ownId || "missing") + ". The signature covers some other element. Classic signature wrapping.", CORE + " §5.4.2; " + SEC + " §6.4.2");
      } else {
        signedBy.push(parent);
      }
      var sm = si && kid(si, "SignatureMethod");
      var smAlg = sm && sm.attrs.Algorithm;
      if (smAlg && WEAK_SIG.test(smAlg)) {
        add("warn", "sig-sha1", where, "The signature on " + where + " uses " + shortAlg(smAlg) + ". SHA-1 signatures can be forged with enough effort; use rsa-sha256 or stronger.", "RFC 6931 §2.3; NIST SP 800-131A");
      }
      var dm = ref && kid(ref, "DigestMethod");
      if (dm && WEAK_DIGEST.test(dm.attrs.Algorithm || "")) {
        add("warn", "digest-sha1", where, "The digest on " + where + " uses " + shortAlg(dm.attrs.Algorithm) + ". Use sha256 or stronger.", "RFC 6931 §2.1");
      }
      var tr = ref && kid(ref, "Transforms");
      kids(tr || { children: [] }, "Transform").forEach(function (t) {
        var a = t.attrs.Algorithm || "";
        if (OK_TRANSFORMS.indexOf(a) === -1) {
          add("error", "transform", where, "The signature on " + where + " uses the transform " + a + ". SAML allows only enveloped-signature and canonicalization. XSLT and XPath transforms have been used to run code and to hide what was signed.", CORE + " §5.4.4; " + SEC + " §6.4.2");
        }
      });
      kids(sig, "KeyInfo").forEach(function () {});
    });

    var commentEls = all({ children: [root] }).filter(function (el) {
      return hasComment(el) && text(el) !== "";
    });
    commentEls.forEach(function (el) {
      add("error", "comment-in-text", el.local, "A comment sits inside the text of " + el.local + " (\"" + el.children.map(function (c) { return c.type === "comment" ? "<!--" + c.value + "-->" : c.value; }).join("").trim().slice(0, 80) + "\"). Comments don't change the signature, but some libraries read only the text before the comment, so user@evil.example<!---->.example.com can become someone else.", "CVE-2017-11427 and related; " + SEC + " §6.4.2");
    });

    var embedded = all({ children: [root] }, "Signature").some(function (sig) {
      return all(sig, "X509Certificate").length > 0;
    });
    if (embedded && root.local !== "EntityDescriptor" && root.local !== "EntitiesDescriptor") {
      add("info", "keyinfo-cert", "Signature", "The signature carries its own certificate. Your service provider must verify with the certificate it has from the identity provider's metadata, never with the one in the message, or anyone can sign with their own key.", SEC + " §6.4.2");
    }

    all({ children: [root] }, "X509Certificate").forEach(function (el) {
      var c = parseCert(text(el));
      var where = ancestor(el, "KeyDescriptor") ? describeKey(ancestor(el, "KeyDescriptor")) : ancestor(el, "Signature") ? "signature KeyInfo" : "certificate";
      if (!c) {
        add("warn", "cert-unreadable", where, "A certificate couldn't be read as X.509.", null);
        return;
      }
      c.where = where;
      facts.certificates.push(c);
      checkCert(c, where);
    });

    function checkCert(c, where) {
      var name = (c.subject ? "CN=" + c.subject : "A certificate") + " (" + where + ")";
      if (c.notAfter <= now) {
        add("error", "cert-expired", where, name + " expired on " + day(c.notAfter) + ". Many service providers reject expired signing certificates outright.", null);
      } else if (c.notAfter - now < Number(opts.certWarnDays) * 86400000) {
        add("warn", "cert-expiring", where, name + " expires on " + day(c.notAfter) + ", in " + Math.ceil((c.notAfter - now) / 86400000) + " days. Publish the next certificate in metadata now so every service provider has it before the switch.", null);
      }
      if (c.notBefore > now + skew) add("error", "cert-future", where, name + " isn't valid until " + day(c.notBefore) + ".", null);
      if (/^RSA$/.test(c.keyType) && c.keyBits && c.keyBits < 2048) {
        add("error", "cert-weak-key", where, name + " has a " + c.keyBits + "-bit RSA key. Use 2048 bits or more.", "NIST SP 800-131A");
      }
      if (/md5|sha1/i.test(c.signatureAlgorithm)) {
        add("info", "cert-sha1", where, name + " is signed with " + c.signatureAlgorithm + ". For a self-signed SAML certificate that matters little, because trust comes from the key in metadata, but some tools and auditors will flag it.", null);
      }
    }

    // ---- By document type ----------------------------------------------------

    if (root.local === "Response") checkResponse(root);
    else if (root.local === "Assertion") checkAssertion(root, null, true);
    else if (root.local === "AuthnRequest") checkAuthnRequest(root);
    else if (root.local === "EntityDescriptor") checkEntity(root, false);
    else if (root.local === "EntitiesDescriptor") {
      checkValidUntil(root);
      var ents = all(root, "EntityDescriptor");
      ents.slice(0, 200).forEach(function (e) {
        checkEntity(e, true);
      });
      if (!kid(root, "Signature")) add("warn", "md-unsigned", "EntitiesDescriptor", "This metadata aggregate isn't signed. Fetch it over TLS from a URL you trust, and prefer signed metadata so a tampered copy is caught.", META + " §3");
    } else if (root.local === "LogoutRequest" || root.local === "LogoutResponse") {
      checkProtocolBasics(root);
    } else {
      add("warn", "unknown-kind", root.local, "The root element is " + root.local + ", which this tool doesn't review in depth. Only the document-wide checks ran.", null);
    }

    function signed(el) {
      return signedBy.indexOf(el) !== -1;
    }

    function checkProtocolBasics(el) {
      if (el.attrs.Version !== "2.0") add("error", "version", el.local, "Version is " + (el.attrs.Version ? "\"" + el.attrs.Version + "\"" : "missing") + ". SAML 2.0 messages must say 2.0.", CORE + " §3.2.1");
      if (!el.attrs.ID) add("error", "no-id", el.local, el.local + " has no ID.", CORE + " §3.2.1");
      else if (/^[0-9]/.test(el.attrs.ID)) add("warn", "id-format", el.local, "The ID starts with a digit (" + el.attrs.ID + "). IDs must be valid xs:ID values, which can't, and some signature libraries will fail to find it.", CORE + " §1.3.4");
      timeNear(el, "IssueInstant");
    }

    function timeNear(el, attr) {
      var v = el.attrs[attr];
      if (!v) {
        add("error", "no-" + attr.toLowerCase(), el.local, el.local + " has no " + attr + ".", CORE + " §3.2.1");
        return;
      }
      var t = Date.parse(v);
      if (isNaN(t)) add("error", "bad-time", el.local, el.local + " " + attr + " isn't a valid time (" + v + ").", CORE + " §1.3.3");
      else if (!/Z$|[+-]\d\d:\d\d$/.test(v)) add("warn", "time-zone", el.local, attr + " has no time zone (" + v + "). SAML times must be UTC with a trailing Z.", CORE + " §1.3.3");
      else if (t > now + skew) add("error", "issued-future", el.local, el.local + " was issued " + ago(t - now) + " in the future. One side's clock is wrong.", CORE + " §1.3.3");
      else if (now - t > 24 * 3600000) add("info", "issued-old", el.local, el.local + " was issued " + ago(now - t) + " ago. If you're reviewing a saved message, set the check time to when it was used.", null);
    }

    function checkResponse(r) {
      checkProtocolBasics(r);
      var issuer = kid(r, "Issuer");
      var rIssuer = text(issuer);
      if (!issuer) add("warn", "response-no-issuer", "Response", "The Response has no Issuer. It's optional on the Response but your service provider can't tell who sent it.", PROF + " §4.1.4.2");
      else if (opts.idpEntityId && rIssuer !== opts.idpEntityId) add("error", "response-issuer-mismatch", "Response", "The Response Issuer is " + rIssuer + ", not " + opts.idpEntityId + ".", PROF + " §4.1.4.2");

      var status = kid(r, "Status");
      var code = status && kid(status, "StatusCode");
      var codeVal = code ? code.attrs.Value : null;
      if (!codeVal) add("error", "no-status", "Response", "The Response has no StatusCode.", CORE + " §3.2.2");
      else if (codeVal !== SUCCESS) {
        var sub = code && kid(code, "StatusCode");
        var msg = status && text(kid(status, "StatusMessage"));
        add("error", "status-failed", "Status", "The identity provider says the sign-in failed: " + shortStatus(codeVal) + (sub ? " / " + shortStatus(sub.attrs.Value) : "") + (msg ? " (\"" + msg + "\")" : "") + ". The fix is on the identity provider's side; its logs will say more.", CORE + " §3.2.2.2");
      }

      var dest = r.attrs.Destination;
      if (!dest) {
        if (signed(r)) add("error", "no-destination", "Response", "The Response is signed but has no Destination. The POST binding requires it on signed responses, so a response stolen from one app can't be replayed at another.", BIND + " §3.5.5.2");
      } else {
        if (opts.acsUrl && dest !== opts.acsUrl) add("error", "destination-mismatch", "Response", "Destination is " + dest + ", but your assertion consumer service is " + opts.acsUrl + ". Compare exactly, including trailing slashes and http vs https.", BIND + " §3.5.5.2");
        if (/^http:/i.test(dest)) add("error", "destination-http", "Response", "Destination is plain HTTP. Assertions must be delivered over TLS.", BIND + " §3.5.5.2");
      }

      var direct = kids(r, "Assertion");
      var encrypted = kids(r, "EncryptedAssertion");
      var allAssertions = all(r, "Assertion");
      allAssertions.forEach(function (a) {
        if (a.parent === r) return;
        if (ancestor(a, "EncryptedAssertion")) return;
        if (ancestor(a, "Advice")) add("warn", "assertion-in-advice", path(a), "An assertion sits inside Advice. That's allowed, but service providers must never use it for sign-in.", CORE + " §2.6.1");
        else add("error", "assertion-hidden", path(a), "An assertion is tucked away at " + path(a) + ". Assertions belong directly under the Response. This is the shape of a signature-wrapping attack.", SEC + " §6.4.2");
      });
      if (direct.length + encrypted.length === 0) {
        if (codeVal === SUCCESS) add("error", "no-assertion", "Response", "A successful Response with no assertion.", PROF + " §4.1.4.2");
      } else if (direct.length + encrypted.length > 1) {
        add("warn", "many-assertions", "Response", "The Response has " + (direct.length + encrypted.length) + " assertions. That's allowed, but most service providers expect one, and wrapping attacks rely on the provider checking one and using another.", SEC + " §6.4.2");
      }
      if (encrypted.length) {
        add("info", "encrypted", "EncryptedAssertion", "The assertion is encrypted, so its contents can't be checked here. To review it, paste the decrypted assertion from your service provider's debug log.", CORE + " §2.3.4");
        encrypted.forEach(function (ea) {
          all(ea, "EncryptionMethod").forEach(function (em) {
            var alg = em.attrs.Algorithm || "";
            if (/rsa-1_5$/.test(alg)) add("warn", "enc-rsa15", "EncryptedAssertion", "The key is wrapped with RSA PKCS#1 v1.5, which is open to padding-oracle attacks. Use RSA-OAEP.", "W3C XML Encryption 1.1 §5.5.1");
            else if (/-cbc$/.test(alg)) add("warn", "enc-cbc", "EncryptedAssertion", "The assertion is encrypted with " + shortAlg(alg) + ". CBC mode in XML Encryption can be decrypted by an attacker who sees error responses. Use AES-GCM.", "W3C XML Encryption 1.1 §5.2");
          });
        });
      }
      var anyAssertionSigned = direct.some(signed);
      if (!signed(r) && !anyAssertionSigned && direct.length) {
        add("error", "unsigned", "Response", "Neither the Response nor the assertion is signed. Anyone could have written this. The browser SSO profile requires the assertion to be signed.", PROF + " §4.1.3.5");
      } else if (signed(r) && direct.length && !anyAssertionSigned) {
        add("info", "only-response-signed", "Response", "Only the Response is signed, not the assertion. That's fine if your service provider verifies the Response signature, but a provider that only checks assertion signatures will reject it.", PROF + " §4.1.3.5");
      }

      direct.forEach(function (a) {
        checkAssertion(a, r, false);
        var ai = text(kid(a, "Issuer"));
        if (rIssuer && ai && ai !== rIssuer) add("error", "issuer-differs", "Assertion", "The Response Issuer (" + rIssuer + ") and the assertion Issuer (" + ai + ") differ.", PROF + " §4.1.4.2");
        var irt = r.attrs.InResponseTo;
        all(a, "SubjectConfirmationData").forEach(function (scd) {
          if (scd.attrs.InResponseTo && irt && scd.attrs.InResponseTo !== irt) add("error", "inresponseto-mismatch", "SubjectConfirmationData", "InResponseTo on the Response (" + irt + ") and in the assertion (" + scd.attrs.InResponseTo + ") differ.", PROF + " §4.1.4.3");
        });
      });
      if (!r.attrs.InResponseTo) {
        add("info", "unsolicited", "Response", "There's no InResponseTo, so this is an IdP-initiated sign-in. Service providers that accept those can't tie the response to a request, which opens the door to login CSRF and replay. Accept them only if you need to.", PROF + " §4.1.5; " + SEC + " §7.1.1.2");
      }
    }

    function checkAssertion(a, response, standalone) {
      if (standalone) {
        if (!signed(a)) add("error", "unsigned", "Assertion", "The assertion isn't signed.", PROF + " §4.1.3.5");
      }
      if (a.attrs.Version !== "2.0") add("error", "version", "Assertion", "The assertion's Version is " + (a.attrs.Version || "missing") + ".", CORE + " §2.3.3");
      if (!a.attrs.ID) add("error", "no-id", "Assertion", "The assertion has no ID, so it can't be signed or checked for replay.", CORE + " §2.3.3");
      timeNear(a, "IssueInstant");

      var issuer = kid(a, "Issuer");
      var ai = text(issuer);
      facts.issuer = ai || facts.issuer;
      if (!issuer) add("error", "no-issuer", "Assertion", "The assertion has no Issuer.", CORE + " §2.3.3");
      else {
        if (issuer.attrs.Format && issuer.attrs.Format !== "urn:oasis:names:tc:SAML:2.0:nameid-format:entity") add("warn", "issuer-format", "Issuer", "The assertion Issuer's Format is " + issuer.attrs.Format + ". In web SSO it must be the entity format, or left out.", PROF + " §4.1.4.2");
        if (opts.idpEntityId && ai !== opts.idpEntityId) add("error", "issuer-mismatch", "Issuer", "The assertion Issuer is " + ai + ", not the identity provider you trust (" + opts.idpEntityId + ").", PROF + " §4.1.4.2");
      }

      var subj = kid(a, "Subject");
      var nameId = subj && kid(subj, "NameID");
      if (!subj) add("error", "no-subject", "Assertion", "The assertion has no Subject, so it doesn't say who signed in.", PROF + " §4.1.4.2");
      else if (!nameId && !kid(subj, "EncryptedID")) add("warn", "no-nameid", "Subject", "There's no NameID. Your service provider will have to find the user from an attribute.", CORE + " §2.4.1");
      if (nameId) {
        facts.nameId = text(nameId);
        facts.nameIdFormat = nameId.attrs.Format || null;
        if (!facts.nameId) add("error", "empty-nameid", "NameID", "NameID is empty.", CORE + " §2.2.3");
        if (/transient$/.test(nameId.attrs.Format || "")) add("info", "nameid-transient", "NameID", "NameID is transient: a new random value each sign-in. Your service provider must find the user by an attribute instead.", CORE + " §8.3.8");
      }

      var bearers = subj ? kids(subj, "SubjectConfirmation").filter(function (sc) { return sc.attrs.Method === BEARER; }) : [];
      if (subj && !bearers.length) add("error", "no-bearer", "Subject", "There's no bearer SubjectConfirmation. Web browser SSO requires one.", PROF + " §4.1.4.2");
      bearers.forEach(function (sc) {
        var d = kid(sc, "SubjectConfirmationData");
        if (!d) {
          add("error", "no-scd", "SubjectConfirmation", "The bearer confirmation has no SubjectConfirmationData, so there's no Recipient or expiry to check.", PROF + " §4.1.4.2");
          return;
        }
        if (!d.attrs.Recipient) add("error", "no-recipient", "SubjectConfirmationData", "There's no Recipient. Without it, an assertion meant for one app can be replayed at another.", PROF + " §4.1.4.2");
        else if (opts.acsUrl && d.attrs.Recipient !== opts.acsUrl) add("error", "recipient-mismatch", "SubjectConfirmationData", "Recipient is " + d.attrs.Recipient + ", but your assertion consumer service is " + opts.acsUrl + ".", PROF + " §4.1.4.3");
        if (!d.attrs.NotOnOrAfter) add("error", "no-scd-expiry", "SubjectConfirmationData", "There's no NotOnOrAfter on the bearer confirmation, so the assertion can be used forever.", PROF + " §4.1.4.2");
        else {
          var exp = Date.parse(d.attrs.NotOnOrAfter);
          if (exp + skew <= now) add("error", "scd-expired", "SubjectConfirmationData", "The bearer confirmation expired " + ago(now - exp) + " ago (NotOnOrAfter " + d.attrs.NotOnOrAfter + ").", PROF + " §4.1.4.3");
        }
        if (d.attrs.NotBefore) add("warn", "scd-notbefore", "SubjectConfirmationData", "The bearer confirmation has a NotBefore. The profile says it must not.", PROF + " §4.1.4.2");
        if (response && response.attrs.InResponseTo && !d.attrs.InResponseTo) add("warn", "scd-no-irt", "SubjectConfirmationData", "The Response answers a request but the bearer confirmation has no InResponseTo.", PROF + " §4.1.4.2");
      });

      var cond = kid(a, "Conditions");
      if (!cond) add("error", "no-conditions", "Assertion", "There are no Conditions, so no audience and no validity window.", PROF + " §4.1.4.2");
      else {
        var nb = cond.attrs.NotBefore ? Date.parse(cond.attrs.NotBefore) : null;
        var na = cond.attrs.NotOnOrAfter ? Date.parse(cond.attrs.NotOnOrAfter) : null;
        facts.notBefore = cond.attrs.NotBefore || null;
        facts.notOnOrAfter = cond.attrs.NotOnOrAfter || null;
        if (nb !== null && nb > now + skew) add("error", "not-yet-valid", "Conditions", "Not valid for another " + ago(nb - now) + " (NotBefore " + cond.attrs.NotBefore + "). Usually the identity provider's clock is ahead.", CORE + " §2.5.1.2");
        if (na !== null && na + skew <= now) add("error", "expired", "Conditions", "Expired " + ago(now - na) + " ago (NotOnOrAfter " + cond.attrs.NotOnOrAfter + ").", CORE + " §2.5.1.2");
        if (na === null) add("warn", "no-expiry", "Conditions", "Conditions has no NotOnOrAfter.", CORE + " §2.5.1.2");
        var start = nb !== null ? nb : a.attrs.IssueInstant ? Date.parse(a.attrs.IssueInstant) : null;
        if (na !== null && start !== null && na - start > Number(opts.maxAssertionMinutes) * 60000) {
          add("warn", "long-lived", "Conditions", "The assertion is valid for " + ago(na - start) + ". Assertions are meant to be used once, within minutes; a long window widens the chance to replay a stolen one.", SEC + " §7.1.1.1");
        }
        var auds = all(cond, "Audience").map(text);
        facts.audience = auds;
        if (!kid(cond, "AudienceRestriction")) add("error", "no-audience", "Conditions", "There's no AudienceRestriction, so this assertion is good at any service provider that trusts this identity provider.", PROF + " §4.1.4.2");
        else if (opts.spEntityId && auds.indexOf(opts.spEntityId) === -1) add("error", "audience-mismatch", "Audience", "Audience is " + auds.join(", ") + ", not your entity ID (" + opts.spEntityId + "). The identity provider has the wrong entity ID for this app, or the app is configured with the wrong one.", CORE + " §2.5.1.4");
        if (kid(cond, "OneTimeUse")) add("info", "one-time-use", "Conditions", "OneTimeUse is set, so your service provider must remember this assertion's ID until it expires.", CORE + " §2.5.1.5");
      }

      var authn = kid(a, "AuthnStatement");
      if (!authn) add("error", "no-authn", "Assertion", "There's no AuthnStatement, so the assertion doesn't say the user signed in.", PROF + " §4.1.4.2");
      else {
        var ctx = text(all(authn, "AuthnContextClassRef")[0]);
        if (ctx) {
          facts.authnContext = ctx;
          if (/PasswordProtectedTransport$|:Password$|unspecified$/.test(ctx)) add("info", "authn-context", "AuthnContextClassRef", "The sign-in method is " + ctx.replace(/^.*:/, "") + ". It says nothing about MFA. If this app needs MFA, require a stronger context in the AuthnRequest or check an MFA attribute.", "SAML 2.0 Authentication Context");
        }
        var sess = authn.attrs.SessionNotOnOrAfter ? Date.parse(authn.attrs.SessionNotOnOrAfter) : null;
        var ai2 = authn.attrs.AuthnInstant ? Date.parse(authn.attrs.AuthnInstant) : null;
        if (sess && ai2 && sess - ai2 > 24 * 3600000) add("info", "long-session", "AuthnStatement", "SessionNotOnOrAfter asks for a session of " + ago(sess - ai2) + ".", CORE + " §2.7.2");
        if (ai2 && now - ai2 > 12 * 3600000 && now - ai2 < 30 * 86400000) add("info", "old-authn", "AuthnStatement", "The user authenticated " + ago(now - ai2) + " ago (AuthnInstant). If this app needs a fresh sign-in, set ForceAuthn or check the age.", CORE + " §2.7.2");
      }

      all(a, "Attribute").forEach(function (at) {
        var name = at.attrs.FriendlyName || at.attrs.Name || "";
        var values = kids(at, "AttributeValue").map(text);
        facts.attributes.push({ name: at.attrs.Name || "", friendlyName: at.attrs.FriendlyName || "", values: values });
        if (/(pass(word)?|secret|ssn|social.?security|credit.?card|private.?key)/i.test(name)) add("warn", "sensitive-attr", name, "An attribute called " + name + " is sent in the assertion. Unless the assertion is encrypted, the browser and anything logging it can read it.", SEC + " §6.2");
      });
    }

    function checkAuthnRequest(req) {
      checkProtocolBasics(req);
      var issuer = text(kid(req, "Issuer"));
      facts.issuer = issuer || null;
      if (!issuer) add("error", "no-issuer", "AuthnRequest", "The AuthnRequest has no Issuer, so the identity provider can't tell which app is asking.", PROF + " §4.1.4.1");
      else if (opts.spEntityId && issuer !== opts.spEntityId) add("error", "issuer-mismatch", "AuthnRequest", "The request's Issuer is " + issuer + ", not " + opts.spEntityId + ".", PROF + " §4.1.4.1");
      var acs = req.attrs.AssertionConsumerServiceURL;
      if (acs) {
        if (/^http:/i.test(acs)) add("error", "acs-http", "AuthnRequest", "AssertionConsumerServiceURL is plain HTTP.", BIND + " §3.5");
        if (opts.acsUrl && acs !== opts.acsUrl) add("error", "acs-mismatch", "AuthnRequest", "The request asks for the response at " + acs + ", not " + opts.acsUrl + ".", PROF + " §4.1.4.1");
        if (!signed(req)) add("info", "acs-unsigned", "AuthnRequest", "The request names its own AssertionConsumerServiceURL but isn't signed here. The identity provider must check that URL against registered metadata, or sign requests (for the Redirect binding the signature is in the URL, not the XML).", PROF + " §4.1.4.1");
      }
      if (req.attrs.Destination && /^http:/i.test(req.attrs.Destination)) add("error", "destination-http", "AuthnRequest", "Destination is plain HTTP.", BIND + " §3.5");
      if (req.attrs.IsPassive === "true" && req.attrs.ForceAuthn === "true") add("warn", "passive-force", "AuthnRequest", "IsPassive and ForceAuthn are both true. The identity provider can't both skip and force a sign-in prompt, so this request will fail.", CORE + " §3.4.1");
      var ctx = all(req, "AuthnContextClassRef").map(text);
      if (ctx.length) facts.authnContext = ctx.join(", ");
    }

    function describeKey(kd) {
      var role = ancestor(kd, "IDPSSODescriptor") ? "IdP" : ancestor(kd, "SPSSODescriptor") ? "SP" : "metadata";
      return role + " " + (kd.attrs.use || "signing+encryption") + " key";
    }

    function checkValidUntil(el) {
      var vu = el.attrs.validUntil;
      if (vu) {
        var t = Date.parse(vu);
        if (t <= now) add("error", "md-expired", el.local, "This metadata's validUntil (" + vu + ") has passed. Service providers that honour it will refuse to use it.", META + " §2.3.1");
        else if (t - now < 7 * 86400000) add("warn", "md-expiring", el.local, "This metadata expires on " + vu + ". Make sure consumers refresh it before then.", META + " §2.3.1");
      }
      return !!vu;
    }

    function checkEntity(e, inAggregate) {
      var id = e.attrs.entityID;
      var label = inAggregate ? id || "EntityDescriptor" : "EntityDescriptor";
      if (!id) add("error", "no-entityid", label, "EntityDescriptor has no entityID.", META + " §2.3.2");
      else {
        if (id.length > 1024) add("error", "entityid-long", label, "entityID is longer than 1024 characters.", META + " §2.3.2");
        if (/^http:/i.test(id)) add("info", "entityid-http", label, "entityID is an http:// URL. That's only a name, so it's not a vulnerability, but https names avoid questions in reviews.", null);
      }
      facts.entityId = facts.entityId || id || null;
      var hasValid = checkValidUntil(e);
      if (!inAggregate) {
        if (!hasValid && !e.attrs.cacheDuration) add("info", "md-no-expiry", label, "No validUntil or cacheDuration, so consumers don't know when to refresh this metadata.", META + " §2.3.2");
        if (!kid(e, "Signature")) add("info", "md-unsigned", label, "This metadata isn't signed. That's common when it's exchanged by hand or fetched over TLS from the provider, but signed metadata lets consumers detect tampering.", META + " §3");
      }

      kids(e, "IDPSSODescriptor").forEach(function (d) {
        facts.role = "IdP";
        checkRole(d, label + " IdP");
        var sso = kids(d, "SingleSignOnService");
        if (!sso.length) add("error", "no-sso", label, "The IdP has no SingleSignOnService endpoint.", META + " §2.4.3");
        sso.forEach(function (s) {
          endpoint(s, label + " SingleSignOnService");
        });
        kids(d, "SingleLogoutService").forEach(function (s) {
          endpoint(s, label + " SingleLogoutService");
        });
        if (d.attrs.WantAuthnRequestsSigned !== "true") add("info", "idp-unsigned-requests", label, "The IdP doesn't require signed AuthnRequests. Then it must check every requested AssertionConsumerServiceURL against registered metadata, or responses can be sent somewhere else.", META + " §2.4.3; " + PROF + " §4.1.4.1");
        var signing = keys(d, "signing");
        if (!signing.length) add("error", "idp-no-signing-key", label, "The IdP publishes no signing certificate, so no one can check its signatures.", META + " §2.4.1.1");
        else if (signing.length === 1) add("info", "single-signing-key", label, "Only one signing certificate is published. To roll it over without an outage, publish the next one alongside it first.", null);
      });

      kids(e, "SPSSODescriptor").forEach(function (d) {
        facts.role = facts.role ? facts.role + " + SP" : "SP";
        checkRole(d, label + " SP");
        var acs = kids(d, "AssertionConsumerService");
        if (!acs.length) add("error", "no-acs", label, "The SP has no AssertionConsumerService endpoint.", META + " §2.4.4");
        acs.forEach(function (s) {
          endpoint(s, label + " AssertionConsumerService");
          if (/HTTP-Redirect$/.test(s.attrs.Binding || "")) add("error", "acs-redirect", label, "An AssertionConsumerService uses the HTTP-Redirect binding. Responses can't be sent that way.", PROF + " §4.1.2");
        });
        kids(d, "SingleLogoutService").forEach(function (s) {
          endpoint(s, label + " SingleLogoutService");
        });
        if (d.attrs.WantAssertionsSigned !== "true") add("warn", "sp-assertions-unsigned", label, "WantAssertionsSigned isn't true. The SP should require signed assertions, not just signed responses, so an assertion lifted out of its response can't be trusted on its own.", META + " §2.4.4");
        if (d.attrs.AuthnRequestsSigned !== "true") add("info", "sp-requests-unsigned", label, "The SP doesn't sign its AuthnRequests.", META + " §2.4.4");
        if (!keys(d, "encryption").length) add("info", "sp-no-encryption-key", label, "The SP publishes no encryption key, so assertions to it can't be encrypted. Fine if nothing sensitive is in them; they pass through the user's browser.", META + " §2.4.1.1");
      });

      if (!kids(e, "IDPSSODescriptor").length && !kids(e, "SPSSODescriptor").length && !kids(e, "AttributeAuthorityDescriptor").length) {
        add("warn", "no-roles", label, "There's no IdP or SP descriptor in this metadata.", META + " §2.3.2");
      }
    }

    function checkRole(d, label) {
      var pse = d.attrs.protocolSupportEnumeration || "";
      if (pse.split(/\s+/).indexOf(PROTOCOL) === -1) add("error", "no-saml2", label, "protocolSupportEnumeration doesn't include SAML 2.0 (" + PROTOCOL + ").", META + " §2.4.1");
      kids(d, "KeyDescriptor").forEach(function () {});
      all(d, "EncryptionMethod").forEach(function (em) {
        var alg = em.attrs.Algorithm || "";
        if (/rsa-1_5$/.test(alg)) add("warn", "md-rsa15", label, "RSA PKCS#1 v1.5 key transport is listed. Use RSA-OAEP.", "W3C XML Encryption 1.1 §5.5.1");
      });
    }

    function keys(d, use) {
      return kids(d, "KeyDescriptor").filter(function (kd) {
        return !kd.attrs.use || kd.attrs.use === use;
      });
    }

    function endpoint(s, label) {
      var loc = s.attrs.Location || "";
      if (!loc) add("error", "endpoint-no-location", label, s.local + " has no Location.", META + " §2.2.2");
      else if (/^http:/i.test(loc) && !/^http:\/\/(localhost|127\.0\.0\.1)/i.test(loc)) add("error", "endpoint-http", label, s.local + " is plain HTTP (" + loc + "). Assertions and requests must travel over TLS.", BIND + " §3.5.5.1; " + SEC + " §6.1");
    }

    return finish(result);
  }

  function unique(a) {
    return a.filter(function (v, i) {
      return a.indexOf(v) === i;
    });
  }
  function shortStatus(v) {
    return String(v || "").replace(/^urn:oasis:names:tc:SAML:2\.0:status:/, "");
  }
  function day(t) {
    return new Date(t).toISOString().slice(0, 10);
  }
  function ago(ms) {
    var s = Math.abs(ms) / 1000;
    if (s < 90) return Math.round(s) + " seconds";
    if (s < 5400) return Math.round(s / 60) + " minutes";
    if (s < 172800) return Math.round(s / 3600) + " hours";
    return Math.round(s / 86400) + " days";
  }

  var ORDER = { error: 0, warn: 1, info: 2 };
  function finish(result) {
    result.findings.sort(function (a, b) {
      return ORDER[a.level] - ORDER[b.level];
    });
    var s = { error: 0, warn: 0, info: 0 };
    result.findings.forEach(function (f) {
      s[f.level]++;
    });
    s.pass = s.error === 0;
    result.summary = s;
    return result;
  }

  // Decode, then check: the one call most callers want.
  function run(input, options) {
    return decode(input).then(function (d) {
      if (d.xml === null || d.xml === "") {
        var r = finish({ kind: null, facts: {}, findings: [{ level: "error", id: "decode", where: null, message: d.error || "Nothing to check.", ref: null }] });
        r.decodedVia = d.via;
        r.xml = null;
        return r;
      }
      var res = check(d.xml, options);
      res.decodedVia = d.via;
      res.xml = d.xml;
      return res;
    });
  }

  // ---- Command line ---------------------------------------------------------

  function cli(argv) {
    var args = argv.slice(2);
    var opts = {};
    var json = false;
    var failOn = "error";
    var target = null;
    for (var i = 0; i < args.length; i++) {
      var a = args[i];
      var v = function () {
        return args[++i];
      };
      if (a === "--sp" || a === "--audience") opts.spEntityId = v();
      else if (a === "--acs") opts.acsUrl = v();
      else if (a === "--idp" || a === "--issuer") opts.idpEntityId = v();
      else if (a === "--skew") opts.skewSeconds = Number(v());
      else if (a === "--max-minutes") opts.maxAssertionMinutes = Number(v());
      else if (a === "--cert-days") opts.certWarnDays = Number(v());
      else if (a === "--now") opts.now = v();
      else if (a === "--fail-on") failOn = v();
      else if (a === "--json") json = true;
      else if (a === "-h" || a === "--help") return help();
      else if (a[0] === "-" && a !== "-") {
        process.stderr.write("Unknown option " + a + "\n");
        process.exit(2);
      } else target = a;
    }
    function go(input) {
      run(input, opts).then(function (r) {
        if (json) {
          var copy = {};
          for (var k in r) if (k !== "xml") copy[k] = r[k];
          process.stdout.write(JSON.stringify(copy, null, 2) + "\n");
        } else {
          if (r.kind) process.stdout.write(r.kind + (r.decodedVia && r.decodedVia !== "XML" ? ", decoded from " + r.decodedVia : "") + "\n\n");
          r.findings.forEach(function (f) {
            var tag = f.level === "error" ? "ERROR" : f.level === "warn" ? "WARN " : "INFO ";
            process.stdout.write(tag + "  " + (f.where ? "[" + f.where + "] " : "") + f.message + (f.ref ? "  (" + f.ref + ")" : "") + "\n");
          });
          process.stdout.write((r.findings.length ? "\n" : "") + r.summary.error + " errors, " + r.summary.warn + " warnings, " + r.summary.info + " notes. Signatures not verified.\n");
        }
        process.exit(r.summary.error > 0 || (failOn === "warn" && r.summary.warn > 0) ? 1 : 0);
      });
    }
    if (target && target !== "-") {
      var fs = require("fs");
      if (fs.existsSync(target)) return go(fs.readFileSync(target, "utf8"));
      if (/^https:\/\//i.test(target)) {
        return fetch(target)
          .then(function (res) {
            if (!res.ok) throw new Error("HTTP " + res.status);
            return res.text();
          })
          .then(go)
          .catch(function (e) {
            process.stderr.write("Couldn't fetch " + target + ": " + e.message + "\n");
            process.exit(2);
          });
      }
      return go(target);
    }
    if (process.stdin.isTTY) return help();
    var buf = "";
    process.stdin.setEncoding("utf8");
    process.stdin.on("data", function (d) {
      buf += d;
    });
    process.stdin.on("end", function () {
      go(buf);
    });
  }

  function help() {
    process.stdout.write(
      [
        "Usage: node saml-check.js <file | metadata-url | base64> [options]",
        "       pbpaste | node saml-check.js --sp https://app.example.com --acs https://app.example.com/saml/acs",
        "",
        "Reviews a SAML response, assertion, AuthnRequest or metadata. Accepts XML,",
        "base64 (POST binding), deflated base64 (Redirect binding) or a SAMLResponse= value.",
        "Exits 1 if any errors are found (or warnings, with --fail-on warn).",
        "",
        "  --sp <entityID>     your service provider's entity ID (checks Audience)",
        "  --acs <url>         your assertion consumer service URL (checks Destination, Recipient)",
        "  --idp <entityID>    the identity provider you trust (checks Issuer)",
        "  --skew <seconds>    clock skew allowed (default 180)",
        "  --max-minutes <n>   warn when an assertion is valid longer than this (default 60)",
        "  --cert-days <n>     warn when a certificate expires within this many days (default 30)",
        "  --now <time>        check as if it were this time (ISO 8601)",
        "  --fail-on warn      also fail on warnings",
        "  --json              print the full result as JSON",
        "",
        "Signatures are not verified and encrypted assertions are not decrypted.",
        "",
      ].join("\n")
    );
  }

  if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
    cli(process.argv);
  }

  return { check: check, decode: decode, run: run, parseXml: parseXml, parseCert: parseCert, defaults: DEFAULTS, cli: cli };
});
