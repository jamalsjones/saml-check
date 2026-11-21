(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  // The sample responses were written for 15:00 UTC on 20 Nov 2026. Shift
  // their times to now so they read as fresh. Certificates keep their dates.
  var SAMPLE_BASE = Date.parse("2026-11-20T15:00:30Z");
  function shiftTimes(xml) {
    var delta = Date.now() - SAMPLE_BASE;
    return xml.replace(/(Instant|NotBefore|NotOnOrAfter)="(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ)"/g, function (all, attr, t) {
      return attr + '="' + new Date(Date.parse(t) + delta).toISOString().replace(/\.\d{3}Z$/, "Z") + '"';
    });
  }

  document.querySelectorAll("[data-sample]").forEach(function (b) {
    b.addEventListener("click", function () {
      var name = b.getAttribute("data-sample");
      fetch("examples/" + name).then(function (r) { return r.text(); }).then(function (t) {
        $("input").value = /^response/.test(name) ? shiftTimes(t) : t;
        $("sp").value = "https://payroll.example.com/saml";
        $("acs").value = "https://payroll.example.com/saml/acs";
        $("idp").value = name === "response-good.xml" ? "https://login.example.com" : "";
        go();
      });
    });
  });

  function go() {
    SamlCheck.run($("input").value, {
      spEntityId: $("sp").value.trim() || null,
      acsUrl: $("acs").value.trim() || null,
      idpEntityId: $("idp").value.trim() || null,
    }).then(render);
  }

  function row(dl, k, v) {
    if (v == null || v === "" || (Array.isArray(v) && !v.length)) return;
    dl.appendChild(el("dt", null, k));
    dl.appendChild(el("dd", null, Array.isArray(v) ? v.join(", ") : String(v)));
  }

  function render(r) {
    var out = $("results");
    out.textContent = "";
    out.appendChild(el("p", "label", "Findings"));
    if (r.kind) out.appendChild(el("p", "kind", r.kind + (r.decodedVia && r.decodedVia !== "XML" ? ", decoded from " + r.decodedVia : "")));

    var sum = el("div", "summary");
    if (r.summary.error === 0) sum.appendChild(el("span", "count ok", "No errors"));
    else sum.appendChild(el("span", "count error", r.summary.error + (r.summary.error === 1 ? " error" : " errors")));
    if (r.summary.warn) sum.appendChild(el("span", "count warn", r.summary.warn + (r.summary.warn === 1 ? " warning" : " warnings")));
    if (r.summary.info) sum.appendChild(el("span", "count info", r.summary.info + (r.summary.info === 1 ? " note" : " notes")));
    out.appendChild(sum);

    var ul = el("ul", "findings");
    r.findings.forEach(function (f) {
      var li = el("li", "finding " + f.level);
      var head = el("div", "head");
      head.appendChild(el("span", "lvl", f.level === "warn" ? "warning" : f.level === "info" ? "note" : "error"));
      if (f.where) head.appendChild(el("code", null, f.where));
      li.appendChild(head);
      li.appendChild(el("p", null, f.message));
      if (f.ref) li.appendChild(el("div", "ref", f.ref));
      ul.appendChild(li);
    });
    out.appendChild(ul);

    var x = r.facts || {};
    var dl = el("dl", "facts");
    row(dl, "Entity ID", x.entityId);
    row(dl, "Role", x.role);
    row(dl, "Issuer", x.issuer);
    row(dl, "NameID", x.nameId);
    row(dl, "NameID format", x.nameIdFormat && x.nameIdFormat.replace(/^urn:oasis:names:tc:SAML:\d\.\d:nameid-format:/, ""));
    row(dl, "Audience", x.audience);
    row(dl, "Valid", x.notBefore || x.notOnOrAfter ? (x.notBefore || "?") + " to " + (x.notOnOrAfter || "?") : null);
    row(dl, "Sign-in method", x.authnContext && x.authnContext.replace(/urn:oasis:names:tc:SAML:2\.0:ac:classes:/g, ""));
    (x.attributes || []).forEach(function (a) {
      row(dl, a.friendlyName || a.name, a.values);
    });
    (x.certificates || []).forEach(function (c) {
      row(dl, "Certificate", (c.subject ? "CN=" + c.subject + ", " : "") + c.keyType + (c.keyBits ? " " + c.keyBits + "-bit" : "") + ", expires " + new Date(c.notAfter).toISOString().slice(0, 10) + " (" + c.where + ")");
    });
    if (dl.children.length) {
      var l = el("p", "label", "What's inside");
      l.style.marginTop = "18px";
      out.appendChild(l);
      out.appendChild(dl);
    }
    if (r.xml && r.decodedVia !== "XML") {
      var d = el("details");
      d.appendChild(el("summary", null, "Decoded XML"));
      var pre = el("pre", "json", r.xml);
      pre.style.marginTop = "8px";
      d.appendChild(pre);
      out.appendChild(d);
    }
  }

  $("check").addEventListener("click", go);
})();
