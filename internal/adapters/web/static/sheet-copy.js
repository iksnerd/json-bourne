// Copy the node sheet as plain text, for pasting into a report. It reads only what the page
// already shows (the text of #sheet-record), sends no request and writes no markup.
//
//   #sheet-copy          the button; hidden in the markup, shown here, so without script
//                        there is no control that does nothing
//   #sheet-record        the record that is copied
//   #sheet-copy-status   where the result is said (a live region)
//
// The clipboard API is tried first. Where it is missing or refuses (an insecure origin, a
// denied permission), a textarea is filled, selected and copied with execCommand, then
// removed. The textarea is placed off-screen through the style object, which the CSP allows.
(function () {
  "use strict";

  function clean(s) { return (s || "").replace(/\s+/g, " ").trim(); }

  function walk(el, out) {
    Array.from(el.children).forEach(function (c) {
      if (c.hasAttribute("hidden")) { return; }
      var tag = c.tagName.toLowerCase();
      if (/^h[1-6]$/.test(tag)) {
        var t = clean(c.textContent);
        if (t) { out.push("", "#".repeat(Math.min(parseInt(tag.charAt(1), 10) + 1, 4)) + " " + t); }
      } else if (tag === "table") {
        Array.from(c.rows).forEach(function (tr) {
          var cells = Array.from(tr.cells).map(function (td) { return clean(td.textContent); });
          if (cells.some(function (x) { return x !== ""; })) { out.push(cells.join(" | ")); }
        });
      } else if (tag === "ul" || tag === "ol") {
        Array.from(c.children).forEach(function (li) {
          var t = clean(li.textContent);
          if (t) { out.push("- " + t); }
        });
      } else if (tag === "p" || tag === "li" || tag === "pre") {
        var p = clean(c.textContent);
        if (p) { out.push(p); }
      } else if (c.children.length === 0) {
        var x = clean(c.textContent);
        if (x) { out.push(x); }
      } else {
        walk(c, out);
      }
    });
  }

  function plainText() {
    var rec = document.getElementById("sheet-record");
    if (!rec) { return ""; }
    var out = [];
    walk(rec, out);
    return out.join("\n").replace(/^\n+/, "") + "\n";
  }

  function say(msg) {
    var st = document.getElementById("sheet-copy-status");
    if (st) { st.textContent = msg; }
  }

  function viaTextarea(text) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.setAttribute("aria-hidden", "true");
    ta.style.position = "fixed";
    ta.style.left = "-9999px";
    ta.style.top = "0";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    return ok;
  }

  function copy() {
    var text = plainText();
    if (text.trim() === "") { say("Nothing to copy."); return; }
    function fallback() {
      say(viaTextarea(text) ? "Copied as plain text." : "Copying was refused by the browser. Select the record and copy it by hand.");
    }
    if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
      navigator.clipboard.writeText(text).then(function () { say("Copied as plain text."); }, fallback);
    } else {
      fallback();
    }
  }

  // A swap puts a new, hidden button into the page: show it again.
  function reveal() {
    Array.from(document.querySelectorAll("#sheet-copy")).forEach(function (b) { b.removeAttribute("hidden"); });
  }

  document.addEventListener("click", function (e) {
    var t = e.target instanceof Element ? e.target.closest("#sheet-copy") : null;
    if (t) { e.preventDefault(); copy(); }
  });
  document.addEventListener("htmx:afterSwap", reveal);
  reveal();
})();
