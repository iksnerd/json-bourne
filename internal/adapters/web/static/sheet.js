// Sheet: the behaviour of the sheet primitive (primitives.templ). It knows nothing about
// the page that uses it; everything it needs is in data attributes.
//
//   [data-sheet]                    the dialog; data-state is "open" or "closed"
//   [data-sheet-open="<id>"]        a trigger that opens it (gets aria-controls, aria-expanded)
//   [data-sheet-close]              a control inside it that closes it
//   sheet:open / sheet:close        events a script can dispatch on the sheet
//   htmx:afterSwap into the sheet   opens it, so a record loaded into it is shown
//
// Non-modal (data-modal="false"): the page stays usable; Escape closes; focus moves in on
// open and is restored on close. Modal (data-modal="true"): in addition an overlay, a
// focus trap, the rest of the page inert, and no scrolling behind. A closed sheet is
// inert: it can be neither focused nor read.
(function () {
  "use strict";

  var FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
  var openSheets = [];            // the stack, innermost last
  var inerted = new Map();        // element -> its previous inert value, while a modal is open

  function sheetOf(id) { var el = document.getElementById(id); return el && el.hasAttribute("data-sheet") ? el : null; }
  function isOpen(el) { return el.getAttribute("data-state") === "open"; }
  function overlayOf(el) { return document.querySelector('[data-sheet-overlay="' + CSS.escape(el.id) + '"]'); }
  function triggersOf(el) { return document.querySelectorAll('[data-sheet-open="' + CSS.escape(el.id) + '"]'); }
  function visible(el) { return !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length); }

  function syncTriggers(el, open) {
    triggersOf(el).forEach(function (t) {
      t.setAttribute("aria-controls", el.id);
      t.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  function setState(el, open) {
    el.setAttribute("data-state", open ? "open" : "closed");
    if (open) { el.removeAttribute("inert"); } else { el.setAttribute("inert", ""); }
    var ov = overlayOf(el);
    if (ov) { ov.setAttribute("data-state", open ? "open" : "closed"); }
    syncTriggers(el, open);
  }

  // A modal makes everything outside it inert and stops the page scrolling.
  function lockPage(el) {
    var root = el.closest("[data-sheet-root]");
    Array.from(document.body.children).forEach(function (c) {
      if (c === root || c.tagName === "SCRIPT") { return; }
      if (!inerted.has(c)) { inerted.set(c, c.hasAttribute("inert")); c.setAttribute("inert", ""); }
    });
    document.documentElement.classList.add("sheet-scroll-lock");
  }
  function unlockPage() {
    inerted.forEach(function (was, c) { if (!was) { c.removeAttribute("inert"); } });
    inerted.clear();
    document.documentElement.classList.remove("sheet-scroll-lock");
  }

  function open(el, opener) {
    if (isOpen(el)) { return; }
    el.__opener = opener || document.activeElement;
    setState(el, true);
    openSheets.push(el);
    if (el.getAttribute("data-modal") === "true") { lockPage(el); }
    // Move focus into the sheet: the close control, which is always there.
    var first = el.querySelector("[data-sheet-close]") || el;
    first.focus({ preventScroll: true });
    el.dispatchEvent(new CustomEvent("sheet:opened", { bubbles: true }));
  }

  function close(el) {
    if (!isOpen(el)) { return; }
    // Focus leaves the sheet before it becomes inert, or the browser drops it to <body>.
    var back = el.__opener;
    el.__opener = null;
    setState(el, false);
    openSheets = openSheets.filter(function (s) { return s !== el; });
    if (el.getAttribute("data-modal") === "true" && !openSheets.some(function (s) { return s.getAttribute("data-modal") === "true"; })) { unlockPage(); }
    if (back && document.contains(back) && !back.hasAttribute("inert") && typeof back.focus === "function") { back.focus({ preventScroll: true }); }
    el.dispatchEvent(new CustomEvent("sheet:closed", { bubbles: true }));
  }

  document.addEventListener("click", function (e) {
    var t = e.target instanceof Element ? e.target : null;
    if (!t) { return; }
    var trig = t.closest("[data-sheet-open]");
    if (trig) {
      var el = sheetOf(trig.getAttribute("data-sheet-open"));
      if (el) { e.preventDefault(); open(el, trig); }
      return;
    }
    var x = t.closest("[data-sheet-close]");
    if (x) { var host = x.closest("[data-sheet]"); if (host) { close(host); } return; }
    var ov = t.closest("[data-sheet-overlay]");
    if (ov) { var s = sheetOf(ov.getAttribute("data-sheet-overlay")); if (s) { close(s); } }
  });

  document.addEventListener("keydown", function (e) {
    var top = openSheets[openSheets.length - 1];
    if (!top) { return; }
    if (e.key === "Escape") { e.preventDefault(); close(top); return; }
    // The focus trap, for a modal sheet only.
    if (e.key === "Tab" && top.getAttribute("data-modal") === "true") {
      var items = Array.from(top.querySelectorAll(FOCUSABLE)).filter(visible);
      if (items.length === 0) { e.preventDefault(); top.focus(); return; }
      var first = items[0], last = items[items.length - 1], active = document.activeElement;
      if (e.shiftKey && (active === first || active === top)) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && active === last) { e.preventDefault(); first.focus(); }
      else if (!top.contains(active)) { e.preventDefault(); first.focus(); }
    }
  });

  // Content swapped in by htmx opens the sheet it landed in.
  document.body.addEventListener("htmx:afterSwap", function (e) {
    var t = e.detail && e.detail.target;
    var el = t && t.closest ? t.closest("[data-sheet]") : null;
    if (el) { open(el, document.activeElement); }
  });

  document.addEventListener("sheet:open", function (e) { if (e.target.hasAttribute && e.target.hasAttribute("data-sheet")) { open(e.target); } });
  document.addEventListener("sheet:close", function (e) { if (e.target.hasAttribute && e.target.hasAttribute("data-sheet")) { close(e.target); } });

  // Triggers describe the state they control from the start.
  document.querySelectorAll("[data-sheet]").forEach(function (el) { syncTriggers(el, isOpen(el)); });
})();
