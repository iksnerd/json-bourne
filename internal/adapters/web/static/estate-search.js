// Search across the nodes of the estate maps on the page. It reads only what the page
// already holds (the drawn nodes: their label and id), sends no request and writes no
// markup: it sets text, an opacity and a stroke width through the style object, which the
// CSP allows.
//
//   typing        keeps the nodes whose id or label contains the text (case-insensitive)
//                 at full strength and fades the others
//   "/"           focuses the box (unless a field already has focus)
//   Escape        clears the box (and keeps the sheet open: it stops there)
//   ArrowDown/Right, ArrowUp/Left
//                 move focus to the next or previous matching node, from the box or from a node
(function () {
  "use strict";
  var box = document.getElementById("estate-search");
  var status = document.getElementById("estate-search-status");
  var graphs = document.getElementById("estate-graphs");
  if (!box || !graphs) { return; }
  box.removeAttribute("hidden");

  function nodes() { return Array.from(graphs.querySelectorAll("svg.estate-d3 a.node")); }
  function textOf(el) {
    var d = window.d3 ? window.d3.select(el).datum() : null;
    var label = d && typeof d.label === "string" ? d.label : (el.textContent || "");
    var id = d && typeof d.id === "string" ? d.id : "";
    return (label + "\n" + id).toLowerCase();
  }
  function matching() {
    var q = box.value.trim().toLowerCase();
    return nodes().filter(function (el) { return q === "" || textOf(el).indexOf(q) >= 0; });
  }

  function apply() {
    var q = box.value.trim().toLowerCase();
    var all = nodes();
    var hits = 0;
    all.forEach(function (el) {
      var hit = q === "" || textOf(el).indexOf(q) >= 0;
      if (hit) { hits++; }
      el.style.opacity = hit ? "" : "0.15";
      var c = el.querySelector("circle");
      if (c) { c.style.strokeWidth = q !== "" && hit ? "5px" : ""; }
    });
    status.textContent = q === "" ? "" : hits + " of " + all.length + " nodes match.";
  }

  function step(from, dir) {
    var list = matching();
    if (list.length === 0) { return; }
    var i = list.indexOf(from);
    var next = i < 0 ? (dir > 0 ? 0 : list.length - 1) : (i + dir + list.length) % list.length;
    list[next].focus();
  }

  box.addEventListener("input", apply);
  box.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      e.stopPropagation(); // sheet.js listens on the document; clearing is all this does
      if (box.value !== "") { box.value = ""; apply(); } else { box.blur(); }
    } else if (e.key === "ArrowDown" || e.key === "ArrowRight" && box.selectionStart === box.value.length) {
      e.preventDefault(); step(null, 1);
    } else if (e.key === "ArrowUp") {
      e.preventDefault(); step(null, -1);
    }
  });

  document.addEventListener("keydown", function (e) {
    if (e.defaultPrevented || e.ctrlKey || e.metaKey || e.altKey) { return; }
    var t = e.target instanceof Element ? e.target : null;
    var typing = t && (t.closest("input, textarea, select") || t.isContentEditable);
    if (e.key === "/" && !typing) { e.preventDefault(); box.focus(); box.select(); return; }
    var node = t && t.closest ? t.closest("a.node") : null;
    if (!node || !graphs.contains(node)) { return; }
    if (e.key === "ArrowDown" || e.key === "ArrowRight") { e.preventDefault(); step(node, 1); }
    else if (e.key === "ArrowUp" || e.key === "ArrowLeft") { e.preventDefault(); step(node, -1); }
    else if (e.key === "Escape" && box.value !== "") { box.value = ""; apply(); }
  });

  // The filters swap the graph boxes and estate.js draws new nodes later; mark those too.
  var pending = false;
  new MutationObserver(function () {
    if (pending) { return; }
    pending = true;
    requestAnimationFrame(function () { pending = false; apply(); });
  }).observe(graphs, { childList: true, subtree: true });
  document.addEventListener("htmx:afterSwap", function () { apply(); });
})();
