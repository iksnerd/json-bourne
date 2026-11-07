// Export of the graph as drawn. The file is built in the browser from the drawing on the
// page and handed to the browser as a download; nothing is sent anywhere and no route
// serves it. A kind or confidence filter has already changed what is drawn, so the file
// holds what the person sees (a node faded by the search is still drawn, so it is kept).
//
//   SVG   one file per drawn map: a standalone copy of the drawing, with the colours the
//         stylesheet gave it written onto the elements, because a file has no stylesheet
//   JSON  one file for all drawn maps: the nodes and edges with their record fields, and
//         the filters in force
//
// Only attributes and text are set: never markup from a string, never a style attribute.
(function () {
  "use strict";
  var svgBtn = document.getElementById("estate-export-svg");
  var jsonBtn = document.getElementById("estate-export-json");
  var status = document.getElementById("estate-export-status");
  var graphs = document.getElementById("estate-graphs");
  if (!svgBtn || !jsonBtn || !graphs) { return; }
  svgBtn.removeAttribute("hidden");
  jsonBtn.removeAttribute("hidden");

  var NS = "http://www.w3.org/2000/svg";
  var KEEP = ["x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "d", "transform", "viewBox", "width", "height"];
  var STYLES = ["fill", "stroke", "stroke-width", "stroke-dasharray", "opacity", "font-size", "font-family", "letter-spacing", "text-anchor", "text-transform", "paint-order"];

  function drawn() { return Array.from(graphs.querySelectorAll("svg.estate-d3")); }
  function say(text) { status.textContent = text; }
  function idOf(svg) { return (svg.getAttribute("aria-label") || "estate graph").replace(/^estate graph /, ""); }
  function fileName(id, ext) {
    return "estate-" + (id.replace(/[^A-Za-z0-9_-]+/g, "_").slice(0, 60) || "graph") + "." + ext;
  }

  // A copy of src as a new SVG element tree. An a (a link to a record page, useless in a
  // file) becomes a g; the styles the page gave the element are written as attributes.
  function copy(src) {
    var tag = src.localName === "a" ? "g" : src.localName;
    var out = document.createElementNS(NS, tag);
    KEEP.forEach(function (k) { if (src.hasAttribute(k)) { out.setAttribute(k, src.getAttribute(k)); } });
    if (src.localName !== "svg" && src.localName !== "g" && src.localName !== "a") {
      var cs = window.getComputedStyle(src);
      STYLES.forEach(function (p) {
        var v = cs.getPropertyValue(p);
        if (v && v !== "normal" && v !== "none") { out.setAttribute(p, v); }
      });
    }
    if (src.localName === "text") {
      out.textContent = src.textContent;
      return out;
    }
    Array.from(src.children).forEach(function (c) { out.appendChild(copy(c)); });
    return out;
  }

  function svgFile(svg) {
    var out = copy(svg);
    out.setAttribute("xmlns", NS);
    var bg = document.createElementNS(NS, "rect");
    bg.setAttribute("width", "100%");
    bg.setAttribute("height", "100%");
    bg.setAttribute("fill", window.getComputedStyle(svg).backgroundColor || "#fff");
    out.insertBefore(bg, out.firstChild);
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + new XMLSerializer().serializeToString(out) + "\n";
  }

  function endId(e) { return typeof e === "object" && e !== null ? e.id : e; }
  function jsonOf(svg) {
    var box = svg.closest("div.graph");
    var q = new URLSearchParams((box && box.getAttribute("data-src") || "").split("?")[1] || "");
    var d3 = window.d3;
    var nodes = [], edges = [];
    svg.querySelectorAll("a.node").forEach(function (el) {
      var d = d3 ? d3.select(el).datum() : null;
      if (d) { nodes.push({ id: d.id, kind: d.kind, label: d.label, degree: d.degree }); }
    });
    svg.querySelectorAll("g.edge-g").forEach(function (el) {
      var d = d3 ? d3.select(el).datum() : null;
      if (d) {
        edges.push({ from: endId(d.source), to: endId(d.target), relation: d.relation, confidence: d.confidence,
          source: d.sourceName, sources: d.sources, newest: d.newest, stale: !!d.stale, weight: d.weight });
      }
    });
    return { id: idOf(svg), filters: { kind: q.getAll("kind"), confidence: q.getAll("confidence") }, nodes: nodes, edges: edges };
  }

  function save(name, type, text) {
    var url = URL.createObjectURL(new Blob([text], { type: type }));
    var a = document.createElement("a");
    a.setAttribute("href", url);
    a.setAttribute("download", name);
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  svgBtn.addEventListener("click", function () {
    var list = drawn();
    if (list.length === 0) { say("Nothing is drawn yet."); return; }
    list.forEach(function (svg) { save(fileName(idOf(svg), "svg"), "image/svg+xml", svgFile(svg)); });
    say("Saved " + list.length + " SVG file(s).");
  });
  jsonBtn.addEventListener("click", function () {
    var list = drawn();
    if (list.length === 0) { say("Nothing is drawn yet."); return; }
    var doc = { exported: "the graph as drawn on the estate page; an opinion is not part of it", graphs: list.map(jsonOf) };
    save("estate-graph.json", "application/json", JSON.stringify(doc, null, 2) + "\n");
    say("Saved the JSON of " + list.length + " map(s).");
  });
})();
