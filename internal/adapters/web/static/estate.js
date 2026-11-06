// Interactive view of an estate map. It reads /estate/graph.json (same origin, JSON
// strings only) and draws with the vendored d3. Every label is set as text, never as
// markup, and a link is used only if the server built it for this dashboard. Selecting
// a node or a connection loads its record, through htmx, into the sheet (sheet.js opens it).
(function () {
  "use strict";
  var d3 = window.d3;
  if (!d3) { return; }
  var reduced = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var W = 960, H = 480;
  var DENSE = 40; // above this many connections, labels show on hover or focus only

  // Stroke width by corroboration: 1, 2, or 3 and more distinct sources. They are set
  // through the style object (allowed by the CSP), not as markup, so no stylesheet change
  // is needed. A connection whose newest claim is older than 90 days is dashed.
  var WIDTH = { 1: 1.25, 2: 2.5, 3: 4 };
  var STALE_DASH = "6 4";

  drawAll();
  // The kind filter swaps the graph boxes through htmx; draw the new ones.
  document.addEventListener("htmx:afterSwap", drawAll);

  function drawAll() {
    document.querySelectorAll("div.graph[data-src]:not([data-drawn])").forEach(function (box) {
      box.setAttribute("data-drawn", "1");
      load(box);
    });
  }

  function load(box) {
    fetch(box.getAttribute("data-src"), { credentials: "same-origin" })
      .then(function (r) { if (!r.ok) { throw new Error("HTTP " + r.status); } return r.json(); })
      .then(function (g) { draw(box, g); })
      .catch(function (e) {
        box.textContent = "The interactive graph could not be loaded (" + e.message + "). The drawing and the tables below hold the same data.";
        box.classList.add("note");
      });
  }

  // Only the kinds the stylesheet colours get their own class; a service node and any
  // later kind take the neutral one.
  var KNOWN_KINDS = ["asn", "org", "network", "ip", "host", "domain"];
  function kindClass(kind) { return KNOWN_KINDS.indexOf(kind) >= 0 ? "k-" + kind : "k-other"; }
  function safeHref(h, prefix) { return typeof h === "string" && h.indexOf(prefix) === 0 ? h : null; }
  // Ask htmx to load a record into the sheet; without htmx or without the sheet the
  // element stays an ordinary link to the record's page.
  function toSheet(el, href) {
    el.setAttribute("href", href);
    if (window.htmx && document.getElementById("estate-detail")) {
      el.setAttribute("hx-get", href);
      el.setAttribute("hx-target", "#estate-detail");
      el.setAttribute("hx-swap", "innerHTML");
      el.setAttribute("hx-push-url", "false");
      window.htmx.process(el);
    }
  }

  function draw(box, g) {
    var nodes = g.nodes.map(function (n) { return Object.assign({}, n); });
    var links = g.edges.map(function (e) { return Object.assign({}, e); });
    if (nodes.length === 0) {
      box.textContent = g.filtered ? "No node of the chosen kinds." : "";
      return;
    }

    var info = d3.select(box).append("p").attr("class", "note");
    info.text(g.nodeTotal + " nodes, " + g.edgeTotal + " connections, " + g.components + " connected piece(s). Drag a node, scroll to zoom, select a node or a connection label for its record. Line width is the number of distinct sources (1, 2, 3 or more); a dashed line has no claim newer than 90 days." +
      (g.filtered ? " Filtered by node kind: showing " + nodes.length + " of " + g.nodeTotal + " nodes." : "") +
      (g.cut ? " Showing the " + nodes.length + " most connected nodes; the tables list every one." : ""));

    var legend = d3.select(box).append("p").attr("class", "legend");
    Array.from(new Set(nodes.map(function (n) { return n.kind; }))).sort().forEach(function (k) {
      legend.append("span").attr("class", "key " + kindClass(k)).text(k);
    });

    var svg = d3.select(box).append("svg").attr("class", "estate-d3").attr("viewBox", "0 0 " + W + " " + H)
      .attr("role", "img").attr("aria-label", "estate graph " + g.id)
      .classed("sparse-labels", links.length > DENSE);
    var root = svg.append("g");
    var detail = d3.select(box).append("p").attr("class", "detail").attr("aria-live", "polite").text("Hover or focus a node or a connection for its details.");

    var edgeG = root.append("g").selectAll("g").data(links).join("g").attr("class", "edge-g");
    var link = edgeG.append("line").attr("class", "edge").classed("inferred", function (d) { return d.confidence === "inferred"; })
      .style("stroke-width", function (d) { return (WIDTH[d.weight] || WIDTH[1]) + "px"; })
      .style("stroke-dasharray", function (d) { return d.stale ? STALE_DASH : null; });
    var elabel = edgeG.append("a").attr("class", "edge-label").attr("tabindex", 0);
    elabel.append("text").text(function (d) { return d.relation; });
    elabel.each(function (d) {
      var h = safeHref(d.href, "/estate/edge?g=");
      if (h) { toSheet(this, h); }
    });
    function describeEdge(_, d) {
      detail.text("connection " + (d.source.id || d.source) + " -[" + d.relation + "]-> " + (d.target.id || d.target) +
        " (source " + d.sourceName + (d.confidence ? ", " + d.confidence : "") + "; " +
        (d.sources ? d.sources.length : 0) + " distinct source(s): " + (d.sources || []).join(", ") +
        (d.newest ? "; newest claim " + d.newest : "") + (d.stale ? "; stale, older than 90 days" : "") + ")");
    }
    edgeG.on("mouseover", describeEdge);
    elabel.on("focus", describeEdge);

    var node = root.append("g").selectAll("a").data(nodes).join("a").attr("class", function (d) { return "node " + kindClass(d.kind); })
      .attr("tabindex", 0);
    node.each(function (d) {
      var h = safeHref(d.href, "/estate/node?g=");
      if (h) { toSheet(this, h); }
    });
    node.append("circle").attr("r", function (d) { return 5 + Math.min(d.degree, 8); });
    node.append("text").attr("x", 10).attr("y", 4).text(function (d) { return d.label; });
    function describe(_, d) {
      detail.text(d.kind + " " + d.label + " (" + d.id + "), " + d.degree + " connection(s)");
    }
    node.on("mouseover", describe).on("focus", describe);

    var sim = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id(function (d) { return d.id; }).distance(110))
      .force("charge", d3.forceManyBody().strength(-520).distanceMax(420))
      .force("center", d3.forceCenter(W / 2, H / 2))
      .force("x", d3.forceX(W / 2).strength(0.06))
      .force("y", d3.forceY(H / 2).strength(0.12))
      .force("collide", d3.forceCollide(34));

    function ticked() {
      if (!box.isConnected) { sim.stop(); return; } // the filter replaced this drawing
      link.attr("x1", function (d) { return d.source.x; }).attr("y1", function (d) { return d.source.y; })
        .attr("x2", function (d) { return d.target.x; }).attr("y2", function (d) { return d.target.y; });
      elabel.attr("transform", function (d) {
        return "translate(" + (d.source.x + d.target.x) / 2 + "," + ((d.source.y + d.target.y) / 2 - 3) + ")";
      });
      node.attr("transform", function (d) { return "translate(" + d.x + "," + d.y + ")"; });
    }
    if (reduced) { sim.stop(); for (var i = 0; i < 300; i++) { sim.tick(); } ticked(); } else { sim.on("tick", ticked); }

    node.call(d3.drag()
      .on("start", function (e, d) { if (!e.active) { sim.alphaTarget(0.3).restart(); } d.fx = d.x; d.fy = d.y; })
      .on("drag", function (e, d) { d.fx = e.x; d.fy = e.y; if (reduced) { ticked(); } })
      .on("end", function (e, d) { if (!e.active) { sim.alphaTarget(0); } d.fx = null; d.fy = null; }));
    svg.call(d3.zoom().scaleExtent([0.3, 4]).on("zoom", function (e) { root.attr("transform", e.transform); }));

    var fig = box.parentNode.querySelector("figure.static-graph");
    if (fig) { fig.classList.add("hidden"); }
  }
})();
