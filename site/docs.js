/* hostveil docs — copy-to-clipboard, mobile sidebar, active link.
   Standalone (does NOT touch the landing-page lightbox). */
(function () {
  "use strict";

  /* ── copy-to-clipboard ────────────────────────────────── */

  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".copy-btn");
    if (!btn) return;
    var text = btn.getAttribute("data-copy");
    if (!text || !navigator.clipboard) return;
    navigator.clipboard.writeText(text).then(function () {
      btn.textContent = "Copied";
      btn.classList.add("copied");
      setTimeout(function () {
        btn.textContent = "Copy";
        btn.classList.remove("copied");
      }, 1500);
    });
  });

  /* ── mobile sidebar toggle ────────────────────────────── */

  var toggle = document.querySelector(".docs-sidebar-toggle");
  var sidebar = document.getElementById("docs-sidebar");

  function isMobile() {
    return window.matchMedia("(max-width: 900px)").matches;
  }

  function syncSidebar() {
    if (!toggle || !sidebar) return;
    if (isMobile()) {
      var open = toggle.getAttribute("aria-expanded") === "true";
      sidebar.hidden = !open;
    } else {
      sidebar.hidden = false;
    }
  }

  if (toggle && sidebar) {
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("aria-expanded") === "true";
      toggle.setAttribute("aria-expanded", String(!open));
      sidebar.hidden = open;
    });
    window.addEventListener("resize", syncSidebar);
    syncSidebar();
  }

  /* ── active link highlight ────────────────────────────── */
  /* Mark the sidebar link matching the current page. Robust to both
     extensionless (/docs/installation) and .html (/docs/installation.html)
     forms, and to the directory index (/docs/ or /docs/index). */

  function pageKey(path) {
    return path
      .replace(/\/index(\.html)?$/, "/") // treat /docs/index[.html] as the dir
      .replace(/\.html$/, "")            // drop a trailing .html
      .split("/")
      .pop() || "index";                 // "" (dir root) -> "index"
  }

  var here = pageKey(location.pathname);
  document.querySelectorAll(".docs-nav-group a").forEach(function (a) {
    var href = a.getAttribute("href") || "";
    var target = pageKey(href.replace(/\/$/, "/index")); // "./" or "" -> index
    if (target === here) {
      a.classList.add("active");
      a.setAttribute("aria-current", "page");
    } else {
      a.classList.remove("active");
    }
  });

  /* ── search ───────────────────────────────────────────── */
  /* Index is built at runtime from the pages listed in the sidebar
     (fetched once, cached in sessionStorage) so it never goes stale. */

  var sInput = document.getElementById("docs-search-input");
  var sResults = document.getElementById("docs-search-results");

  if (sInput && sResults) {
    var INDEX = null;
    var building = null;
    var active = -1;

    function pages() {
      var seen = {};
      var out = [];
      document.querySelectorAll(".docs-nav-group a").forEach(function (a) {
        var url = a.getAttribute("href") || "";
        var key = pageKey(url.replace(/\/$/, "/index"));
        if (seen[key]) return;
        seen[key] = true;
        out.push({ url: url, title: a.textContent.trim(), current: key === here });
      });
      return out;
    }

    function records(doc, page) {
      var prose = doc.querySelector(".docs-prose");
      if (!prose) return [];
      var recs = [];
      var cur = null;
      Array.prototype.forEach.call(prose.children, function (node) {
        var tag = (node.tagName || "").toLowerCase();
        if (tag === "h1" || tag === "h2" || tag === "h3") {
          if (cur) recs.push(cur);
          cur = { title: page.title, url: page.url, heading: node.textContent.trim(), anchor: node.id || "", text: "" };
        } else {
          if (!cur) cur = { title: page.title, url: page.url, heading: page.title, anchor: "", text: "" };
          cur.text += " " + (node.textContent || "");
        }
      });
      if (cur) recs.push(cur);
      return recs;
    }

    function build() {
      if (INDEX) return Promise.resolve(INDEX);
      if (building) return building;
      try {
        var cached = sessionStorage.getItem("hv-docs-index");
        if (cached) {
          INDEX = JSON.parse(cached);
          return Promise.resolve(INDEX);
        }
      } catch (e) { /* ignore */ }
      building = Promise.all(pages().map(function (p) {
        if (p.current) return Promise.resolve(records(document, p));
        return fetch(p.url)
          .then(function (r) { return r.ok ? r.text() : ""; })
          .then(function (html) {
            return html ? records(new DOMParser().parseFromString(html, "text/html"), p) : [];
          })
          .catch(function () { return []; });
      })).then(function (all) {
        INDEX = all.reduce(function (a, b) { return a.concat(b); }, []);
        try { sessionStorage.setItem("hv-docs-index", JSON.stringify(INDEX)); } catch (e) { /* ignore */ }
        return INDEX;
      });
      return building;
    }

    function esc(s) {
      return String(s).replace(/[&<>"]/g, function (c) {
        return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c];
      });
    }

    function query(q) {
      var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
      if (!terms.length || !INDEX) return [];
      var out = [];
      INDEX.forEach(function (r) {
        var hay = (r.title + " " + r.heading + " " + r.text).toLowerCase();
        if (!terms.every(function (t) { return hay.indexOf(t) >= 0; })) return;
        var score = 0;
        terms.forEach(function (t) {
          if (r.title.toLowerCase().indexOf(t) >= 0) score += 3;
          if (r.heading.toLowerCase().indexOf(t) >= 0) score += 5;
          if (r.text.toLowerCase().indexOf(t) >= 0) score += 1;
        });
        out.push({ r: r, score: score });
      });
      return out
        .sort(function (a, b) { return b.score - a.score; })
        .slice(0, 8)
        .map(function (x) { return x.r; });
    }

    function close() {
      sResults.hidden = true;
      sResults.innerHTML = "";
      sInput.setAttribute("aria-expanded", "false");
      sInput.removeAttribute("aria-activedescendant");
      active = -1;
    }

    function render(items) {
      active = -1;
      if (!sInput.value.trim()) { close(); return; }
      if (!items.length) {
        sResults.innerHTML = '<li class="docs-search-empty">No matches</li>';
      } else {
        sResults.innerHTML = items.map(function (r, i) {
          var href = r.url + (r.anchor ? "#" + r.anchor : "");
          var sub = r.heading && r.heading !== r.title ? r.title : "In this section";
          return '<li role="option" id="ds-opt-' + i + '">' +
            '<a href="' + esc(href) + '"><strong>' + esc(r.heading) + "</strong>" +
            "<span>" + esc(sub) + "</span></a></li>";
        }).join("");
      }
      sResults.hidden = false;
      sInput.setAttribute("aria-expanded", "true");
    }

    function move(delta) {
      var opts = sResults.querySelectorAll('li[role="option"]');
      if (!opts.length) return;
      Array.prototype.forEach.call(opts, function (o) { o.classList.remove("active"); });
      active = (active + delta + opts.length) % opts.length;
      var el = opts[active];
      el.classList.add("active");
      sInput.setAttribute("aria-activedescendant", el.id);
      el.scrollIntoView({ block: "nearest" });
    }

    sInput.addEventListener("focus", build);

    sInput.addEventListener("input", function () {
      var q = sInput.value;
      if (!q.trim()) { close(); return; }
      build().then(function () {
        if (sInput.value === q) render(query(q));
      });
    });

    sInput.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") { e.preventDefault(); move(1); }
      else if (e.key === "ArrowUp") { e.preventDefault(); move(-1); }
      else if (e.key === "Enter") {
        var links = sResults.querySelectorAll('li[role="option"] a');
        var pick = active >= 0 ? links[active] : links[0];
        if (pick) { e.preventDefault(); window.location.href = pick.getAttribute("href"); }
      } else if (e.key === "Escape") {
        if (!sResults.hidden) { e.preventDefault(); close(); }
        else { sInput.value = ""; }
      }
    });

    document.addEventListener("click", function (e) {
      if (!e.target.closest(".docs-search")) close();
    });
  }
})();
