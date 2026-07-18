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
})();
