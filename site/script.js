/* hostveil landing page — copy-to-clipboard + lightbox */
(function () {
  "use strict";

  var KO = document.documentElement.lang === "ko";
  var T = {
    copy: KO ? "복사" : "Copy",
    copied: KO ? "복사됨" : "Copied",
  };

  /* ── copy-to-clipboard ────────────────────────────────── */

  document.addEventListener("click", function (e) {
    var btn = e.target.closest(".copy-btn");
    if (!btn) return;
    var text = btn.getAttribute("data-copy");
    if (!text) return;
    navigator.clipboard.writeText(text).then(function () {
      btn.textContent = T.copied;
      btn.classList.add("copied");
      setTimeout(function () {
        btn.textContent = T.copy;
        btn.classList.remove("copied");
      }, 1500);
    });
  });

  /* ── lightbox ─────────────────────────────────────────── */

  var overlay = document.getElementById("lightbox");
  var lbImg = document.getElementById("lightbox-img");
  var lbCaption = document.getElementById("lightbox-caption");
  var lastFocused = null;

  // Prepare overlay for focus management
  overlay.tabIndex = -1;
  overlay.setAttribute("aria-modal", "true");

  // All body children except the lightbox — makes background inert when open
  var inertTargets = Array.from(document.body.children).filter(function (el) {
    return el !== overlay;
  });

  function openLightbox(card) {
    var img = card.querySelector("img");
    var strong = card.querySelector("figcaption strong");
    var span = card.querySelector("figcaption span");
    if (!img) return;

    lastFocused = card;

    lbImg.src = img.src;
    lbImg.alt = img.alt;
    lbCaption.innerHTML =
      (strong ? "<strong>" + strong.textContent + "</strong>" : "") +
      (span ? span.textContent : "");

    overlay.classList.add("active");
    overlay.setAttribute("aria-hidden", "false");

    // Make background inert
    inertTargets.forEach(function (el) {
      if (el) el.setAttribute("inert", "");
    });

    document.body.style.overflow = "hidden";
    overlay.focus();
  }

  function closeLightbox() {
    overlay.classList.remove("active");
    overlay.setAttribute("aria-hidden", "true");

    // Remove inert from background
    inertTargets.forEach(function (el) {
      if (el) el.removeAttribute("inert");
    });

    document.body.style.overflow = "";

    // Restore focus to the element that opened the lightbox
    if (lastFocused) {
      lastFocused.focus();
      lastFocused = null;
    }
  }

  /* ── event handlers ───────────────────────────────────── */

  document.addEventListener("click", function (e) {
    var card = e.target.closest(".screenshot-card");
    if (card) {
      openLightbox(card);
      return;
    }
    if (e.target === overlay || e.target.closest(".lightbox-content") === null) {
      closeLightbox();
    }
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape" && overlay.classList.contains("active")) {
      closeLightbox();
      return;
    }

    // Trap Tab inside lightbox when open
    if (e.key === "Tab" && overlay.classList.contains("active")) {
      var focusable = overlay.querySelectorAll("img, button, [tabindex]");
      if (focusable.length === 0) return;
      var first = focusable[0];
      var last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  });

  /* keyboard activation for screenshot cards */
  document.querySelectorAll(".screenshot-card").forEach(function (card) {
    card.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        openLightbox(card);
      }
    });
  });

  /* ── hero scan canvas ─────────────────────────────────────
     Illustrative only: cell outcomes/ratios below are not the real
     Auto/Review/Manual fix split (see docs/checks for that) — this is a
     decorative echo of "scan finds issues, hostveil resolves most of them,"
     drawn with the site's real severity colors. Plays once on load; never
     loops. */

  var heroCanvas = document.getElementById("hero-scan");
  if (heroCanvas && heroCanvas.getContext) {
    (function () {
      var ctx = heroCanvas.getContext("2d");
      var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      var rootStyle = getComputedStyle(document.documentElement);
      var colorDanger = rootStyle.getPropertyValue("--danger").trim();
      var colorWarning = rootStyle.getPropertyValue("--warning").trim();
      var colorSignal = rootStyle.getPropertyValue("--signal").trim();
      var colorLine = rootStyle.getPropertyValue("--line").trim();

      var CELL = 36;
      var GAP = 5;
      var SWEEP = 1500;
      var cells = [];
      var rafId = null;
      var startTime = null;

      // Deterministic per-index pseudo-random outcome, so a resize (which
      // rebuilds the grid at a new size) redraws the same-looking mix
      // rather than reshuffling it.
      function outcomeFor(i) {
        var r = ((i * 2654435761) % 100 + 100) % 100;
        if (r < 55) return "dim";
        if (r < 72) return "warning";
        return "signal";
      }

      function buildGrid() {
        var rect = heroCanvas.getBoundingClientRect();
        var dpr = window.devicePixelRatio || 1;
        heroCanvas.width = Math.max(1, Math.round(rect.width * dpr));
        heroCanvas.height = Math.max(1, Math.round(rect.height * dpr));
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        var cols = Math.max(1, Math.floor(rect.width / CELL));
        var rows = Math.max(1, Math.floor(rect.height / CELL));
        cells = [];
        var i = 0;
        for (var y = 0; y < rows; y++) {
          for (var x = 0; x < cols; x++) {
            cells.push({
              x: x,
              y: y,
              outcome: outcomeFor(i),
              delay: (i * 37) % (SWEEP * 0.6),
              flash: 130 + ((i * 53) % 160),
            });
            i++;
          }
        }
      }

      function colorForOutcome(outcome) {
        if (outcome === "warning") return colorWarning;
        if (outcome === "signal") return colorSignal;
        return null; // "dim" cells never fill, only outline
      }

      function stateColorAt(cell, elapsed) {
        var t = elapsed - cell.delay;
        if (t < 0) return null;
        if (cell.outcome === "dim") return null;
        if (t < cell.flash) {
          return cell.outcome === "signal" ? colorDanger : colorWarning;
        }
        return colorForOutcome(cell.outcome);
      }

      function drawFrame(elapsed) {
        ctx.clearRect(0, 0, heroCanvas.width, heroCanvas.height);
        for (var i = 0; i < cells.length; i++) {
          var cell = cells[i];
          var px = cell.x * CELL;
          var py = cell.y * CELL;
          var size = CELL - GAP;
          var fill = stateColorAt(cell, elapsed);
          if (fill) {
            ctx.fillStyle = fill;
            ctx.fillRect(px, py, size, size);
          } else {
            ctx.strokeStyle = colorLine;
            ctx.lineWidth = 1;
            ctx.strokeRect(px + 0.5, py + 0.5, size - 1, size - 1);
          }
        }
      }

      function settledDuration() {
        return SWEEP * 0.6 + 160 + 160 + 40; // last cell's delay + flash + margin
      }

      function step(now) {
        if (startTime === null) startTime = now;
        var elapsed = now - startTime;
        drawFrame(elapsed);
        if (elapsed < settledDuration()) {
          rafId = requestAnimationFrame(step);
        } else {
          rafId = null;
        }
      }

      function start() {
        buildGrid();
        if (reduceMotion) {
          drawFrame(settledDuration() + 1); // final state, no animation ever runs
          return;
        }
        startTime = null;
        if (rafId) cancelAnimationFrame(rafId);
        rafId = requestAnimationFrame(step);
      }

      var resizeTimer = null;
      window.addEventListener("resize", function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () {
          buildGrid();
          drawFrame(settledDuration() + 1); // redraw settled state only, never replay the sweep
        }, 150);
      });

      start();
    })();
  }

  /* ── ledger bar grow-in ───────────────────────────────────
     A real measurement, not decoration: the bar fills to a width set on
     the element itself, driven purely by CSS transition once .in-view is
     added. */

  var ledgerBars = document.querySelectorAll(".ledger-bar");
  if (ledgerBars.length) {
    var reduceMotionBars = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (reduceMotionBars || !("IntersectionObserver" in window)) {
      ledgerBars.forEach(function (bar) {
        bar.classList.add("in-view");
      });
    } else {
      var barObserver = new IntersectionObserver(
        function (entries) {
          entries.forEach(function (entry) {
            if (entry.isIntersecting) {
              entry.target.classList.add("in-view");
              barObserver.unobserve(entry.target);
            }
          });
        },
        { threshold: 0.4 }
      );
      ledgerBars.forEach(function (bar) {
        barObserver.observe(bar);
      });
    }
  }
})();
