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

  /* ── hero panel dissolve reveal ────────────────────────────
     Hostveil = "host" + "veil": the product panel starts covered by a
     solid veil, which dissolves tile by tile in a diagonal wave to
     reveal the real score/findings markup underneath. The canvas only
     ever draws a cover-and-uncover effect over real HTML that was
     already there — nothing is hidden from a screen reader or a no-JS
     client. Every tile is always in exactly one of three states — solid
     cover, a brief solid accent flash, or fully cleared — so there is
     never a partially-drawn frame that could show a jagged slice of the
     real text underneath. Plays once on load; never loops. */

  var veilCanvas = document.querySelector(".hero-panel .veil-canvas");
  if (veilCanvas && veilCanvas.getContext && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    (function () {
      var panel = veilCanvas.closest(".hero-panel");
      var ctx = veilCanvas.getContext("2d");
      var rootStyle = getComputedStyle(document.documentElement);
      var colorCover = rootStyle.getPropertyValue("--bg").trim();
      var colorAccent = rootStyle.getPropertyValue("--accent").trim();

      var TILE = 15;
      var FLASH = 90;
      var DURATION = 900;
      var width = 0;
      var height = 0;
      var cols = 0;
      var rows = 0;
      var delays = [];
      var rafId = null;
      var startTime = null;
      var finished = false;

      function build() {
        var rect = panel.getBoundingClientRect();
        var dpr = window.devicePixelRatio || 1;
        width = rect.width;
        height = rect.height;
        veilCanvas.width = Math.max(1, Math.round(width * dpr));
        veilCanvas.height = Math.max(1, Math.round(height * dpr));
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

        cols = Math.max(1, Math.ceil(width / TILE));
        rows = Math.max(1, Math.ceil(height / TILE));
        var maxDist = cols + rows;
        delays = [];
        for (var y = 0; y < rows; y++) {
          for (var x = 0; x < cols; x++) {
            // A diagonal wave (distance from the top-left corner) with a
            // little deterministic per-tile jitter, so the dissolve reads
            // as an organic sweep rather than a mechanical grid-scan.
            var jitter = ((x * 928371 + y * 452930) % 17) - 8;
            var dist = Math.max(0, x + y + jitter);
            delays.push((dist / maxDist) * (DURATION - FLASH));
          }
        }
      }

      function drawFrame(elapsed) {
        ctx.clearRect(0, 0, width, height);
        var i = 0;
        for (var y = 0; y < rows; y++) {
          for (var x = 0; x < cols; x++, i++) {
            var t = elapsed - delays[i];
            if (t < 0) {
              ctx.fillStyle = colorCover;
            } else if (t < FLASH) {
              ctx.fillStyle = colorAccent;
            } else {
              continue; // cleared — real panel content shows through
            }
            ctx.fillRect(x * TILE, y * TILE, TILE, TILE);
          }
        }
      }

      function step(now) {
        if (startTime === null) startTime = now;
        var elapsed = now - startTime;
        drawFrame(elapsed);
        if (elapsed < DURATION) {
          rafId = requestAnimationFrame(step);
        } else {
          rafId = null;
          finished = true;
          ctx.clearRect(0, 0, width, height);
        }
      }

      function start() {
        build();
        drawFrame(0);
        startTime = null;
        rafId = requestAnimationFrame(step);
      }

      var resizeTimer = null;
      window.addEventListener("resize", function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () {
          if (rafId) cancelAnimationFrame(rafId);
          finished = true;
          build();
          ctx.clearRect(0, 0, width, height); // skip to the end rather than replay mid-dissolve
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
