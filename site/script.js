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

  /* ── hero panel veil reveal ───────────────────────────────
     Hostveil = "host" + "veil": the product panel starts covered by a
     redacted-document overlay, and a scanline sweeps it clear to reveal
     the real score/findings markup underneath. The canvas only ever
     draws a cover-and-uncover effect over real HTML that was already
     there — nothing is hidden from a screen reader or a no-JS client,
     and nothing is redrawn. Plays once on load; never loops. */

  var veilCanvas = document.querySelector(".hero-panel .veil-canvas");
  if (veilCanvas && veilCanvas.getContext && !window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    (function () {
      var panel = veilCanvas.closest(".hero-panel");
      var ctx = veilCanvas.getContext("2d");
      var rootStyle = getComputedStyle(document.documentElement);
      var colorBar = rootStyle.getPropertyValue("--line-strong").trim();
      var colorDanger = rootStyle.getPropertyValue("--danger").trim();
      var colorWarning = rootStyle.getPropertyValue("--warning").trim();
      var colorAccent = rootStyle.getPropertyValue("--accent").trim();
      var colorShadow = rootStyle.getPropertyValue("--shadow-cut").trim();

      var BAR_H = 7;
      var BAR_GAP = 3;
      var DURATION = 950;
      var width = 0;
      var height = 0;
      var rafId = null;
      var startTime = null;
      var finished = false;

      // Deterministic per-row pseudo-random accent, so a resize redraws
      // the same-looking mix of bars rather than reshuffling it.
      function barColor(row) {
        var r = ((row * 2654435761) % 100 + 100) % 100;
        if (r < 10) return colorDanger;
        if (r < 22) return colorWarning;
        return colorBar;
      }

      function size() {
        var rect = panel.getBoundingClientRect();
        var dpr = window.devicePixelRatio || 1;
        width = rect.width;
        height = rect.height;
        veilCanvas.width = Math.max(1, Math.round(width * dpr));
        veilCanvas.height = Math.max(1, Math.round(height * dpr));
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      }

      function drawBars(fromY, toY) {
        var row = Math.floor(fromY / (BAR_H + BAR_GAP));
        for (var y = row * (BAR_H + BAR_GAP); y < toY; y += BAR_H + BAR_GAP) {
          if (y + BAR_H < fromY) continue;
          ctx.fillStyle = barColor(row);
          ctx.fillRect(0, y, width, BAR_H);
          row++;
        }
      }

      function drawFrame(sweepY) {
        ctx.clearRect(0, 0, width, height);
        drawBars(sweepY, height);
        if (sweepY < height) {
          ctx.fillStyle = colorShadow;
          ctx.fillRect(0, sweepY + 2, width, 2);
          ctx.fillStyle = colorAccent;
          ctx.fillRect(0, sweepY, width, 2);
        }
      }

      function step(now) {
        if (startTime === null) startTime = now;
        var t = Math.min(1, (now - startTime) / DURATION);
        var sweepY = t * height;
        drawFrame(sweepY);
        if (t < 1) {
          rafId = requestAnimationFrame(step);
        } else {
          rafId = null;
          finished = true;
          ctx.clearRect(0, 0, width, height);
        }
      }

      function start() {
        size();
        drawFrame(0);
        startTime = null;
        rafId = requestAnimationFrame(step);
      }

      var resizeTimer = null;
      window.addEventListener("resize", function () {
        clearTimeout(resizeTimer);
        resizeTimer = setTimeout(function () {
          if (finished) {
            size(); // stays fully transparent; resizing a canvas clears it
            return;
          }
          if (rafId) cancelAnimationFrame(rafId);
          finished = true;
          size();
          ctx.clearRect(0, 0, width, height); // skip to the end rather than replay mid-sweep
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
