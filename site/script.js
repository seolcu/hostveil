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
})();
