/* hostveil — suggest the Korean version to Korean-locale visitors.
   Non-intrusive banner, no forced redirect. Loaded on English pages only. */
(function () {
  "use strict";

  var DISMISS_KEY = "hv-lang-suggest-dismissed";

  // Already on a /ko/ page? Nothing to suggest.
  if (location.pathname.indexOf("/ko/") === 0) return;

  // Does the visitor prefer Korean?
  var langs = navigator.languages || [navigator.language || ""];
  var prefersKo = langs.some(function (l) {
    return /^ko\b/i.test(l || "");
  });
  if (!prefersKo) return;

  // Respect a prior dismissal.
  try {
    if (localStorage.getItem(DISMISS_KEY) === "1") return;
  } catch (e) { /* ignore */ }

  // Korean counterpart of the current page.
  var koHref = "/ko" + location.pathname + location.search + location.hash;

  function dismiss() {
    try { localStorage.setItem(DISMISS_KEY, "1"); } catch (e) { /* ignore */ }
    if (banner.parentNode) banner.parentNode.removeChild(banner);
  }

  var banner = document.createElement("div");
  banner.className = "lang-suggest";
  banner.setAttribute("role", "region");
  banner.setAttribute("aria-label", "언어 안내");

  var msg = document.createElement("span");
  msg.textContent = "이 페이지는 한국어로도 볼 수 있습니다.";

  var link = document.createElement("a");
  link.href = koHref;
  link.textContent = "한국어로 보기 →";
  link.addEventListener("click", function () {
    try { localStorage.setItem(DISMISS_KEY, "1"); } catch (e) { /* ignore */ }
  });

  var close = document.createElement("button");
  close.type = "button";
  close.textContent = "✕";
  close.setAttribute("aria-label", "닫기");
  close.addEventListener("click", dismiss);

  banner.appendChild(msg);
  banner.appendChild(link);
  banner.appendChild(close);

  document.body.insertBefore(banner, document.body.firstChild);
})();
