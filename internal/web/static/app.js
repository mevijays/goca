// goca portal - small progressive enhancements only. Every page works without
// JavaScript; this adds copy buttons, confirmations and form toggles.

(function () {
  "use strict";

  // Copy-to-clipboard buttons for PEM blocks and secrets.
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    ev.preventDefault();
    var sel = btn.getAttribute("data-copy");
    var el = document.querySelector(sel);
    if (!el) return;
    var text = el.value !== undefined ? el.value : el.textContent;
    var done = function () {
      var old = btn.textContent;
      btn.textContent = "copied";
      setTimeout(function () { btn.textContent = old; }, 1400);
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, fallback);
    } else {
      fallback();
    }
    function fallback() {
      var ta = document.createElement("textarea");
      ta.value = text;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand("copy"); done(); } catch (e) { /* ignore */ }
      document.body.removeChild(ta);
    }
  });

  // Destructive actions ask first.
  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      ev.preventDefault();
    }
  });

  // Request form: switch between "generate a key for me" and "I have a CSR".
  var modeInputs = document.querySelectorAll("input[name=mode]");
  function applyMode() {
    var mode = document.querySelector("input[name=mode]:checked");
    if (!mode) return;
    document.querySelectorAll("[data-mode]").forEach(function (el) {
      var want = el.getAttribute("data-mode").split(" ");
      el.hidden = want.indexOf(mode.value) === -1;
      // Disable every field in a hidden section, not just required ones -
      // otherwise a same-named field left over from another mode (e.g. two
      // modes each having their own "Display name" box) gets submitted
      // alongside the one actually in use, and the server reads whichever
      // came first in the form rather than the one you filled in.
      el.querySelectorAll("input, select, textarea").forEach(function (input) {
        input.disabled = el.hidden;
      });
    });
  }
  modeInputs.forEach(function (el) { el.addEventListener("change", applyMode); });
  if (modeInputs.length) applyMode();

  // CA form: parent selector only matters for intermediates.
  var kindInputs = document.querySelectorAll("input[name=ca_kind]");
  function applyKind() {
    var kind = document.querySelector("input[name=ca_kind]:checked");
    if (!kind) return;
    document.querySelectorAll("[data-kind]").forEach(function (el) {
      el.hidden = el.getAttribute("data-kind").split(" ").indexOf(kind.value) === -1;
    });
  }
  kindInputs.forEach(function (el) { el.addEventListener("change", applyKind); });
  if (kindInputs.length) applyKind();

  // Keep the search box focused on list pages for quick filtering.
  var q = document.querySelector("[data-autofocus]");
  if (q) q.focus();

  // Bulk selection on the certificate list.
  var selectAll = document.querySelector("[data-select-all]");
  var rowBoxes = Array.prototype.slice.call(document.querySelectorAll("[data-row-select]"));
  var bulkBar = document.querySelector("[data-bulk-bar]");
  var bulkCount = document.querySelector("[data-bulk-count]");

  function refreshBulk() {
    var n = rowBoxes.filter(function (b) { return b.checked; }).length;
    if (bulkCount) bulkCount.textContent = String(n);
    if (bulkBar) bulkBar.hidden = n === 0;
    if (selectAll) {
      selectAll.checked = n > 0 && n === rowBoxes.length;
      selectAll.indeterminate = n > 0 && n < rowBoxes.length;
    }
  }
  if (selectAll) {
    selectAll.addEventListener("change", function () {
      rowBoxes.forEach(function (b) { b.checked = selectAll.checked; });
      refreshBulk();
    });
  }
  rowBoxes.forEach(function (b) { b.addEventListener("change", refreshBulk); });
  if (rowBoxes.length) refreshBulk();

  // Bulk buttons carry their own confirmation, since the submit handler above
  // only knows about the form, not which button was pressed.
  document.querySelectorAll("[data-confirm-bulk]").forEach(function (btn) {
    btn.addEventListener("click", function (ev) {
      var n = rowBoxes.filter(function (b) { return b.checked; }).length;
      var msg = btn.getAttribute("data-confirm-bulk") + "\n\n" + n + " certificate(s) selected.";
      if (!window.confirm(msg)) ev.preventDefault();
    });
  });
})();
