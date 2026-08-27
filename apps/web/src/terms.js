/**
 * Hover tooltips for glossary terms in rendered course HTML.
 *
 * annotateTerms(root) wraps known technical terms in <span data-term-key>
 * markers right after markdown is parsed into DOM. attachTermPopovers()
 * installs ONE document-level popover driven by event delegation, so it
 * survives renderShell()/renderLesson() wiping #app/#main.
 */
import { findTermEntry, buildTermPattern } from "@kernelforge/course-content";

// Matches every glossary surface form (longest first), optionally with a
// trailing plural "s", never inside a larger word. Commands ("!irql") are
// excluded by buildTermPattern — they only ever match whole code elements.
let termRegex = null;
function getTermRegex() {
  if (!termRegex) {
    termRegex = new RegExp(`(?<![\\w$.])(?:${buildTermPattern()})s?(?!\\w)`, "gi");
  }
  return termRegex;
}

const SKIP_SELECTOR = "pre, textarea, select, option, script, style, [data-term-key]";

/** True if node sits inside anything we never annotate. */
function isSkippable(textNode) {
  const parent = textNode.parentElement;
  return !parent || !parent.closest || parent.closest(SKIP_SELECTOR) !== null;
}

/** Split a text node around regex matches, wrapping hits in term markers. */
function annotateTextNode(node) {
  const text = node.data;
  // Reset lastIndex: one shared global regex across many nodes.
  getTermRegex().lastIndex = 0;
  let match;
  let last = 0;
  const frag = document.createDocumentFragment();
  let touched = false;
  while ((match = getTermRegex().exec(text)) !== null) {
    const entry = findTermEntry(match[0]);
    if (!entry) continue;
    touched = true;
    if (match.index > last) frag.append(document.createTextNode(text.slice(last, match.index)));
    frag.append(hTermSpan(entry.key, match[0]));
    last = match.index + match[0].length;
  }
  if (!touched) return;
  if (last < text.length) frag.append(document.createTextNode(text.slice(last)));
  node.replaceWith(frag);
}

function hTermSpan(key, surfaceText) {
  const span = document.createElement("span");
  span.className = "term";
  span.setAttribute("tabindex", "0");
  span.setAttribute("data-term-key", key);
  span.textContent = surfaceText;
  return span;
}

/** Annotate whole inline-code elements when the entire span is a known term. */
function annotateCodeElement(code) {
  if (code.closest("[data-term-key]") || code.dataset.termKey) return;
  const entry = findTermEntry(code.textContent);
  if (!entry) return;
  code.classList.add("term");
  code.setAttribute("data-term-key", entry.key);
}

/**
 * Wrap glossary terms in freshly-rendered HTML. Safe to call repeatedly
 * (annotated regions are skipped by the walker).
 */
export function annotateTerms(root) {
  if (!root || !root.querySelectorAll) return;

  // Whole-code-span terms first (their text is then off-limits below).
  for (const code of root.querySelectorAll("code")) {
    if (!code.closest("pre")) annotateCodeElement(code);
  }

  const walker = document.createTreeWalker(root, window.NodeFilter?.SHOW_TEXT ?? 4, {
    acceptNode: (n) => (isSkippable(n) ? 2 : 1), // FILTER_REJECT : FILTER_ACCEPT
  });
  const nodes = [];
  while (walker.nextNode()) {
    if (walker.currentNode.data.trim()) nodes.push(walker.currentNode);
  }
  for (const n of nodes) annotateTextNode(n);
}

// ------------------------------------------------------------- popover

let attached = false;

/**
 * Install the shared tooltip popover (once per page). Uses delegation on
 * document, so lesson/lab re-renders need no rebinding.
 */
export function attachTermPopovers() {
  if (attached || typeof document === "undefined") return;
  attached = true;

  const pop = document.createElement("div");
  pop.className = "term-popover";
  const nameEl = document.createElement("div");
  nameEl.className = "term-popover-name";
  const fullEl = document.createElement("div");
  fullEl.className = "term-popover-full";
  const defEl = document.createElement("p");
  defEl.className = "term-popover-def";
  pop.append(nameEl, fullEl, defEl);

  let anchor = null;

  function showFor(termEl) {
    const entry = findTermEntry(termEl.getAttribute("data-term-key"));
    if (!entry) return;
    anchor = termEl;
    nameEl.textContent = entry.term;
    fullEl.textContent = entry.full ?? "";
    fullEl.style.display = entry.full ? "" : "none";
    defEl.textContent = entry.def;
    pop.classList.add("open");
    positionNear(termEl);
  }

  function hide() {
    anchor = null;
    pop.classList.remove("open");
  }

  function positionNear(termEl) {
    const rect = termEl.getBoundingClientRect();
    const w = pop.offsetWidth || 320;
    const hgt = pop.offsetHeight || 90;
    const margin = 8;
    let left = rect.left + rect.width / 2 - w / 2;
    left = Math.max(margin, Math.min(left, window.innerWidth - w - margin));
    let top = rect.bottom + 8;
    if (top + hgt > window.innerHeight - margin) top = rect.top - hgt - 8;
    pop.style.left = `${Math.max(margin, Math.round(left))}px`;
    pop.style.top = `${Math.max(margin, Math.round(top))}px`;
  }

  function isElement(t) {
    // Duck-typed instead of `instanceof Element`: DOM shims (happy-dom) may
    // not expose the Element constructor on globals.
    return !!t && typeof t.closest === "function";
  }

  function targetIsLive(t) {
    if (!isElement(t)) return false;
    return t.closest("[data-term-key]") != null || pop.contains(t);
  }

  document.addEventListener("mouseover", (e) => {
    const termEl = e.target?.closest?.("[data-term-key]");
    if (termEl) {
      if (termEl !== anchor) showFor(termEl);
      return;
    }
    // Hovering the popover itself keeps it open (text stays selectable).
    if (!isElement(e.target) || !pop.contains(e.target)) hide();
  });

  document.addEventListener("mouseout", (e) => {
    if (targetIsLive(e.relatedTarget)) return;
    hide();
  });

  document.addEventListener("focusin", (e) => {
    const termEl = e.target?.closest?.("[data-term-key]");
    if (termEl) showFor(termEl);
  });

  document.addEventListener("focusout", () => hide());

  // Touch: tap toggles; tap anywhere else dismisses.
  document.addEventListener("click", (e) => {
    const termEl = e.target?.closest?.("[data-term-key]");
    if (termEl) {
      if (termEl !== anchor) showFor(termEl);
      else hide();
      return;
    }
    if (!isElement(e.target) || !pop.contains(e.target)) hide();
  });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") hide();
  });

  // Fixed positioning drifts when the page scrolls under an open popover.
  document.addEventListener("scroll", () => hide(), true);

  document.body.append(pop);
}
