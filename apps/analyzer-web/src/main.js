import "../../web/src/styles.css";
import "@kernelforge/debugger-ui/styles.css";
import { renderAnalyzer } from "../../web/src/analyzer.js";

const app = document.getElementById("app");

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs ?? {})) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null) el.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c == null) continue;
    el.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return el;
}

function renderShell() {
  app.innerHTML = "";
  const header = h("header", null,
    h("span", { class: "logo" }, "⚒ KernelForge — Analyzers"),
    h("span", { class: "spacer" }),
    h("span", { class: "dim", style: "font-size:12px" }, "Driver Analyzer · Linux Analyzer"),
  );
  app.append(header, h("div", { id: "layout" },
    h("aside", { id: "sidebar" }),
    h("main", { id: "main" }),
  ));
  renderSidebar();
  renderWelcome();
}

function renderSidebar() {
  const sidebar = document.getElementById("sidebar");
  sidebar.innerHTML = "";
  sidebar.append(h("h2", null, "Tools"));
  const analyzerBtn = h("button", {
    class: "tool",
    onclick: () => renderAnalyzer(document.getElementById("main")),
  }, "⚒ Driver Analyzer (.sys)");
  sidebar.append(analyzerBtn);
  const linuxAnalyzerBtn = h("button", {
    class: "tool",
    onclick: async () => {
      const { renderLinuxAnalyzer } = await import("../../web/src/linux-analyzer.js");
      renderLinuxAnalyzer(document.getElementById("main"));
    },
  }, "🐧 Linux Driver Analyzer (.ko)");
  sidebar.append(linuxAnalyzerBtn);

  sidebar.append(h("div", { class: "dim", style: "margin:16px 4px 8px;font-size:12px;line-height:1.5" },
    "Standalone analyzer deployment — no course lessons, no flags. Upload any x64 .sys or .ko, run DriverEntry/init_module, drive IOCTLs/file_ops, fuzz + concolic + Find Bugs. All client-side."
  ));
  const backLink = h("a", { href: "https://kernelforge-3kd.pages.dev", target: "_blank", class: "dim", style: "margin:8px 4px;font-size:12px;display:block" }, "→ Full KernelForge class →");
  sidebar.append(backLink);
}

function renderWelcome() {
  const main = document.getElementById("main");
  main.innerHTML = "";
  main.append(
    h("div", { class: "card" },
      h("h1", null, "Driver Analyzers"),
      h("p", null, "Upload any x64 Windows driver (.sys) or Linux LKM (.ko) — it is manual-mapped into the emulated kernel, every import resolves (modeled or stubbed), DriverEntry/init_module runs under SEH, deferred work drains, and you can drive MajorFunction/file_operations with scripted IOCTLs. All client-side; nothing leaves this tab."),
      h("p", { class: "dim" }, "Pick a tool from the sidebar. For the full course labs (DKOM, IRQL, hooks, pool, SMM, Sauer, v86), visit the class site."),
    ),
    h("div", { class: "card" },
      h("h2", null, "Quick start"),
      h("ul", null,
        h("li", null, "Windows: Driver Analyzer → pick .sys → Load & run DriverEntry → Send IOCTL / Auto-drive IRPs → Find Bugs"),
        h("li", null, "Linux: Linux Analyzer → pick .ko → Load & run init_module → Send FileOp / Auto-drive ops → Find Bugs"),
      ),
    ),
  );
  // auto-open analyzer for convenience? keep welcome first
}

(async function init() {
  renderShell();
})();
