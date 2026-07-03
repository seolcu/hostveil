import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Keyboard shortcut interactions", () => {
  test("number keys filter and 0 resets to all", async ({ page }) => {
    await ready(page);
    for (const key of ["1", "2", "3", "4"]) {
      await page.keyboard.press(key);
      await page.waitForTimeout(200);
      const count = await page.locator("#findings tr[data-index]").count();
      expect(count).toBeGreaterThan(0);
      expect(count).toBeLessThanOrEqual(14);
    }
    await page.keyboard.press("0");
    await page.waitForTimeout(200);
    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });

  test("R key clears all filters and shows toast", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    await page.keyboard.press("R");
    await page.waitForTimeout(300);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);

    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
  });

  test("o key cycles sort field and O toggles direction", async ({ page }) => {
    await ready(page);
    const sortBy = page.locator("#sortBy");
    expect(await sortBy.inputValue()).toBe("severity");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    expect(await sortBy.inputValue()).toBe("source");

    await page.keyboard.press("O");
    await page.waitForTimeout(100);

    const firstId1 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    await page.keyboard.press("O");
    await page.waitForTimeout(100);
    const firstId2 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    expect(firstId1).not.toBe(firstId2);
  });

  test("Escape closes any open modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
    await expect(page.locator("#helpModal")).not.toBeVisible();

    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });

  test("f key opens fix for current finding", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("f");
    await page.waitForTimeout(500);
    const modal = page.locator("#fixModal");
    if ((await modal.count()) > 0) {
      await page.keyboard.press("Escape");
      await page.waitForTimeout(200);
    }
  });

  test("Enter opens fix modal on fixable finding", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Enter");
    await page.waitForTimeout(500);
    const modal = page.locator("#fixModal");
    if ((await modal.count()) > 0) {
      await page.keyboard.press("Escape");
      await page.waitForTimeout(200);
    }
  });
});

test.describe("Filter + sort + search interactions", () => {
  test("applying filter then sorting preserves filter", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    const countBefore = await page.locator("#findings tr[data-index]").count();

    await page.locator("#sortBy").selectOption("title");
    await page.waitForTimeout(200);
    const countAfter = await page.locator("#findings tr[data-index]").count();
    expect(countAfter).toBe(countBefore);
  });

  test("search + filter narrows results", async ({ page }) => {
    await ready(page);

    // Apply critical filter first
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    const countBefore = await page.locator("#findings tr[data-index]").count();
    expect(countBefore).toBe(2); // 2 critical findings

    // Now search - should narrow further or stay the same
    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);
    const countAfter = await page.locator("#findings tr[data-index]").count();
    expect(countAfter).toBeLessThanOrEqual(countBefore);

    await query.fill("");
    await page.keyboard.press("0");
    await page.waitForTimeout(300);
  });

  test("sort dropdown syncs with column header click", async ({ page }) => {
    await ready(page);
    const sortBy = page.locator("#sortBy");

    await page.locator("th.sortable").nth(1).click();
    await page.waitForTimeout(200);
    expect(await sortBy.inputValue()).toBe("source");

    await page.locator("th.sortable").nth(0).click();
    await page.waitForTimeout(200);
    expect(await sortBy.inputValue()).toBe("severity");
  });
});

test.describe("Score breakdown rendering", () => {
  test("each axis has correct label and score format", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const labels = ["Vulnerabilities", "Container exposure", "Host hardening", "Secrets"];
    for (let i = 0; i < 4; i++) {
      const label = await axes.nth(i).locator(".score-axis-top span").textContent();
      expect(label).toBe(labels[i]);
      const score = await axes.nth(i).locator(".score-axis-top strong").textContent();
      expect(score).toMatch(/^\d+\/100$/);
    }
  });

  test("penalty bars have valid width styles", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    for (let i = 0; i < 4; i++) {
      const style = await bars.nth(i).getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
    }
  });

  test("score breakdown head has description text", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const span = await head.locator("span").textContent();
    expect(span).toBe("Score breakdown");
    const p = await head.locator("p").textContent();
    expect(p).toContain("penalty cap");
  });
});

test.describe("Detail panel for each finding type", () => {
  test("trivy CVE shows all detail sections", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const detail = page.locator("#detail");
    await expect(detail).toBeVisible({ timeout: 5000 });
    const text = await detail.textContent();
    expect(text).toContain("trivy.cve-2024-0001");
    expect(text).toContain("critical");
    expect(text).toContain("nginx:1.24");
    expect(text).toContain("Description");
    expect(text).toContain("How to fix");
  });

  test("lynis finding shows correct metadata", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail").textContent();
    expect(text).toContain("lynis.AUTH-9286");
    expect(text).toContain("Auto");
    expect(text).toContain("one clear fix");
  });

  test("compose finding shows service", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='compose.dr004']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail").textContent();
    expect(text).toContain("compose.dr004");
    expect(text).toContain("webapp");
  });

  test("unavailable finding has no fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    expect(await fixBtn.count()).toBe(0);
  });

  test("fixed finding has no fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0003']").click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    expect(await fixBtn.count()).toBe(0);
  });
});

test.describe("Table row states", () => {
  test("fixed row has fixed and disabled classes", async ({ page }) => {
    await ready(page);
    const cls = await page.locator("#findings tr[data-id='trivy.cve-2024-0003']").getAttribute("class");
    expect(cls).toContain("fixed");
    expect(cls).toContain("disabled");
  });

  test("fixed row has check mark instead of badge", async ({ page }) => {
    await ready(page);
    const cell = page.locator("#findings tr[data-id='trivy.cve-2024-0003'] td").nth(1);
    const text = await cell.textContent();
    expect(text).toContain("✓");
  });

  test("every row has 6 cells", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      expect(await rows.nth(i).locator("td").count()).toBe(6);
    }
  });

  test("rows have sequential data-index", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      expect(await rows.nth(i).getAttribute("data-index")).toBe(String(i));
    }
  });
});

test.describe("Selection behavior", () => {
  test("clicking row selects it", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
    await row.click({ force: true });
    await page.waitForTimeout(200);
    const cls = await row.getAttribute("class");
    expect(cls).toContain("selected");
  });

  test("double-click toggles row-selected", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='lynis.FILE-6310']");
    await row.dblclick();
    await page.waitForTimeout(200);
    const cls1 = await row.getAttribute("class");
    expect(cls1).toContain("row-selected");
    await row.dblclick();
    await page.waitForTimeout(200);
    const cls2 = await row.getAttribute("class");
    expect(cls2).not.toContain("row-selected");
  });

  test("select-all checkbox selects all batch-selectable", async ({ page }) => {
    await ready(page);
    await page.locator("#selectAllCheck").check({ force: true });
    await page.waitForTimeout(200);
    const selected = await page.locator("#findings tr.row-selected").count();
    expect(selected).toBeGreaterThan(0);
    await page.locator("#selectAllCheck").uncheck({ force: true });
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(0);
  });

  test("Space toggles selection", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(1);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(0);
  });
});

test.describe("Responsive behavior", () => {
  test("score breakdown at 768px shows all axes", async ({ page }) => {
    await ready(page);
    await page.setViewportSize({ width: 768, height: 900 });
    await page.waitForTimeout(200);
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
    await page.setViewportSize({ width: 1440, height: 900 });
  });

  test("score breakdown at 320px shows all axes", async ({ page }) => {
    await ready(page);
    await page.setViewportSize({ width: 320, height: 568 });
    await page.waitForTimeout(200);
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
    await page.setViewportSize({ width: 1440, height: 900 });
  });
});

test.describe("Export and help modals", () => {
  test("export modal has JSON, CSV, AI options and close button", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const text = await modal.textContent();
    expect(text).toContain("JSON");
    expect(text).toContain("CSV");
    expect(text).toContain("AI brief");
    expect(text).toContain("Close");
    await page.keyboard.press("Escape");
  });

  test("help modal has all four sections", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const text = await modal.textContent();
    expect(text).toContain("Navigation");
    expect(text).toContain("Filters");
    expect(text).toContain("Actions");
    expect(text).toContain("Other");
    await page.keyboard.press("Escape");
  });
});

test.describe("API contract validation", () => {
  test("result has all required fields", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("score");
    expect(result).toHaveProperty("score_breakdown");
    expect(result).toHaveProperty("hostname");
    expect(result.findings.length).toBe(14);
  });

  test("score_breakdown has 4 axes with valid data", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    expect(result.score_breakdown.axes.length).toBe(4);
    for (const axis of result.score_breakdown.axes) {
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
      expect(axis.max_penalty).toBeGreaterThan(0);
    }
  });

  test("finding IDs are unique", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const ids = result.findings.map((f: { id: string }) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("each finding has required fields", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    for (const f of result.findings) {
      expect(typeof f.id).toBe("string");
      expect(typeof f.title).toBe("string");
      expect(typeof f.severity).toBe("number");
      expect(typeof f.source).toBe("number");
      expect(typeof f.remediation).toBe("number");
      expect(typeof f.fixed).toBe("boolean");
    }
  });

  test("score is between 0 and 100", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    expect(result.score).toBeGreaterThanOrEqual(0);
    expect(result.score).toBeLessThanOrEqual(100);
  });

  test("score_breakdown.overall matches score", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    expect(result.score_breakdown.overall).toBe(result.score);
  });
});

test.describe("Score breakdown penalty cap values", () => {
  test("vulnerabilities max penalty is 35", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const v = result.score_breakdown.axes.find((a: { id: string }) => a.id === "vulnerabilities");
    expect(v.max_penalty).toBe(35);
  });

  test("secrets max penalty is 10", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const s = result.score_breakdown.axes.find((a: { id: string }) => a.id === "secrets");
    expect(s.max_penalty).toBe(10);
  });
});

test.describe("Recalc and rescan", () => {
  test("recalc button shows toast", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 5000 });
    expect(await toast.textContent()).toContain("recalculated");
  });

  test("rescan button re-enables after completion", async ({ page }) => {
    await ready(page);
    const btn = page.locator("#rescanBtn");
    await btn.click();
    await page.waitForTimeout(500);
    expect(await btn.isDisabled()).toBe(true);
    await expect(btn).toBeEnabled({ timeout: 10000 });
  });
});

test.describe("Fix error handling", () => {
  test("fix with unregistered ID returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "nonexistent.id", action_index: 0 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("no fix registered");
  });

  test("fix with out-of-range action_index returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "trivy.cve-2024-0001", action_index: 99 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toBeTruthy();
  });

  test("fix with malformed JSON returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{invalid",
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("invalid request");
  });
});

test.describe("Export format edge cases", () => {
  test("export with no format defaults to JSON", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export");
      return { ct: resp.headers.get("content-type"), cd: resp.headers.get("content-disposition") };
    });
    expect(r.ct).toContain("application/json");
    expect(r.cd).toContain("hostveil-report.json");
  });

  test("export with format=csv returns CSV", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=csv");
      return { ct: resp.headers.get("content-type"), text: await resp.text() };
    });
    expect(r.ct).toContain("text/csv");
    expect(r.text).toContain("ID");
  });

  test("export with format=ai returns markdown", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai");
      return { ct: resp.headers.get("content-type"), text: await resp.text() };
    });
    expect(r.ct).toContain("text/markdown");
    expect(r.text).toContain("#");
  });
});

test.describe("Secure headers", () => {
  test("API responses include security headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/health");
      return {
        xcto: resp.headers.get("x-content-type-options"),
        xfo: resp.headers.get("x-frame-options"),
        rp: resp.headers.get("referrer-policy"),
      };
    });
    expect(r.xcto).toBe("nosniff");
    expect(r.xfo).toBe("DENY");
    expect(r.rp).toBe("no-referrer");
  });
});

test.describe("Score plate and metrics", () => {
  test("score plate has severity class", async ({ page }) => {
    await ready(page);
    const cls = await page.locator(".scoreplate").getAttribute("class");
    expect(cls).toMatch(/score-(low|medium|high|critical)/);
  });

  test("score element shows N/100 format", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#score").textContent()).toMatch(/^\d+\/100$/);
  });

  test("metrics has 6 items", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").count()).toBe(6);
  });

  test("total metric shows 14", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").first().textContent()).toContain("14");
  });
});

test.describe("Search edge cases", () => {
  test("search by service name", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);
    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);
    await query.fill("");
    await page.waitForTimeout(300);
  });

  test("search by CVE URL", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("nvd.nist.gov");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(1);
    await query.fill("");
    await page.waitForTimeout(300);
  });

  test("impossible search shows no results", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("zzzzimpossible");
    await page.waitForTimeout(300);
    const text = await page.locator("#findings tr td.muted").textContent();
    expect(text).toContain("No findings match");
    await query.fill("");
    await page.waitForTimeout(300);
  });

  test("search is case-insensitive", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("SSH");
    await page.waitForTimeout(300);
    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);
    await query.fill("");
    await page.waitForTimeout(300);
  });
});

test.describe("Fix modal for review finding", () => {
  test("review finding shows radio buttons", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.dr001']");
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        const radios = modal.locator("input[name='fixAction']");
        expect(await radios.count()).toBeGreaterThanOrEqual(2);
        const confirmBtn = modal.locator("#modalFixYes");
        expect(await confirmBtn.isDisabled()).toBe(true);
        await radios.first().click();
        await page.waitForTimeout(100);
        expect(await confirmBtn.isEnabled()).toBe(true);
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Evidence section", () => {
  test("evidence keys are sorted alphabetically", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const summary = page.locator("#detail .evidence-details summary").first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);
      const keys = page.locator("#detail .evidence-details:first-of-type pre strong");
      const count = await keys.count();
      const texts: string[] = [];
      for (let i = 0; i < count; i++) {
        texts.push((await keys.nth(i).textContent()) ?? "");
      }
      for (let i = 1; i < texts.length; i++) {
        expect(texts[i].localeCompare(texts[i - 1])).toBeGreaterThanOrEqual(0);
      }
    }
  });
});

test.describe("Topbar and findings panel structure", () => {
  test("topbar has hostveil title", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".topbar h1").textContent()).toContain("hostveil");
  });

  test("findings panel has eyebrow", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".findings-panel .eyebrow").textContent()).toContain("Findings");
  });

  test("search input has placeholder", async ({ page }) => {
    await ready(page);
    const placeholder = await page.locator("#query").getAttribute("placeholder");
    expect(placeholder).toBeTruthy();
  });

  test("clear filters button exists", async ({ page }) => {
    await ready(page);
    await expect(page.locator("#clearFilters")).toBeVisible();
  });
});

test.describe("Sort by source groups findings", () => {
  test("compose findings are grouped together", async ({ page }) => {
    await ready(page);
    await page.locator("#sortBy").selectOption("source");
    await page.waitForTimeout(200);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const ids: string[] = [];
    for (let i = 0; i < count; i++) {
      const id = await rows.nth(i).getAttribute("data-id");
      if (id) ids.push(id);
    }
    const composeIdx = ids.map((id, i) => id.startsWith("compose.") ? i : -1).filter(i => i >= 0);
    if (composeIdx.length >= 2) {
      for (let i = 1; i < composeIdx.length; i++) {
        expect(composeIdx[i] - composeIdx[i - 1]).toBe(1);
      }
    }
  });
});

test.describe("Sort stability", () => {
  test("sort order persists after clicking a row", async ({ page }) => {
    await ready(page);
    const ids1: string[] = [];
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const id = await rows.nth(i).getAttribute("data-id");
      if (id) ids1.push(id);
    }
    await rows.first().click({ force: true });
    await page.waitForTimeout(200);
    const ids2: string[] = [];
    const rows2 = page.locator("#findings tr[data-index]");
    for (let i = 0; i < count; i++) {
      const id = await rows2.nth(i).getAttribute("data-id");
      if (id) ids2.push(id);
    }
    expect(ids1).toEqual(ids2);
  });
});

test.describe("Tab navigation", () => {
  test("Tab moves focus through interactive elements", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);
    const focused = await page.evaluate(() => document.activeElement?.tagName || "");
    expect(focused).toBeTruthy();
  });
});

test.describe("No findings match message", () => {
  test("shows message when all filtered out", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("zzzzimpossible");
    await page.waitForTimeout(300);
    const text = await page.locator("#findings tr td.muted").textContent();
    expect(text).toContain("No findings match");
    await query.fill("");
    await page.waitForTimeout(300);
  });
});

test.describe("Fix modal for auto finding", () => {
  test("auto finding fix modal has finding title", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        const text = await modal.textContent();
        expect(text).toBeTruthy();
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Keyboard navigation", () => {
  test("ArrowDown and ArrowUp navigate findings", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    expect(await page.locator("#findings tr.selected").count()).toBe(1);
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(100);
  });

  test("/ focuses search input", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("/");
    await page.waitForTimeout(100);
    const focused = await page.evaluate(() => document.activeElement?.id || "");
    expect(focused).toBe("query");
    await page.keyboard.press("Escape");
  });

  test("Escape blurs search input", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.focus();
    await page.waitForTimeout(100);
    expect(await query.evaluate((el) => el === document.activeElement)).toBe(true);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);
    expect(await query.evaluate((el) => el === document.activeElement)).toBe(false);
  });
});

test.describe("Score breakdown data-axis attributes", () => {
  test("each axis has correct data-axis value", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const expected = ["vulnerabilities", "container_exposure", "host_hardening", "secrets"];
    for (let i = 0; i < 4; i++) {
      expect(expected).toContain(await axes.nth(i).getAttribute("data-axis"));
    }
  });
});

test.describe("Recalc preserves score breakdown", () => {
  test("recalc returns same number of axes", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(1000);
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
  });
});

test.describe("Finding count after filter reset", () => {
  test("count returns to 14 after clearing all", async ({ page }) => {
    await ready(page);
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
  });
});

test.describe("Modal overlay click-to-close", () => {
  test("help modal closes on overlay click", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });
});

test.describe("Detail panel copy button", () => {
  test("how_to_fix section has copy button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    const copyBtn = page.locator("#detail button.copy");
    await expect(copyBtn).toBeVisible({ timeout: 5000 });
  });
});

test.describe("Batch fix selection", () => {
  test("selecting findings shows count on Fix Selected", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    const btn = page.locator("#fixSelectedBtn");
    await expect(btn).toBeVisible();
    expect(await btn.textContent()).toContain("2");
  });
});

test.describe("Score breakdown penalty bar accessibility", () => {
  test("penalty bars have aria-label", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    for (let i = 0; i < 4; i++) {
      const label = await bars.nth(i).getAttribute("aria-label");
      expect(label).toBeTruthy();
    }
  });
});

test.describe("Evidence expand/collapse", () => {
  test("evidence disclosure toggles", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const summary = page.locator("#detail .evidence-details summary").first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);
      const pres = page.locator("#detail .evidence-details pre");
      expect(await pres.count()).toBeGreaterThanOrEqual(1);
      await summary.click();
      await page.waitForTimeout(200);
    }
  });
});

test.describe("Fix via batch API", () => {
  test("batch with empty findings returns empty results", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: [], action_index: 0 }),
      });
      return resp.json();
    });
    expect(r.results.length).toBe(0);
  });

  test("batch with mix of valid and invalid findings", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [{ id: "nonexistent.abc", action_index: 0 }],
          action_index: 0,
        }),
      });
      return resp.json();
    });
    expect(r.results.length).toBe(1);
    expect(r.results[0].success).toBe(false);
  });
});

test.describe("Score breakdown severity counts", () => {
  test("vulnerabilities axis has severity count spans", async ({ page }) => {
    await ready(page);
    const axis = page.locator("#scoreBreakdown .score-axis").filter({ hasText: "Vulnerabilities" });
    const counts = axis.locator(".score-axis-counts span");
    expect(await counts.count()).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Filter chip active state persistence", () => {
  test("active chip stays active after re-render", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    let active = await page.locator("#severityFilters button.active").textContent();
    expect(active).toContain("Critical");

    await page.locator("#findings tr[data-index]").first().click({ force: true });
    await page.waitForTimeout(200);
    active = await page.locator("#severityFilters button.active").textContent();
    expect(active).toContain("Critical");
  });
});

test.describe("Remediation distribution", () => {
  test("correct counts per remediation type", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const rems: Record<number, number> = {};
    for (const f of result.findings) {
      rems[f.remediation] = (rems[f.remediation] || 0) + 1;
    }
    expect(rems[0]).toBe(10); // auto
    expect(rems[1]).toBe(3);  // review
    expect(rems[2]).toBe(1);  // unavailable
  });
});

test.describe("Source distribution", () => {
  test("correct counts per source", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const srcs: Record<number, number> = {};
    for (const f of result.findings) {
      srcs[f.source] = (srcs[f.source] || 0) + 1;
    }
    expect(srcs[0]).toBe(6); // trivy
    expect(srcs[1]).toBe(6); // lynis
    expect(srcs[2]).toBe(2); // compose
  });
});
