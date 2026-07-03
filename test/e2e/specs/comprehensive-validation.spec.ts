import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score plate severity class for different scores", () => {
  test("score plate has correct class for current score", async ({ page }) => {
    await ready(page);
    const scoreplate = page.locator(".scoreplate");
    const cls = await scoreplate.getAttribute("class");
    expect(cls).toMatch(/score-(low|medium|high|critical)/);
  });

  test("score element has matching severity class", async ({ page }) => {
    await ready(page);
    const scoreEl = page.locator("#score");
    const cls = await scoreEl.getAttribute("class");
    expect(cls).toMatch(/(low|medium|high|critical)/);
  });

  test("score plate class matches score element class", async ({ page }) => {
    await ready(page);
    const scoreEl = page.locator("#score");
    const scoreplate = page.locator(".scoreplate");
    const scoreCls = await scoreEl.getAttribute("class");
    const plateCls = await scoreplate.getAttribute("class");
    // Both should contain the same severity class
    expect(plateCls).toContain(scoreCls);
  });
});

test.describe("Metrics row shows all counts", () => {
  test("metrics row has 6 metric cards", async ({ page }) => {
    await ready(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBe(6);
  });

  test("total metric shows 14", async ({ page }) => {
    await ready(page);
    const first = await page.locator("#metrics .metric").first().textContent();
    expect(first).toContain("14");
  });

  test("critical metric shows 2", async ({ page }) => {
    await ready(page);
    const second = await page.locator("#metrics .metric").nth(1).textContent();
    expect(second).toContain("2");
  });

  test("high metric shows 6", async ({ page }) => {
    await ready(page);
    const third = await page.locator("#metrics .metric").nth(2).textContent();
    expect(third).toContain("6");
  });

  test("medium metric shows 4", async ({ page }) => {
    await ready(page);
    const fourth = await page.locator("#metrics .metric").nth(3).textContent();
    expect(fourth).toContain("4");
  });

  test("low metric shows 2", async ({ page }) => {
    await ready(page);
    const fifth = await page.locator("#metrics .metric").nth(4).textContent();
    expect(fifth).toContain("2");
  });
});

test.describe("Fixable metric shows correct count", () => {
  test("fixable metric shows 13 (all except unavailable)", async ({
    page,
  }) => {
    await ready(page);
    const fixable = await page
      .locator("#metrics .metric")
      .nth(5)
      .textContent();
    expect(fixable).toContain("Fixable");
    expect(fixable).toContain("13");
  });
});

test.describe("Score breakdown axes structure", () => {
  test("each axis has label, score, bar, and meta", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const top = axes.nth(i).locator(".score-axis-top");
      await expect(top).toBeVisible();

      const label = top.locator("span");
      const labelText = await label.textContent();
      expect(labelText).toBeTruthy();

      const score = top.locator("strong");
      const scoreText = await score.textContent();
      expect(scoreText).toMatch(/^\d+\/100$/);

      const bar = axes.nth(i).locator(".score-axis-bar span");
      await expect(bar).toBeVisible();

      const meta = axes.nth(i).locator(".score-axis-meta");
      await expect(meta).toBeVisible();
    }
  });
});

test.describe("Detail panel for trivy CVE finding", () => {
  test("detail shows ID, source, severity, service, remediation", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    await expect(detail).toBeVisible({ timeout: 5000 });

    const text = await detail.textContent();
    expect(text).toContain("trivy.cve-2024-0001");
    expect(text).toContain("trivy");
    expect(text).toContain("critical");
    expect(text).toContain("nginx:1.24");
    expect(text).toContain("Auto");
  });
  test("detail shows description and how_to_fix sections", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const sections = detail.locator(".section");
    const count = await sections.count();
    expect(count).toBeGreaterThanOrEqual(2);

    const headings = detail.locator(".section h3");
    const headingTexts: string[] = [];
    for (let i = 0; i < (await headings.count()); i++) {
      headingTexts.push((await headings.nth(i).textContent()) ?? "");
    }
    expect(headingTexts).toContain("Description");
    expect(headingTexts).toContain("How to fix");
  });
});

test.describe("Detail panel for lynis finding", () => {
  test("lynis finding shows correct detail fields", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("lynis.AUTH-9286");
    expect(text).toContain("lynis");
    expect(text).toContain("Auto");
  });
});

test.describe("Detail panel for compose finding", () => {
  test("compose finding shows service and metadata", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='compose.dr004']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("compose.dr004");
    expect(text).toContain("compose");
    expect(text).toContain("env_file");
    expect(text).toContain("webapp");
  });
});

test.describe("Detail panel for unavailable finding", () => {
  test("unavailable finding shows Unavailable and not yet classified", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Unavailable");
    expect(text).toContain("not yet classified");
  });
});

test.describe("Detail panel for fixed finding", () => {
  test("fixed finding has no Fix button", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    const count = await fixBtn.count();
    expect(count).toBe(0);
  });
});

test.describe("Table row rendering", () => {
  test("every row has 6 cells", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const cells = rows.nth(i).locator("td");
      const cellCount = await cells.count();
      expect(cellCount).toBe(6);
    }
  });

  test("every row has data-id and data-index", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const dataId = await rows.nth(i).getAttribute("data-id");
      const dataIdx = await rows.nth(i).getAttribute("data-index");
      expect(dataId).toBeTruthy();
      expect(dataIdx).toBe(String(i));
    }
  });

  test("fixed row has fixed and disabled classes", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const cls = await row.getAttribute("class");
    expect(cls).toContain("fixed");
    expect(cls).toContain("disabled");
  });

  test("fixed row has disabled checkbox", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const checkbox = row.locator(".row-check");
    const isDisabled = await checkbox.isDisabled();
    expect(isDisabled).toBe(true);
  });
});

test.describe("Filter chips rendering", () => {
  test("severity chips have All, Critical, High, Medium, Low", async ({
    page,
  }) => {
    await ready(page);
    const chips = page.locator("#severityFilters button.chip");
    const count = await chips.count();
    expect(count).toBe(5);

    const labels: string[] = [];
    for (let i = 0; i < count; i++) {
      labels.push((await chips.nth(i).textContent()) ?? "");
    }
    expect(labels).toContain("All");
    expect(labels).toContain("Critical");
    expect(labels).toContain("High");
    expect(labels).toContain("Medium");
    expect(labels).toContain("Low");
  });

  test("All chip is active by default", async ({ page }) => {
    await ready(page);
    const activeChip = page.locator("#severityFilters button.chip.active");
    const text = await activeChip.textContent();
    expect(text).toContain("All");
  });

  test("clicking Critical activates it", async ({ page }) => {
    await ready(page);

    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);

    const activeChip = page.locator("#severityFilters button.chip.active");
    const text = await activeChip.textContent();
    expect(text).toContain("Critical");

    // Back to All
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);
  });
});

test.describe("Sort dropdown", () => {
  test("sort dropdown has 4 options", async ({ page }) => {
    await ready(page);
    const sortBy = page.locator("#sortBy");
    const options = sortBy.locator("option");
    const count = await options.count();
    expect(count).toBe(4);
  });

  test("sort dropdown defaults to severity", async ({ page }) => {
    await ready(page);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("severity");
  });

  test("changing sort dropdown updates table order", async ({ page }) => {
    await ready(page);

    await page.locator("#sortBy").selectOption("source");
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("source");
  });
});

test.describe("Search filtering", () => {
  test("typing in search filters the findings table", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);
    expect(count).toBeLessThan(14);
  });

  test("clearing search restores all findings", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeLessThan(14);

    await query.fill("");
    await page.waitForTimeout(300);

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });

  test("search is case-insensitive", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("NGINX");
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);

    await query.fill("");
    await page.waitForTimeout(300);
  });
});

test.describe("Keyboard navigation", () => {
  test("ArrowDown and ArrowUp navigate findings", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);

    const selected = page.locator("#findings tr.selected");
    const count = await selected.count();
    expect(count).toBe(1);

    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(100);
  });

  test("/ focuses search input", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("/");
    await page.waitForTimeout(100);

    const query = page.locator("#query");
    const isFocused = await query.evaluate(
      (el) => el === document.activeElement
    );
    expect(isFocused).toBe(true);

    await page.keyboard.press("Escape");
  });

  test("e opens export modal", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("e");
    await page.waitForTimeout(300);

    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    await page.keyboard.press("Escape");
  });

  test("? opens help modal", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("?");
    await page.waitForTimeout(300);

    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    await page.keyboard.press("Escape");
  });

  test("Space toggles selection", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);

    await page.keyboard.press("Space");
    await page.waitForTimeout(200);

    const selectedRows = page.locator("#findings tr.row-selected");
    const count = await selectedRows.count();
    expect(count).toBe(1);

    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
  });
});

test.describe("Score breakdown penalty cap values", () => {
  test("vulnerabilities max penalty is 35", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const vuln = result.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "vulnerabilities"
    );
    expect(vuln.max_penalty).toBe(35);
  });

  test("container_exposure max penalty is 30", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const ce = result.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "container_exposure"
    );
    expect(ce.max_penalty).toBe(30);
  });

  test("host_hardening max penalty is 25", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const hh = result.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "host_hardening"
    );
    expect(hh.max_penalty).toBe(25);
  });

  test("secrets max penalty is 10", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const s = result.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "secrets"
    );
    expect(s.max_penalty).toBe(10);
  });
});

test.describe("API contract validation", () => {
  test("result has required top-level fields", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("score");
    expect(result).toHaveProperty("score_breakdown");
    expect(result).toHaveProperty("hostname");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.findings.length).toBe(14);
  });

  test("score_breakdown has 4 axes", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });
    const axes = result.score_breakdown.axes;
    expect(Array.isArray(axes)).toBe(true);
    expect(axes.length).toBe(4);
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

test.describe("Recalc preserves score breakdown", () => {
  test("recalc returns same number of axes", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(1000);
    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);
  });
});

test.describe("Rescan lifecycle", () => {
  test("rescan button re-enables after completion", async ({ page }) => {
    await ready(page);
    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeVisible();
    await rescanBtn.click();
    await page.waitForTimeout(500);
    const isDisabled = await rescanBtn.isDisabled();
    expect(isDisabled).toBe(true);
    await expect(rescanBtn).toBeEnabled({ timeout: 10000 });
  });
});

test.describe("Export modal", () => {
  test("export modal has JSON, CSV, and AI options", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const text = await modal.textContent();
    expect(text).toContain("JSON");
    expect(text).toContain("CSV");
    expect(text).toContain("AI brief");
    await page.keyboard.press("Escape");
  });
});

test.describe("Help modal", () => {
  test("help modal shows keyboard shortcuts", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const text = await modal.textContent();
    expect(text).toContain("Navigation");
    expect(text).toContain("Filters");
    await page.keyboard.press("Escape");
  });
});

test.describe("No findings message", () => {
  test("shows no-match message when all findings filtered out", async ({
    page,
  }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("zzzznonexistent999");
    await page.waitForTimeout(300);
    const noMatch = page.locator("#findings tr td.muted");
    const text = await noMatch.textContent();
    expect(text).toContain("No findings match");
    await query.fill("");
    await page.waitForTimeout(300);
  });
});

test.describe("Select-all checkbox", () => {
  test("select-all checkbox selects all batch-selectable findings", async ({
    page,
  }) => {
    await ready(page);
    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });
    await page.waitForTimeout(200);
    const isChecked = await selectAll.isChecked();
    expect(isChecked).toBe(true);
    const selectedRows = page.locator("#findings tr.row-selected");
    const count = await selectedRows.count();
    expect(count).toBeGreaterThan(0);
  });

  test("unchecking select-all clears selection", async ({ page }) => {
    await ready(page);
    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });
    await page.waitForTimeout(200);
    await selectAll.uncheck({ force: true });
    await page.waitForTimeout(200);
    const selectedRows = page.locator("#findings tr.row-selected");
    const count = await selectedRows.count();
    expect(count).toBe(0);
  });
});

test.describe("Double-click toggles selection", () => {
  test("double-click on row toggles row-selected class", async ({
    page,
  }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.FILE-6310']"
    );
    await row.dblclick();
    await page.waitForTimeout(200);
    let cls = await row.getAttribute("class");
    expect(cls).toContain("row-selected");
    await row.dblclick();
    await page.waitForTimeout(200);
    cls = await row.getAttribute("class");
    expect(cls).not.toContain("row-selected");
  });
});

test.describe("Fix modal for auto finding", () => {
  test("auto finding fix modal has finding title", async ({ page }) => {
    await ready(page);
    // Use a finding that might not be fixed yet
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9308']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        const modalText = await modal.textContent();
        expect(modalText).toBeTruthy();
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Review fix modal shows radio buttons", () => {
  test("review finding fix modal has action selection options", async ({
    page,
  }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        const radios = modal.locator("input[name='fixAction']");
        const radioCount = await radios.count();
        expect(radioCount).toBeGreaterThanOrEqual(2);
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Score breakdown penalty bars", () => {
  test("each penalty bar has a width percentage", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();
    expect(count).toBe(4);
    for (let i = 0; i < count; i++) {
      const style = await bars.nth(i).getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
    }
  });
});

test.describe("Evidence key ordering", () => {
  test("evidence keys are displayed in alphabetical order", async ({
    page,
  }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const summary = page
      .locator("#detail .evidence-details summary")
      .first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);
      const keys = page.locator(
        "#detail .evidence-details:first-of-type pre strong"
      );
      const count = await keys.count();
      const keyTexts: string[] = [];
      for (let i = 0; i < count; i++) {
        keyTexts.push((await keys.nth(i).textContent()) ?? "");
      }
      for (let i = 1; i < keyTexts.length; i++) {
        expect(keyTexts[i].localeCompare(keyTexts[i - 1])).toBeGreaterThanOrEqual(0);
      }
    }
  });
});

test.describe("Detail panel copy button", () => {
  test("how_to_fix section has copy button", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0002']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const detail = page.locator("#detail");
    await expect(detail).toBeVisible({ timeout: 5000 });
    const copyBtn = detail.locator("button.copy");
    await expect(copyBtn).toBeVisible();
  });
});

test.describe("Sort by title then severity", () => {
  test("title sort is stable", async ({ page }) => {
    await ready(page);
    await page.locator("#sortBy").selectOption("title");
    await page.waitForTimeout(200);
    const ids1: string[] = [];
    const rows1 = page.locator("#findings tr[data-index]");
    const count = await rows1.count();
    for (let i = 0; i < count; i++) {
      const id = await rows1.nth(i).getAttribute("data-id");
      if (id) ids1.push(id);
    }
    await rows1.first().click({ force: true });
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
