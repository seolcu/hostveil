import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("No findings match message", () => {
  test("shows no-match message when all findings filtered out", async ({
    page,
  }) => {
    await ready(page);

    // Search for something impossible
    const query = page.locator("#query");
    await query.fill("zzzznonexistent999");
    await page.waitForTimeout(300);

    const noMatch = page.locator("#findings tr td.muted");
    const text = await noMatch.textContent();
    expect(text).toContain("No findings match");

    // Clear
    await query.fill("");
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Select-all checkbox states", () => {
  test("select-all checkbox becomes checked when all selected", async ({
    page,
  }) => {
    await ready(page);

    const selectAll = page.locator("#selectAllCheck");
    const isInitiallyChecked = await selectAll.isChecked();
    expect(isInitiallyChecked).toBe(false);

    // Click select all
    await selectAll.check({ force: true });
    await page.waitForTimeout(200);

    const isChecked = await selectAll.isChecked();
    expect(isChecked).toBe(true);

    // All selectable rows should be selected
    const selectedRows = page.locator("#findings tr.row-selected");
    const count = await selectedRows.count();
    expect(count).toBeGreaterThan(0);
  });

  test("select-all checkbox unchecks when unchecked", async ({ page }) => {
    await ready(page);

    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });
    await page.waitForTimeout(200);
    expect(await selectAll.isChecked()).toBe(true);

    await selectAll.uncheck({ force: true });
    await page.waitForTimeout(200);
    expect(await selectAll.isChecked()).toBe(false);

    const selectedRows = page.locator("#findings tr.row-selected");
    const count = await selectedRows.count();
    expect(count).toBe(0);
  });
});

test.describe("Double-click toggles selection", () => {
  test("double-click on row toggles its row-selected class", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.FILE-6310']"
    );

    // Double-click to select
    await row.dblclick();
    await page.waitForTimeout(200);

    let cls = await row.getAttribute("class");
    expect(cls).toContain("row-selected");

    // Double-click again to deselect
    await row.dblclick();
    await page.waitForTimeout(200);

    cls = await row.getAttribute("class");
    expect(cls).not.toContain("row-selected");
  });
});

test.describe("q key shows toast", () => {
  test("pressing q shows close-tab hint", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("q");
    await page.waitForTimeout(500);

    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
    const text = await toast.textContent();
    expect(text).toContain("Ctrl+W");
  });
});

test.describe("Recalc via button", () => {
  test("recalc button triggers recalc and shows toast", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);

    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 5000 });
    const text = await toast.textContent();
    expect(text).toContain("recalculated");
  });
});

test.describe("Rescan via button", () => {
  test("rescan button triggers rescan", async ({ page }) => {
    await ready(page);
    await page.locator("#rescanBtn").click();
    await page.waitForTimeout(500);

    const rescanBtn = page.locator("#rescanBtn");
    const isDisabled = await rescanBtn.isDisabled();
    expect(isDisabled).toBe(true);
  });
});

test.describe("R key clears all filters", () => {
  test("R key resets filters and shows toast", async ({ page }) => {
    await ready(page);

    // Apply critical filter
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    // R to clear
    await page.keyboard.press("R");
    await page.waitForTimeout(500);

    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
    const text = await toast.textContent();
    expect(text).toContain("Filters cleared");

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Sort dropdown syncs with column header click", () => {
  test("clicking severity header updates sort dropdown", async ({ page }) => {
    await ready(page);

    const sortBy = page.locator("#sortBy");
    expect(await sortBy.inputValue()).toBe("severity");

    await page.locator("th.sortable").nth(1).click();
    await page.waitForTimeout(200);
    expect(await sortBy.inputValue()).toBe("source");

    await page.locator("th.sortable").nth(2).click();
    await page.waitForTimeout(200);
    expect(await sortBy.inputValue()).toBe("title");

    await page.locator("th.sortable").nth(0).click();
    await page.waitForTimeout(200);
    expect(await sortBy.inputValue()).toBe("severity");
  });

  test("o key updates sort dropdown", async ({ page }) => {
    await ready(page);

    const sortBy = page.locator("#sortBy");
    expect(await sortBy.inputValue()).toBe("severity");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    expect(await sortBy.inputValue()).toBe("source");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    expect(await sortBy.inputValue()).toBe("title");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    expect(await sortBy.inputValue()).toBe("remediation");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    expect(await sortBy.inputValue()).toBe("severity");
  });
});

test.describe("Batch fix via API", () => {
  test("POST /api/fix/batch with mix of valid and invalid findings", async ({
    page,
  }) => {
    await ready(page);

    const result = await page.evaluate(async () => {
      const r = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [
            { id: "nonexistent.id", action_index: 0 },
            { id: "another.bad.id", action_index: 0 },
          ],
        }),
      });
      return r.json();
    });

    expect(result.results).toBeTruthy();
    expect(Array.isArray(result.results)).toBe(true);
    expect(result.results.length).toBe(2);
  });
});

test.describe("Review fix modal shows radio buttons", () => {
  test("review finding fix modal has action selection options", async ({
    page,
  }) => {
    await ready(page);

    // trivy.dr001 is a review finding
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    // Should have radio buttons for action selection
    const radios = modal.locator("input[name='fixAction']");
    const radioCount = await radios.count();
    expect(radioCount).toBeGreaterThanOrEqual(2);

    // Confirm button should be disabled until action selected
    const confirmBtn = modal.locator("#modalFixYes");
    const isDisabled = await confirmBtn.isDisabled();
    expect(isDisabled).toBe(true);

    // Select first action
    await radios.first().click();
    await page.waitForTimeout(100);

    // Now confirm should be enabled
    const isEnabled = await confirmBtn.isEnabled();
    expect(isEnabled).toBe(true);

    await page.keyboard.press("Escape");
  });
});

test.describe("Number key severity filter", () => {
  test("pressing 1 filters to critical", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);
  });

  test("pressing 0 shows all", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    await page.keyboard.press("0");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Export modal close button", () => {
  test("export modal closes on Close button click", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("e");
    await page.waitForTimeout(300);

    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    const closeBtn = modal.locator("button").filter({ hasText: "Close" });
    await closeBtn.click();
    await page.waitForTimeout(300);

    await expect(modal).not.toBeVisible();
  });
});

test.describe("Help modal close button", () => {
  test("help modal closes on Close button click", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("?");
    await page.waitForTimeout(300);

    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    const closeBtn = modal.locator("button").filter({ hasText: "Close" });
    await closeBtn.click();
    await page.waitForTimeout(300);

    await expect(modal).not.toBeVisible();
  });
});

test.describe("Detail panel sections", () => {
  test("detail panel has description and how_to_fix sections", async ({
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

    const sections = detail.locator(".section");
    const count = await sections.count();
    expect(count).toBeGreaterThanOrEqual(2);

    // Check for Description and How to fix headings
    const headings = detail.locator(".section h3");
    const headingCount = await headings.count();
    const headingTexts: string[] = [];
    for (let i = 0; i < headingCount; i++) {
      headingTexts.push((await headings.nth(i).textContent()) ?? "");
    }
    expect(headingTexts).toContain("Description");
    expect(headingTexts).toContain("How to fix");
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

test.describe("Finding IDs are unique", () => {
  test("all finding IDs in API response are unique", async ({ page }) => {
    await ready(page);

    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });

    const ids = result.findings.map((f: { id: string }) => f.id);
    const uniqueIds = new Set(ids);
    expect(uniqueIds.size).toBe(ids.length);
  });
});

test.describe("Finding structure validation", () => {
  test("each finding has required fields", async ({ page }) => {
    await ready(page);

    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });

    for (const f of result.findings) {
      expect(f).toHaveProperty("id");
      expect(f).toHaveProperty("title");
      expect(f).toHaveProperty("severity");
      expect(f).toHaveProperty("source");
      expect(f).toHaveProperty("remediation");
      expect(typeof f.id).toBe("string");
      expect(typeof f.title).toBe("string");
      expect(typeof f.severity).toBe("number");
      expect(typeof f.source).toBe("number");
      expect(typeof f.remediation).toBe("number");
    }
  });
});

test.describe("Score is in valid range", () => {
  test("overall score between 0 and 100", async ({ page }) => {
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

test.describe("Row click selects row", () => {
  test("clicking a row adds selected class", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0002']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(200);

    const cls = await row.getAttribute("class");
    expect(cls).toContain("selected");
  });

  test("clicking a different row changes selection", async ({ page }) => {
    await ready(page);

    const row1 = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const row2 = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0002']"
    );

    await row1.click({ force: true });
    await page.waitForTimeout(200);
    const cls1 = await row1.getAttribute("class");
    expect(cls1).toContain("selected");

    await row2.click({ force: true });
    await page.waitForTimeout(200);
    const cls2 = await row2.getAttribute("class");
    expect(cls2).toContain("selected");

    // Row1 should no longer be selected
    const cls1After = await row1.getAttribute("class");
    expect(cls1After).not.toContain("selected");
  });
});

test.describe("Search includes evidence values", () => {
  test("searching by evidence value finds the finding", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);

    await query.fill("");
    await page.waitForTimeout(300);
  });

  test("search by CVE URL finds the finding", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("nvd.nist.gov");
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(1);

    await query.fill("");
    await page.waitForTimeout(300);
  });
});

test.describe("Keyboard Escape while typing in search", () => {
  test("Escape blurs search input", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.focus();
    await page.waitForTimeout(100);

    const isFocused = await query.evaluate(
      (el) => el === document.activeElement
    );
    expect(isFocused).toBe(true);

    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);

    const isStillFocused = await query.evaluate(
      (el) => el === document.activeElement
    );
    expect(isStillFocused).toBe(false);
  });
});

test.describe("Score breakdown after filtering", () => {
  test("score breakdown remains visible when filtered", async ({ page }) => {
    await ready(page);

    // Apply critical filter
    await page.keyboard.press("1");
    await page.waitForTimeout(200);

    // Score breakdown should still show 4 axes
    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);

    // Clear
    await page.keyboard.press("0");
    await page.waitForTimeout(200);
  });
});

test.describe("Table row data attributes", () => {
  test("each row has data-id attribute", async ({ page }) => {
    await ready(page);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const dataId = await rows.nth(i).getAttribute("data-id");
      expect(dataId).toBeTruthy();
      expect(dataId!.length).toBeGreaterThan(0);
    }
  });

  test("each row has data-index attribute matching position", async ({
    page,
  }) => {
    await ready(page);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const dataIdx = await rows.nth(i).getAttribute("data-index");
      expect(dataIdx).toBe(String(i));
    }
  });
});
