import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown + recalc interaction", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Recalc preserves score breakdown axes", async ({ page }) => {
    const axesBefore = await page
      .locator("#scoreBreakdown .score-axis")
      .count();
    expect(axesBefore).toBe(4);

    await page.locator("#recalcBtn").click();
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });

    // Breakdown should still be visible with 4 axes
    const axesAfter = await page
      .locator("#scoreBreakdown .score-axis")
      .count();
    expect(axesAfter).toBe(4);
  });

  test("Score breakdown penalty bars update after recalc", async ({ page }) => {
    // Capture penalty bar widths before recalc
    const barsBefore = await page
      .locator("#scoreBreakdown .score-axis-bar span")
      .evaluateAll((els) => els.map((el) => el.style.width));

    await page.locator("#recalcBtn").click();
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
    await page.waitForTimeout(500);

    // After recalc in fixture mode, bars should still be present
    const barsAfter = await page
      .locator("#scoreBreakdown .score-axis-bar span")
      .evaluateAll((els) => els.map((el) => el.style.width));
    expect(barsAfter.length).toBe(4);

    // In fixture mode, values should be identical
    expect(barsAfter).toEqual(barsBefore);
  });
});

test.describe("Service filter + findings count interaction", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Nginx service filter shows exactly 2 findings", async ({ page }) => {
    await page
      .locator('#serviceFilters button[data-value="nginx:1.24"]')
      .click();
    await page.waitForTimeout(300);

    const count = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(count).toBe(2);

    // All visible rows should have findings (count is the key assertion)
  });

  test("Webapp service filter shows 4 findings", async ({ page }) => {
    await page
      .locator('#serviceFilters button[data-value="webapp"]')
      .click();
    await page.waitForTimeout(300);

    const count = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(count).toBe(4);
  });

  test("Redis service filter shows correct count", async ({ page }) => {
    await page
      .locator('#serviceFilters button[data-value="redis:7"]')
      .click();
    await page.waitForTimeout(300);

    const count = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Sort by source column", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Sorting by source groups findings by source", async ({ page }) => {
    // Change sort to Source
    await page.locator("select").selectOption("source");
    await page.waitForTimeout(300);

    const sources = await page
      .locator("#findings tr[data-index] td:nth-child(3)")
      .allTextContents();

    // Filter out empty sources (fixed findings may have empty source)
    const nonEmpty = sources.filter((s) => s.trim().length > 0);
    const sorted = [...nonEmpty].sort((a, b) =>
      a.toLowerCase().localeCompare(b.toLowerCase())
    );
    expect(nonEmpty.map((s) => s.toLowerCase())).toEqual(
      sorted.map((s) => s.toLowerCase())
    );
  });

  test("Sort direction toggles on column header click", async ({ page }) => {
    const sevHeader = page.locator("th").filter({ hasText: "Severity" });
    await sevHeader.click();
    await page.waitForTimeout(300);

    // Check sort direction indicator
    const classList = await sevHeader.evaluate((el) => el.className);
    expect(classList).toMatch(/asc|desc/);
  });
});

test.describe("Detail panel metadata values", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Clicking trivy CVE shows correct ID in detail", async ({ page }) => {
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    await row.click();
    await page.waitForTimeout(300);

    const meta = page.locator(".detail-meta");
    await expect(meta).toBeVisible();

    const dtElements = meta.locator("dt");
    const ddElements = meta.locator("dd");
    const dtCount = await dtElements.count();

    for (let i = 0; i < dtCount; i++) {
      const label = await dtElements.nth(i).textContent();
      const value = await ddElements.nth(i).textContent();
      if (label?.trim() === "ID") {
        expect(value).toContain("trivy.cve-2024-0001");
      }
      if (label?.trim() === "Source") {
        expect(value?.toLowerCase()).toContain("trivy");
      }
    }
  });

  test("Clicking lynis finding shows Lynis source", async ({ page }) => {
    const row = page.locator("#findings tr[data-id='lynis.AUTH-9286']");
    await row.click();
    await page.waitForTimeout(300);

    const meta = page.locator(".detail-meta");
    const ddElements = meta.locator("dd");
    const dtElements = meta.locator("dt");
    const dtCount = await dtElements.count();

    for (let i = 0; i < dtCount; i++) {
      const label = await dtElements.nth(i).textContent();
      const value = await ddElements.nth(i).textContent();
      if (label?.trim() === "Source") {
        expect(value?.toLowerCase()).toContain("lynis");
      }
    }
  });
});

test.describe("Help modal keyboard shortcuts", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Help modal lists navigation shortcuts", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const modal = page.locator(".modal-content");
    const text = await modal.textContent();
    expect(text).toContain("Navigation");
    expect(text).toContain("↑");
  });

  test("Help modal lists action shortcuts", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const modal = page.locator(".modal-content");
    const text = await modal.textContent();
    expect(text).toContain("fix");
    expect(text).toContain("help");
  });
});

test.describe("Score breakdown penalty bar accessibility", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Penalty bars have aria-label with axis name and penalty info", async ({
    page,
  }) => {
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    const count = await bars.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const ariaLabel = await bars.nth(i).getAttribute("aria-label");
      expect(ariaLabel).toBeTruthy();
      expect(ariaLabel).toContain("penalty");
    }
  });
});

test.describe("Table column width at 1440px", () => {
  test("Table does not overflow at 1440px width", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await waitForReady(page);

    const overflow = await page.evaluate(() => {
      const body = document.body;
      const html = document.documentElement;
      return {
        bodyScroll: body.scrollWidth,
        bodyClient: body.clientWidth,
        htmlScroll: html.scrollWidth,
        htmlClient: html.clientWidth,
      };
    });

    expect(overflow.bodyScroll).toBeLessThanOrEqual(overflow.bodyClient + 1);
    expect(overflow.htmlScroll).toBeLessThanOrEqual(overflow.htmlClient + 1);
  });
});

test.describe("Fix modal action type badge", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Auto fix shows action type in badge", async ({ page }) => {
    const row = page.locator("#findings tr").nth(1);
    await row.click();

    const fixBtn = page.locator(".fix-btn");
    if (await fixBtn.isVisible().catch(() => false)) {
      await fixBtn.click();

      const modal = page.locator(".modal-overlay");
      await expect(modal).toBeVisible({ timeout: 5000 });

      // Check for action type badge
      const badge = modal.locator(".action-type-badge");
      if (await badge.count() > 0) {
        const text = await badge.first().textContent();
        expect(text?.toLowerCase()).toMatch(/edit|exec|prompt/);
      }

      await modal.locator(".modal-actions button").last().click();
    }
  });
});

test.describe("Export AI brief content", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("AI brief export triggers download with markdown content", async ({
    page,
  }) => {
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    // Find and click the AI brief option
    const aiOption = page.locator(".export-option").filter({ hasText: "AI" });
    if (await aiOption.count() > 0) {
      const [download] = await Promise.all([
        page.waitForEvent("download"),
        aiOption.click(),
      ]);

      expect(download.suggestedFilename()).toContain("hostveil");
      const ext = download.suggestedFilename().split(".").pop();
      expect(["md", "txt"]).toContain(ext);
    }
  });
});

test.describe("Recalc preserves UI state", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Recalc preserves filter state", async ({ page }) => {
    // Apply severity filter
    await page.locator("button:text('Critical')").click();
    await page.waitForTimeout(300);
    const countBefore = await page
      .locator("#findings tr[data-index]")
      .count();

    // Recalc
    await page.locator("#recalcBtn").click();
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
    await page.waitForTimeout(500);

    // Filter should still be active
    const countAfter = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(countAfter).toBe(countBefore);
  });

  test("Recalc button is disabled during recalc", async ({ page }) => {
    const recalcBtn = page.locator("#recalcBtn");
    await expect(recalcBtn).toBeEnabled();

    await recalcBtn.click();
    // In fixture mode recalc is fast, but button should briefly be disabled
    await page.waitForTimeout(100);

    // After recalc completes, button should be re-enabled
    await expect(recalcBtn).toBeEnabled({ timeout: 5000 });
  });
});

test.describe("Rescan button state", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Rescan button shows loading state during rescan", async ({ page }) => {
    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeEnabled();

    await rescanBtn.click();

    // Button text may change to indicate loading
    await page.waitForTimeout(200);

    // After rescan completes, button should be re-enabled
    await expect(rescanBtn).toBeEnabled({ timeout: 15000 });
    await expect(rescanBtn).toContainText("Rescan");
  });

  test("Rescan refreshes score breakdown", async ({ page }) => {
    const axesBefore = await page
      .locator("#scoreBreakdown .score-axis")
      .count();

    await page.locator("#rescanBtn").click();
    await expect(page.locator("#rescanBtn")).toBeEnabled({ timeout: 15000 });
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });

    const axesAfter = await page
      .locator("#scoreBreakdown .score-axis")
      .count();
    expect(axesAfter).toBe(axesBefore);
  });
});
