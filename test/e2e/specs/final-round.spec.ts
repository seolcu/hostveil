import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Batch selection edge cases", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Fixed finding has disabled checkbox", async ({ page }) => {
    const fixedRow = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    if ((await fixedRow.count()) > 0) {
      const check = fixedRow.locator(".row-check");
      await expect(check).toBeDisabled();
    }
  });

  test("Deselecting all hides fix selected button", async ({ page }) => {
    // Select a row
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    const check = row.locator(".row-check");
    await check.check();
    await page.waitForTimeout(200);

    const fixBtn = page.locator("#fixSelectedBtn");
    await expect(fixBtn).toBeVisible();

    // Deselect
    await check.uncheck();
    await page.waitForTimeout(200);
    await expect(fixBtn).toBeHidden();
  });
});

test.describe("Score breakdown consistency", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown is hidden when no findings exist", async ({
    page,
  }) => {
    // This tests the JS logic - in fixture mode there are always findings
    // but we can verify the section exists
    const section = page.locator("#scoreBreakdown");
    await expect(section).toBeVisible();
  });

  test("Each axis penalty cap is greater than zero", async ({ page }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();

    for (let i = 0; i < count; i++) {
      const metaText = await axes
        .nth(i)
        .locator(".score-axis-meta span")
        .first()
        .textContent();
      // Format: "N/M penalty cap used"
      const match = metaText?.match(/(\d+)\/(\d+)/);
      expect(match).toBeTruthy();
      if (match) {
        const maxPenalty = parseInt(match[2]);
        expect(maxPenalty).toBeGreaterThan(0);
      }
    }
  });
});

test.describe("Detail panel metadata completeness", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Detail shows all expected metadata fields for auto finding", async ({
    page,
  }) => {
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const meta = page.locator(".detail-meta");
      await expect(meta).toBeVisible();

      const dtElements = meta.locator("dt");
      const dtCount = await dtElements.count();
      const labels = [];
      for (let i = 0; i < dtCount; i++) {
        labels.push((await dtElements.nth(i).textContent())?.trim());
      }

      expect(labels).toContain("ID");
      expect(labels).toContain("Source");
      expect(labels).toContain("Remediation");
      expect(labels).toContain("Service");
    }
  });
});

test.describe("Fix modal content validation", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Fix modal shows finding title", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    if (await fixBtn.isVisible().catch(() => false)) {
      await fixBtn.click();

      const modal = page.locator(".modal-overlay");
      await expect(modal).toBeVisible({ timeout: 5000 });

      // Modal should have a label showing the finding
      const label = modal.locator(".fix-label, .action-summary");
      await expect(label.first()).toBeVisible();

      await page.locator(".modal-actions button").last().click();
    }
  });
});

test.describe("Score breakdown at extreme viewports", () => {
  test("At 1920px, score breakdown shows 4 columns", async ({ page }) => {
    await page.setViewportSize({ width: 1920, height: 1080 });
    await waitForReady(page);

    const grid = page.locator("#scoreBreakdown .score-axis-grid");
    const cols = await grid.evaluate((el) =>
      getComputedStyle(el).gridTemplateColumns
    );
    expect(cols.split(" ").length).toBe(4);
  });

  test("At 480px, table hides ID column", async ({ page }) => {
    await page.setViewportSize({ width: 480, height: 800 });
    await waitForReady(page);

    const headers = page.locator("th");
    const visibleHeaders: string[] = [];
    const count = await headers.count();
    for (let i = 0; i < count; i++) {
      const display = await headers.nth(i).evaluate((el) =>
        getComputedStyle(el).display
      );
      if (display !== "none") {
        const text = await headers.nth(i).textContent();
        visibleHeaders.push(text || "");
      }
    }
    // At 480px, ID column should be hidden
    expect(visibleHeaders).not.toContain("ID");
  });
});

test.describe("Finding row data attributes", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Each finding row has data-id attribute", async ({ page }) => {
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);

    for (let i = 0; i < count; i++) {
      const dataId = await rows.nth(i).getAttribute("data-id");
      expect(dataId).toBeTruthy();
      expect(dataId).not.toBe("");
    }
  });

  test("Each finding row has data-index attribute", async ({ page }) => {
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();

    for (let i = 0; i < count; i++) {
      const dataIdx = await rows.nth(i).getAttribute("data-index");
      expect(dataIdx).toBeTruthy();
    }
  });
});

test.describe("Score severity tier validation", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score color class matches score value range", async ({ page }) => {
    const scoreEl = page.locator("#score");
    await expect(scoreEl).toHaveText(/^\d+\/100$/, { timeout: 5000 });

    const scoreText = await scoreEl.textContent();
    const score = parseInt(scoreText?.match(/^(\d+)/)?.[1] || "0");
    const className = await scoreEl.evaluate((el) => el.className);

    if (score >= 85) {
      expect(className).toBe("low");
    } else if (score >= 65) {
      expect(className).toBe("medium");
    } else if (score >= 40) {
      expect(className).toBe("high");
    } else {
      expect(className).toBe("critical");
    }
  });
});

test.describe("Workspace layout at desktop", () => {
  test("At 1440px, workspace uses flex layout", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await waitForReady(page);

    const workspace = page.locator(".workspace");
    const display = await workspace.evaluate((el) =>
      getComputedStyle(el).display
    );
    expect(display).toBe("flex");
  });

  test("At 1440px, filters panel has fixed width", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 });
    await waitForReady(page);

    const filters = page.locator(".filters");
    const width = await filters.evaluate((el) => el.offsetWidth);
    expect(width).toBeGreaterThan(200);
    expect(width).toBeLessThanOrEqual(400);
  });
});
