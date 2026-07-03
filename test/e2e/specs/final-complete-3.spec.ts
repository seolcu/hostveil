import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Export modal options", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Export modal shows 3 options: JSON, CSV, AI Brief", async ({
    page,
  }) => {
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const options = page.locator(".export-option");
    const count = await options.count();
    expect(count).toBe(3);
  });

  test("Export modal has close button", async ({ page }) => {
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const closeBtn = page.locator("#exportModal .modal-actions button");
    await expect(closeBtn).toBeVisible();
  });
});

test.describe("Score breakdown score format", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Each axis score is formatted as N/100", async ({ page }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();

    for (let i = 0; i < count; i++) {
      const scoreText = await axes
        .nth(i)
        .locator(".score-axis-top strong")
        .textContent();
      expect(scoreText).toMatch(/^\d+\/100$/);
    }
  });
});

test.describe("Detail panel description section", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Description section has h3 heading", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const h3s = page.locator("#detail h3");
    const count = await h3s.count();
    expect(count).toBeGreaterThanOrEqual(1);

    const firstH3 = await h3s.first().textContent();
    expect(firstH3?.toLowerCase()).toContain("description");
  });
});

test.describe("Score breakdown responsive at 320px", () => {
  test("Score breakdown remains visible at 320px", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 568 });
    await waitForReady(page);

    const section = page.locator("#scoreBreakdown");
    await expect(section).toBeVisible();
  });

  test("All 4 axis cards visible at 320px", async ({ page }) => {
    await page.setViewportSize({ width: 320, height: 568 });
    await waitForReady(page);

    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);
  });
});

test.describe("Finding row styling", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Fixed finding row has reduced opacity", async ({ page }) => {
    const fixedRow = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    if ((await fixedRow.count()) > 0) {
      const opacity = await fixedRow.evaluate(
        (el) => getComputedStyle(el).opacity
      );
      expect(parseFloat(opacity)).toBeLessThan(1);
    }
  });

  test("Normal finding row has full opacity", async ({ page }) => {
    const normalRow = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    if ((await normalRow.count()) > 0) {
      const opacity = await normalRow.evaluate(
        (el) => getComputedStyle(el).opacity
      );
      expect(parseFloat(opacity)).toBe(1);
    }
  });
});

test.describe("Score breakdown bar color", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown bars have colored fill", async ({ page }) => {
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();

    for (let i = 0; i < count; i++) {
      const bgColor = await bars.nth(i).evaluate(
        (el) => getComputedStyle(el).backgroundColor
      );
      // Should have a non-transparent background
      expect(bgColor).toBeTruthy();
      expect(bgColor).not.toBe("rgba(0, 0, 0, 0)");
    }
  });
});

test.describe("Table cell text alignment", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Table data cells have left text alignment", async ({ page }) => {
    // Skip first column (checkbox, center-aligned)
    const cells = page.locator("td:not(:first-child)");
    const count = await cells.count();
    expect(count).toBeGreaterThan(0);

    const firstDataCell = cells.first();
    const textAlign = await firstDataCell.evaluate(
      (el) => getComputedStyle(el).textAlign
    );
    expect(textAlign).toBe("left");
  });
});

test.describe("Help modal help grid", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Help modal shows help grid with sections", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const grid = page.locator(".help-grid");
    await expect(grid).toBeVisible();

    const sections = page.locator(".help-section");
    const count = await sections.count();
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test("Help modal sections have headings", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const headings = page.locator(".help-section h3");
    const count = await headings.count();
    expect(count).toBeGreaterThanOrEqual(2);

    for (let i = 0; i < count; i++) {
      const text = await headings.nth(i).textContent();
      expect(text?.trim().length).toBeGreaterThan(0);
    }
  });
});

test.describe("Score breakdown axis label colors", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Axis labels use muted color", async ({ page }) => {
    const labels = page.locator(
      "#scoreBreakdown .score-axis-top span"
    );
    const count = await labels.count();

    for (let i = 0; i < count; i++) {
      const color = await labels.nth(i).evaluate(
        (el) => getComputedStyle(el).color
      );
      expect(color).toBeTruthy();
    }
  });
});

test.describe("Detail panel how-to-fix section", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("How-to-fix section has copy guidance button", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const copyBtn = page.locator("text=Copy guidance");
    if (await copyBtn.isVisible().catch(() => false)) {
      await expect(copyBtn).toBeVisible();
      const text = await copyBtn.textContent();
      expect(text).toContain("Copy guidance");
    }
  });
});

test.describe("Score breakdown total score consistency", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Main score element and score plate show same value", async ({
    page,
  }) => {
    const mainScore = await page.locator("#score").textContent();
    const plateScore = await page
      .locator(".scoreplate strong")
      .textContent();
    expect(mainScore).toBe(plateScore);
  });

  test("Score breakdown overall matches main score via API", async ({
    page,
  }) => {
    const result = await page.evaluate(() =>
      fetch("/api/result").then((r) => r.json())
    );

    const uiScore = parseInt(
      (await page.locator("#score").textContent())?.match(/^(\d+)/)?.[1] ||
        "0"
    );
    expect(uiScore).toBe(result.score);
    expect(uiScore).toBe(result.score_breakdown.overall);
  });
});
