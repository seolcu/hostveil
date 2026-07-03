import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("JSON export structure validation", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("JSON export contains score_breakdown", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportJson").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const json = JSON.parse(Buffer.concat(content).toString("utf-8"));

    expect(json).toHaveProperty("score_breakdown");
    expect(json.score_breakdown).toHaveProperty("overall");
    expect(json.score_breakdown).toHaveProperty("axes");
    expect(Array.isArray(json.score_breakdown.axes)).toBe(true);
  });

  test("JSON export contains hostname", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportJson").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const json = JSON.parse(Buffer.concat(content).toString("utf-8"));

    expect(json).toHaveProperty("hostname", "e2e-test-box");
  });

  test("JSON export contains local_ip", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportJson").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const json = JSON.parse(Buffer.concat(content).toString("utf-8"));

    expect(json).toHaveProperty("local_ip", "192.168.1.100");
  });
});

test.describe("Score breakdown at 768px tablet", () => {
  test("Score breakdown grid shows 2 columns at 768px", async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await waitForReady(page);

    const grid = page.locator("#scoreBreakdown .score-axis-grid");
    const cols = await grid.evaluate((el) =>
      getComputedStyle(el).gridTemplateColumns
    );
    // 768px > 760px breakpoint, so 2-column layout applies
    const colCount = cols.split(" ").length;
    expect(colCount).toBe(2);
  });
});

test.describe("Detail panel at narrow width", () => {
  test("Detail panel renders at 375px width", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await waitForReady(page);

    const detail = page.locator("#detail");
    await expect(detail).toBeVisible();

    const h2 = detail.locator("h2");
    await expect(h2).not.toBeEmpty();
  });
});

test.describe("Score breakdown penalty cap format", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Penalty cap text shows 'N/M penalty cap used'", async ({ page }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();

    for (let i = 0; i < count; i++) {
      const metaText = await axes
        .nth(i)
        .locator(".score-axis-meta span")
        .first()
        .textContent();
      expect(metaText).toMatch(/\d+\/\d+ penalty cap used/);
    }
  });
});

test.describe("Finding count after filter reset", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Count returns to 14 after clearing all filters", async ({ page }) => {
    // Apply multiple filters
    await page.locator("button:text('Critical')").click();
    await page.waitForTimeout(200);
    await page
      .locator('#serviceFilters button[data-value="nginx:1.24"]')
      .click();
    await page.waitForTimeout(200);

    const filteredCount = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(filteredCount).toBeLessThan(14);

    // Clear all
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);

    const resetCount = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(resetCount).toBe(14);
  });
});

test.describe("Score breakdown axis count summary", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Vulnerabilities axis shows severity counts", async ({ page }) => {
    const axis = page.locator("#scoreBreakdown .score-axis").nth(0);
    const counts = axis.locator(".score-axis-counts span:not(.muted)");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);

    for (let i = 0; i < count; i++) {
      const text = await counts.nth(i).textContent();
      expect(text).toMatch(/^\d+[CHML]$/);
    }
  });

  test("Host hardening axis shows severity counts", async ({ page }) => {
    const axis = page.locator("#scoreBreakdown .score-axis").nth(2);
    const counts = axis.locator(".score-axis-counts span:not(.muted)");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);

    for (let i = 0; i < count; i++) {
      const text = await counts.nth(i).textContent();
      expect(text).toMatch(/^\d+[CHML]$/);
    }
  });
});

test.describe("Table row count matches findings", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("All 14 findings are rendered in the table", async ({ page }) => {
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);
  });

  test("Each row has a severity badge", async ({ page }) => {
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();

    for (let i = 0; i < count; i++) {
      const badge = rows.nth(i).locator(".badge");
      const checkmark = rows.nth(i).locator("td:nth-child(2)");
      const text = await checkmark.textContent();
      // Either a badge or a checkmark for fixed
      const hasBadge = (await badge.count()) > 0;
      const hasCheck = text?.trim() === "✓";
      expect(hasBadge || hasCheck).toBe(true);
    }
  });
});

test.describe("Score breakdown at 768px head layout", () => {
  test("Score breakdown head stays flex at 768px", async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    await waitForReady(page);

    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const display = await head.evaluate((el) =>
      getComputedStyle(el).display
    );
    // 768px > 760px breakpoint, so flex layout persists
    expect(display).toBe("flex");
  });
});

test.describe("Detail panel badge styling", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Detail badge has correct severity color", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    await expect(badge).toBeVisible();

    const className = await badge.evaluate((el) => el.className);
    expect(className).toMatch(/critical|high|medium|low/);
  });

  test("Detail badge text matches severity label", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    const text = await badge.textContent();
    // Badge uses CSS text-transform:uppercase; textContent returns raw
    expect(text).toMatch(/critical|high|medium|low/);
  });
});

test.describe("Score plate title", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score plate shows 'Security score' label", async ({ page }) => {
    const label = page.locator(".score-label");
    await expect(label).toHaveText("Security score");
  });
});

test.describe("Finding title truncation", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Long finding titles are truncated with ellipsis", async ({ page }) => {
    const titles = page.locator("#findings .title");
    const count = await titles.count();
    expect(count).toBeGreaterThan(0);

    for (let i = 0; i < Math.min(count, 5); i++) {
      const overflow = await titles.nth(i).evaluate(
        (el) => getComputedStyle(el).textOverflow
      );
      expect(overflow).toBe("ellipsis");
    }
  });
});

test.describe("Score breakdown head paragraph", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown head paragraph mentions penalty cap", async ({
    page,
  }) => {
    const p = page.locator("#scoreBreakdown .score-breakdown-head p");
    await expect(p).toContainText("penalty cap");
  });

  test("Score breakdown head paragraph mentions scanner", async ({ page }) => {
    const p = page.locator("#scoreBreakdown .score-breakdown-head p");
    await expect(p).toContainText("scanner");
  });
});
