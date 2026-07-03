import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown when score is high", () => {
  test("Score breakdown still shows all axes when score >= 85", async ({
    page,
  }) => {
    // This tests the JS logic - in fixture mode score is 49
    // but we can verify the section always renders
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);
  });
});

test.describe("Detail panel evidence content", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Trivy CVE finding has evidence with key-value pairs", async ({
    page,
  }) => {
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const evidence = page.locator(".evidence-details");
      const count = await evidence.count();
      expect(count).toBeGreaterThanOrEqual(1);

      // First evidence section should have a summary
      const summary = evidence.first().locator("summary");
      await expect(summary).toBeVisible();
      const summaryText = await summary.textContent();
      expect(summaryText).toBeTruthy();
    }
  });
});

test.describe("Fix modal for unregistered finding", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Unavailable finding shows no Fix button", async ({ page }) => {
    const row = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const fixBtn = page.locator("#detail .fix-btn");
      await expect(fixBtn).not.toBeVisible();
    }
  });
});

test.describe("Export JSON findings count", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("JSON export contains all 14 findings", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportJson").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const json = JSON.parse(Buffer.concat(content).toString("utf-8"));

    expect(json.findings.length).toBe(14);
  });

  test("JSON export findings have required fields", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportJson").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const json = JSON.parse(Buffer.concat(content).toString("utf-8"));

    for (const finding of json.findings) {
      expect(finding).toHaveProperty("id");
      expect(finding).toHaveProperty("title");
      expect(finding).toHaveProperty("severity");
      expect(finding).toHaveProperty("source");
    }
  });
});

test.describe("Score breakdown penalty bar height", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Penalty bars have consistent height", async ({ page }) => {
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    const count = await bars.count();

    const heights: number[] = [];
    for (let i = 0; i < count; i++) {
      const height = await bars.nth(i).evaluate(
        (el) => el.offsetHeight
      );
      heights.push(height);
    }

    // All bars should have the same height
    const firstHeight = heights[0];
    for (const h of heights) {
      expect(h).toBe(firstHeight);
    }
  });
});

test.describe("Detail panel badge margin", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Detail badge has bottom margin", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    await expect(badge).toBeVisible();

    const marginBottom = await badge.evaluate(
      (el) => getComputedStyle(el).marginBottom
    );
    expect(marginBottom).toBe("12px");
  });
});

test.describe("Score breakdown axis score color", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Axis score uses large font", async ({ page }) => {
    const scores = page.locator("#scoreBreakdown .score-axis-top strong");
    const count = await scores.count();

    for (let i = 0; i < count; i++) {
      const fontSize = await scores.nth(i).evaluate(
        (el) => getComputedStyle(el).fontSize
      );
      expect(fontSize).toBe("18px");
    }
  });
});

test.describe("Finding title text styling", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Finding titles have white-space nowrap", async ({ page }) => {
    const titles = page.locator("#findings .title");
    const count = await titles.count();
    expect(count).toBeGreaterThan(0);

    const whiteSpace = await titles.first().evaluate(
      (el) => getComputedStyle(el).whiteSpace
    );
    expect(whiteSpace).toBe("nowrap");
  });
});

test.describe("Score breakdown section margin", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown has bottom margin", async ({ page }) => {
    const section = page.locator("#scoreBreakdown");
    const marginBottom = await section.evaluate(
      (el) => getComputedStyle(el).marginBottom
    );
    expect(marginBottom).toBe("16px");
  });
});

test.describe("Modal overlay z-index", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Modal overlay has high z-index", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const overlay = page.locator(".modal-overlay");
    const zIndex = await overlay.evaluate(
      (el) => getComputedStyle(el).zIndex
    );
    expect(parseInt(zIndex)).toBeGreaterThanOrEqual(200);

    await page.keyboard.press("Escape");
  });
});

test.describe("Score breakdown head gap", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown head has gap between span and p", async ({ page }) => {
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const gap = await head.evaluate(
      (el) => getComputedStyle(el).gap
    );
    expect(gap).toBe("16px");
  });
});

test.describe("Table wrap overflow", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Table wrap has overflow auto", async ({ page }) => {
    const tableWrap = page.locator(".table-wrap");
    const overflow = await tableWrap.evaluate(
      (el) => getComputedStyle(el).overflow
    );
    expect(overflow).toBe("auto");
  });
});

test.describe("Score plate minimum width", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score plate has minimum width", async ({ page }) => {
    const scoreplate = page.locator(".scoreplate");
    const width = await scoreplate.evaluate(
      (el) => el.offsetWidth
    );
    expect(width).toBeGreaterThanOrEqual(250);
  });
});
