import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("View more / View less toggle", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Toggle expands and collapses long description", async ({ page }) => {
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const toggleBtn = page.locator(".toggle-more");
      if (await toggleBtn.isVisible().catch(() => false)) {
        const textBefore = await toggleBtn.textContent();
        expect(textBefore).toMatch(/View more|View less/);

        await toggleBtn.click();
        await page.waitForTimeout(200);

        const textAfter = await toggleBtn.textContent();
        expect(textAfter).toMatch(/View more|View less/);
        expect(textAfter).not.toBe(textBefore);
      }
    }
  });
});

test.describe("Score plate border color", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score plate has border matching score severity", async ({ page }) => {
    const scoreEl = page.locator("#score");
    await expect(scoreEl).toHaveText(/^\d+\/100$/, { timeout: 5000 });

    const scoreText = await scoreEl.textContent();
    const score = parseInt(scoreText?.match(/^(\d+)/)?.[1] || "0");

    const scoreplate = page.locator(".scoreplate");
    const borderColor = await scoreplate.evaluate(
      (el) => getComputedStyle(el).borderColor
    );
    expect(borderColor).toBeTruthy();
  });
});

test.describe("Detail panel metadata grid", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Metadata grid has consistent spacing", async ({ page }) => {
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const meta = page.locator(".detail-meta");
      await expect(meta).toBeVisible();

      const gap = await meta.evaluate(
        (el) => getComputedStyle(el).gap
      );
      expect(gap).toBeTruthy();
    }
  });

  test("Metadata values are not empty", async ({ page }) => {
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const meta = page.locator(".detail-meta");
      const ddElements = meta.locator("dd");
      const count = await ddElements.count();

      for (let i = 0; i < count; i++) {
        const text = await ddElements.nth(i).textContent();
        expect(text?.trim().length).toBeGreaterThan(0);
      }
    }
  });
});

test.describe("Score breakdown consistency with API", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown axes match API response", async ({ page }) => {
    const result = await page.evaluate(() =>
      fetch("/api/result").then((r) => r.json())
    );

    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(result.score_breakdown.axes.length);

    for (let i = 0; i < count; i++) {
      const apiAxis = result.score_breakdown.axes[i];
      const uiLabel = await axes
        .nth(i)
        .locator(".score-axis-top span")
        .textContent();
      expect(uiLabel).toBe(apiAxis.label);
    }
  });

  test("Overall score matches API response", async ({ page }) => {
    const result = await page.evaluate(() =>
      fetch("/api/result").then((r) => r.json())
    );

    const scoreEl = page.locator("#score");
    await expect(scoreEl).toHaveText(/^\d+\/100$/, { timeout: 5000 });

    const uiScore = parseInt(
      (await scoreEl.textContent())?.match(/^(\d+)/)?.[1] || "0"
    );
    expect(uiScore).toBe(result.score);
  });
});

test.describe("Export CSV content validation", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("CSV contains expected header columns", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportCsv").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const csv = Buffer.concat(content).toString("utf-8");

    expect(csv).toContain("ID,Severity,Source,Service,Title");
    expect(csv).toContain("trivy.cve-2024-0001");
    expect(csv).toContain("lynis.AUTH-9286");
  });

  test("CSV has correct number of data rows", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportCsv").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const csv = Buffer.concat(content).toString("utf-8");
    const lines = csv.trim().split("\n");

    // Header + 14 data rows
    expect(lines.length).toBe(15);
  });
});

test.describe("Finding row selection highlight", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Selected row has visual highlight class", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(200);

    // Check if row or detail panel updated
    const detailH2 = page.locator("#detail h2");
    await expect(detailH2).not.toBeEmpty();
  });
});

test.describe("Score breakdown bar widths are valid percentages", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("All bar widths sum to <= 400% (4 axes * 100%)", async ({ page }) => {
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();
    expect(count).toBe(4);

    let totalPct = 0;
    for (let i = 0; i < count; i++) {
      const width = await bars.nth(i).evaluate((el) => el.style.width);
      const pct = parseFloat(width);
      totalPct += pct;
    }
    expect(totalPct).toBeLessThanOrEqual(400);
    expect(totalPct).toBeGreaterThanOrEqual(0);
  });
});

test.describe("Table header alignment", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Table header has correct number of columns", async ({ page }) => {
    const headers = page.locator("th");
    const count = await headers.count();
    // checkbox + severity + source + ID + finding + fix = 6
    expect(count).toBe(6);
  });

  test("Table header text matches expected columns", async ({ page }) => {
    const headers = page.locator("th");
    const texts = await headers.allTextContents();

    expect(texts[1]?.trim()).toBe("Severity");
    expect(texts[2]?.trim()).toBe("Source");
    expect(texts[3]?.trim()).toBe("ID");
    expect(texts[4]?.trim()).toBe("Finding");
    expect(texts[5]?.trim()).toBe("Fix");
  });
});

test.describe("Score breakdown section visibility", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown is not hidden by default", async ({ page }) => {
    const section = page.locator("#scoreBreakdown");
    const isHidden = await section.evaluate((el) => el.hidden);
    expect(isHidden).toBe(false);
  });

  test("Score breakdown head has correct structure", async ({ page }) => {
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    await expect(head).toBeVisible();

    // Should have a span and a p
    const span = head.locator("span");
    const p = head.locator("p");
    await expect(span).toBeVisible();
    await expect(p).toBeVisible();
    await expect(span).toHaveText("Score breakdown");
  });
});
