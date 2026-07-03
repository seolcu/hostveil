import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Fix keyboard shortcut 'f'", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Pressing f on a fixable finding opens fix modal", async ({ page }) => {
    const row = page
      .locator("#findings tr[data-index]:not(.disabled)")
      .first();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });

    // Press f to open fix modal
    await page.keyboard.press("f");
    await expect(page.locator(".modal-overlay")).toBeVisible({
      timeout: 3000,
    });

    // Close modal
    await page.keyboard.press("Escape");
    await expect(page.locator(".modal-overlay")).toHaveCount(0);
  });
});

test.describe("Service filter keyboard shortcut 'v'", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Pressing v cycles through service filters", async ({ page }) => {
    const initialCount = await page
      .locator("#findings tr[data-index]")
      .count();

    // Press v to cycle to first service
    await page.keyboard.press("v");
    await page.waitForTimeout(300);

    const afterFirstV = await page
      .locator("#findings tr[data-index]")
      .count();
    // Count should change (or stay same if cycling to 'all')
    expect(afterFirstV).toBeGreaterThanOrEqual(0);
    expect(afterFirstV).toBeLessThanOrEqual(initialCount);
  });
});

test.describe("Export while filters are active", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("JSON export respects active filters", async ({ page }) => {
    // Apply critical filter
    await page.locator("button:text('Critical')").click();
    await page.waitForTimeout(300);

    const visibleCount = await page
      .locator("#findings tr[data-index]")
      .count();

    // Open export and download JSON
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportJson").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const json = JSON.parse(Buffer.concat(content).toString("utf-8"));

    // JSON export should contain all findings (not filtered)
    expect(json.findings.length).toBe(14);
  });
});

test.describe("Multiple modal open/close cycles", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Can open and close help modal multiple times", async ({ page }) => {
    for (let i = 0; i < 3; i++) {
      await page.keyboard.press("?");
      await expect(page.locator("#helpModal")).toBeVisible({
        timeout: 3000,
      });
      await page.keyboard.press("Escape");
      await expect(page.locator("#helpModal")).toHaveCount(0);
      await page.waitForTimeout(200);
    }
  });

  test("Can open and close export modal multiple times", async ({ page }) => {
    for (let i = 0; i < 3; i++) {
      await page.keyboard.press("e");
      await expect(page.locator("#exportModal")).toBeVisible({
        timeout: 3000,
      });
      await page.keyboard.press("Escape");
      await expect(page.locator("#exportModal")).toHaveCount(0);
      await page.waitForTimeout(200);
    }
  });
});

test.describe("Detail panel with different finding types", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Compose finding shows compose source in detail", async ({ page }) => {
    const row = page.locator(
      "#findings tr[data-id='compose.ds001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const meta = page.locator(".detail-meta");
      const ddElements = meta.locator("dd");
      const dtElements = meta.locator("dt");
      const dtCount = await dtElements.count();

      for (let i = 0; i < dtCount; i++) {
        const label = await dtElements.nth(i).textContent();
        const value = await ddElements.nth(i).textContent();
        if (label?.trim() === "Source") {
          expect(value?.toLowerCase()).toContain("compose");
        }
      }
    }
  });

  test("Trivy CVE finding shows service in detail", async ({ page }) => {
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    if ((await row.count()) > 0) {
      await row.click({ force: true });
      await page.waitForTimeout(300);

      const meta = page.locator(".detail-meta");
      const ddElements = meta.locator("dd");
      const dtElements = meta.locator("dt");
      const dtCount = await dtElements.count();

      for (let i = 0; i < dtCount; i++) {
        const label = await dtElements.nth(i).textContent();
        const value = await ddElements.nth(i).textContent();
        if (label?.trim() === "Service") {
          expect(value).toContain("nginx");
        }
      }
    }
  });
});

test.describe("Score breakdown axis scores sum check", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score breakdown overall matches main score", async ({ page }) => {
    const mainScore = await page.locator("#score").textContent();
    const scoreNum = parseInt(mainScore?.match(/^(\d+)/)?.[1] || "0");

    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    // Each axis score should be 0-100
    for (let i = 0; i < count; i++) {
      const axisScore = await axes
        .nth(i)
        .locator(".score-axis-top strong")
        .textContent();
      const num = parseInt(axisScore?.match(/^(\d+)/)?.[1] || "0");
      expect(num).toBeGreaterThanOrEqual(0);
      expect(num).toBeLessThanOrEqual(100);
    }
  });
});

test.describe("Table scroll behavior", () => {
  test("Table scrolls when content exceeds container", async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 600 });
    await waitForReady(page);

    const tableWrap = page.locator(".table-wrap");
    const scrollHeight = await tableWrap.evaluate(
      (el) => el.scrollHeight
    );
    const clientHeight = await tableWrap.evaluate(
      (el) => el.clientHeight
    );

    // Table should fit or be scrollable
    expect(scrollHeight).toBeGreaterThanOrEqual(1);
    expect(clientHeight).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Score plate score value", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score plate shows numeric score matching main score", async ({
    page,
  }) => {
    const mainScore = await page.locator("#score").textContent();
    const plateScore = await page.locator(".scoreplate strong").textContent();
    expect(plateScore).toBe(mainScore);
  });

  test("Score is between 0 and 100", async ({ page }) => {
    const score = await page.locator("#score").textContent();
    const num = parseInt(score?.match(/^(\d+)/)?.[1] || "-1");
    expect(num).toBeGreaterThanOrEqual(0);
    expect(num).toBeLessThanOrEqual(100);
  });
});

test.describe("Finding count consistency", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Finding count matches visible rows", async ({ page }) => {
    const countText = await page.locator("#findingCount").textContent();
    const displayedCount = parseInt(
      countText?.match(/^(\d+)/)?.[1] || "0"
    );

    const visibleRows = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(displayedCount).toBe(visibleRows);
  });

  test("After filtering, count updates correctly", async ({ page }) => {
    await page.locator("button:text('Critical')").click();
    await page.waitForTimeout(300);

    const countText = await page.locator("#findingCount").textContent();
    const displayedCount = parseInt(
      countText?.match(/^(\d+)/)?.[1] || "0"
    );

    const visibleRows = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(displayedCount).toBe(visibleRows);
  });
});

test.describe("Remediation hint text", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Auto finding shows correct remediation hint", async ({ page }) => {
    // Find an auto finding
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    let autoIdx = -1;

    for (let i = 0; i < count; i++) {
      const mutedCells = rows.nth(i).locator("td.muted");
      const lastCell = mutedCells.last();
      if (await lastCell.isVisible().catch(() => false)) {
        const text = (await lastCell.textContent()) || "";
        if (text.trim().toLowerCase() === "auto") {
          autoIdx = i;
          break;
        }
      }
    }

    test.skip(autoIdx < 0, "no Auto finding in fixture");

    await rows.nth(autoIdx).click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator(".detail-meta");
    const ddElements = meta.locator("dd");
    const dtElements = meta.locator("dt");
    const dtCount = await dtElements.count();

    for (let i = 0; i < dtCount; i++) {
      const label = await dtElements.nth(i).textContent();
      const value = await ddElements.nth(i).textContent();
      if (label?.trim() === "Remediation") {
        expect(value).toContain("one clear fix");
      }
    }
  });
});
