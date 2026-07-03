import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Page refresh resets all state", () => {
  test("refreshing page clears filters and selection", async ({ page }) => {
    await waitForReady(page);

    // Apply a filter
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await chip.click();
    await page.waitForTimeout(200);

    // Verify filter is applied
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    // Refresh
    await page.reload();
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });

    // All findings should be back
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Finding ID short form in table", () => {
  test("table shows short ID (after last dot)", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    const idCell = row.locator(".id");
    const text = await idCell.textContent();
    // shortId extracts after last dot
    expect(text).toContain("AUTH-9286");
  });
});

test.describe("Finding title in table is escaped", () => {
  test("titles with special chars render safely", async ({ page }) => {
    await waitForReady(page);
    // All finding titles should render without XSS
    const titles = page.locator("#findings .title");
    const count = await titles.count();
    expect(count).toBe(14);

    // No script tags should exist in the DOM
    const scriptCount = await page.locator("#findings script").count();
    expect(scriptCount).toBe(0);
  });
});

test.describe("Detail panel XSS protection", () => {
  test("description is rendered as text, not HTML", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    // No script tags in detail
    const scriptCount = await page.locator("#detail script").count();
    expect(scriptCount).toBe(0);

    // Description should contain the actual text
    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("remote code execution");
  });
});

test.describe("Score breakdown visible when findings exist", () => {
  test("score breakdown is not hidden on load", async ({ page }) => {
    await waitForReady(page);
    const breakdown = page.locator("#scoreBreakdown");
    const hidden = await breakdown.getAttribute("hidden");
    expect(hidden).toBeNull();
  });
});

test.describe("Filter chip click resets selection", () => {
  test("clicking a filter chip resets selected index to 0", async ({
    page,
  }) => {
    await waitForReady(page);

    // Move selection down
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(200);

    // Click a filter chip
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "High" });
    await chip.click();
    await page.waitForTimeout(200);

    // Selection should be on first row
    const selectedRow = page.locator("#findings tr.selected");
    const idx = await selectedRow.getAttribute("data-index");
    expect(idx).toBe("0");
  });
});

test.describe("Export modal JSON download", () => {
  test("JSON export triggers download with correct filename", async ({
    page,
  }) => {
    await waitForReady(page);
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportJson").click(),
    ]);

    const filename = download.suggestedFilename();
    expect(filename).toContain("hostveil-report.json");
  });
});

test.describe("Export modal CSV download", () => {
  test("CSV export triggers download with correct filename", async ({
    page,
  }) => {
    await waitForReady(page);
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportCsv").click(),
    ]);

    const filename = download.suggestedFilename();
    expect(filename).toContain("hostveil-report.csv");
  });
});

test.describe("Detail panel shows all remediation hints", () => {
  test("auto finding shows one clear fix hint", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("one clear fix");
  });

  test("review finding shows multiple options hint", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("multiple options");
  });

  test("unavailable finding shows not yet classified hint", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("not yet classified");
  });
});

test.describe("Metrics critical and high counts", () => {
  test("critical metric shows 2", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    for (let i = 0; i < count; i++) {
      const text = await metrics.nth(i).textContent();
      if (text.includes("Critical")) {
        expect(text).toContain("2");
        return;
      }
    }
    throw new Error("Critical metric not found");
  });

  test("high metric shows 6", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    for (let i = 0; i < count; i++) {
      const text = await metrics.nth(i).textContent();
      if (text.includes("High")) {
        expect(text).toContain("6");
        return;
      }
    }
    throw new Error("High metric not found");
  });
});

test.describe("Score plate has correct layout", () => {
  test("score plate contains score-label and score value", async ({
    page,
  }) => {
    await waitForReady(page);
    const scoreplate = page.locator(".scoreplate");
    await expect(scoreplate).toBeVisible();

    const label = scoreplate.locator(".score-label");
    await expect(label).toBeVisible();

    const score = page.locator("#score");
    await expect(score).toBeVisible();
  });
});

test.describe("Topbar renders correctly", () => {
  test("topbar has h1 with hostveil", async ({ page }) => {
    await waitForReady(page);
    const h1 = page.locator(".topbar h1");
    await expect(h1).toBeVisible();
    await expect(h1).toContainText("hostveil");
  });

  test("topbar has sysinfo", async ({ page }) => {
    await waitForReady(page);
    const sysinfo = page.locator("#sysinfo");
    await expect(sysinfo).toBeVisible();
  });
});
