import { test, expect } from "@playwright/test";

test.describe("Dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test("Scenario 1: Dashboard loads with findings table and score", async ({ page }) => {
    await expect(page.locator(".shell.loading")).toHaveCount(0, { timeout: 5000 });

    const scoreEl = page.locator("#score");
    await expect(scoreEl).toBeVisible();
    // Score element renders "--" until the scan snapshot is computed; wait for
    // the final numeric form before asserting.
    await expect(scoreEl).toHaveText(/^\d+\/100$/, { timeout: 5000 });
    const scoreText = await scoreEl.textContent();
    expect(scoreText).toMatch(/^\d+\/100$/);

    const rows = page.locator("#findings tr");
    await expect(rows.first()).toBeVisible();
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThan(0);

    const countText = await page.locator("#findingCount").textContent();
    expect(countText).toMatch(/^\d+ visible$/);

    const metrics = page.locator("#metrics article.metric");
    await expect(metrics.first()).toBeVisible();

    const sysinfo = page.locator("#sysinfo");
    await expect(sysinfo).toBeVisible();
    expect(await sysinfo.textContent()).toContain("e2e-test-box");

    await expect(page.locator("h1")).toHaveText("hostveil");
  });

  test("Scenario 2: Filter findings by severity", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    const initialCountText = await page.locator("#findingCount").textContent();
    const initialCount = parseInt(initialCountText || "0", 10);

    await page.locator('#severityFilters button[data-value="critical"]').click();
    await page.waitForTimeout(300);

    const criticalCountText = await page.locator("#findingCount").textContent();
    const criticalCount = parseInt(criticalCountText || "0", 10);
    expect(criticalCount).toBe(2);
    expect(criticalCount).toBeLessThan(initialCount);

    await page.locator('#severityFilters button[data-value="all"]').click();
    await page.waitForTimeout(300);
    const resetCountText = await page.locator("#findingCount").textContent();
    const resetCount = parseInt(resetCountText || "0", 10);
    expect(resetCount).toBe(initialCount);
  });

  test("Scenario 2: Filter findings by source", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    await page.locator('#sourceFilters button[data-value="lynis"]').click();
    await page.waitForTimeout(300);

    const rows = await page.locator("#findings tr[data-index]").count();
    expect(rows).toBeGreaterThan(0);

    await page.locator('#sourceFilters button[data-value="all"]').click();
  });

  test("Scenario 2: Filter findings by remediation", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    await page.locator('#remediationFilters button[data-value="unavailable"]').click();
    await page.waitForTimeout(300);

    const countText = await page.locator("#findingCount").textContent();
    const count = parseInt(countText || "0", 10);
    expect(count).toBe(1);

    await expect(page.locator("#findings tr td.muted:has-text('Unavailable')")).toBeVisible();
  });

  test("Scenario 2: Text search filters findings", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    await page.locator("#query").fill("SSH");
    await page.waitForTimeout(300);

    const countText = await page.locator("#findingCount").textContent();
    const count = parseInt(countText || "0", 10);
    expect(count).toBeGreaterThanOrEqual(2);
    expect(count).toBeLessThan(14);

    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);
    const resetText = await page.locator("#findingCount").textContent();
    expect(resetText).not.toContain("0 visible");
  });

  test("Scenario 3: Clicking a finding shows detail panel", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // First finding is pre-selected; detail panel should show finding info
    const detail = page.locator("#detail");
    await expect(detail.locator("h2")).toBeVisible();
    await expect(detail.locator("dl.detail-meta")).toBeVisible();
    await expect(detail.locator("dt:has-text('ID')")).toBeVisible();
    await expect(detail.locator("dt:has-text('Source')")).toBeVisible();

    // Find the second row and click it — detail should update
    const secondRow = page.locator("#findings tr[data-index='1']");
    await secondRow.click({ force: true });
    await page.waitForTimeout(300);

    // Detail panel should show updated content (the second finding's info)
    const detailH2 = await detail.locator("h2").textContent();
    expect(detailH2?.length).toBeGreaterThan(0);
  });

  test("Scenario 3: Arrow keys navigate findings", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    await expect(page.locator("#findings tr.selected").first()).toBeVisible();

    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(200);

    const selectedCount = await page.locator("#findings tr.selected").count();
    expect(selectedCount).toBe(1);
    const selectedIndex = await page.locator("#findings tr.selected").getAttribute("data-index");
    expect(selectedIndex).toBe("1");

    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(200);
    const newIndex = await page.locator("#findings tr.selected").getAttribute("data-index");
    expect(newIndex).toBe("0");
  });

  test("Metrics panel shows correct finding counts", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    const metrics = page.locator("#metrics article.metric");
    await expect(metrics.first()).toBeVisible();

    // Total = 14 (12 original + 2 compose)
    const totalMetric = metrics.filter({ hasText: "Total" });
    await expect(totalMetric.locator("strong")).toHaveText("14");

    // Critical = 2
    const criticalMetric = metrics.filter({ hasText: "Critical" });
    await expect(criticalMetric.locator("strong")).toHaveText("2");

    // High = 6 (4 original + 2 compose)
    const highMetric = metrics.filter({ hasText: "High" });
    await expect(highMetric.locator("strong")).toHaveText("6");

    // Medium = 4
    const mediumMetric = metrics.filter({ hasText: "Medium" });
    await expect(mediumMetric.locator("strong")).toHaveText("4");

    // Low = 2
    const lowMetric = metrics.filter({ hasText: "Low" });
    await expect(lowMetric.locator("strong")).toHaveText("2");

    // Fixable = 13 (both compose findings are classified as auto by the fix registry)
    const fixableMetric = metrics.filter({ hasText: "Fixable" });
    await expect(fixableMetric.locator("strong")).toHaveText("13");
  });

  test("Score element has severity color class", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    const scoreEl = page.locator("#score");
    const classAttr = await scoreEl.getAttribute("class");
    const validClasses = ["critical", "high", "medium", "low"];
    const hasValidClass = validClasses.some(
      (cls) => classAttr?.includes(cls) ?? false
    );
    expect(hasValidClass).toBe(true);
  });

  test("Sysinfo shows hostname and IP", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    const sysinfo = page.locator("#sysinfo");
    const text = await sysinfo.textContent();
    expect(text).toContain("e2e-test-box");
    expect(text).toContain("192.168.1.100");
  });

  test("Source column renders 'compose' for compose findings, not '2'", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // Source filter chip should be labeled "compose" (not "2")
    const composeChip = page.locator('#sourceFilters button[data-value="compose"]');
    await expect(composeChip).toBeVisible();
    await expect(composeChip).toContainText("Compose");

    // Filter to compose only — at least 1 row
    await composeChip.click();
    await page.waitForTimeout(300);
    const composeRows = page.locator("#findings tr[data-index]");
    expect(await composeRows.count()).toBeGreaterThan(0);

    // Each row's source cell should show "compose" (label uppercases), never "2"
    const sources = await page.locator("#findings td:nth-child(3)").allTextContents();
    for (const s of sources) {
      expect(s.trim().toLowerCase()).toBe("compose");
    }

    // reset
    await page.locator('#sourceFilters button[data-value="all"]').click();
  });
});
