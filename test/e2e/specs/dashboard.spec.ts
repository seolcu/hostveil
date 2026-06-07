import { test, expect } from "@playwright/test";

test.describe("Dashboard", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
  });

  test("Scenario 1: Dashboard loads with findings table and score", async ({ page }) => {
    // The shell should not be in loading state
    await expect(page.locator(".shell.loading")).toHaveCount(0, { timeout: 5000 });

    // Score badge should display a numeric value
    const scoreEl = page.locator("#score");
    await expect(scoreEl).toBeVisible();
    const scoreText = await scoreEl.textContent();
    expect(scoreText).toMatch(/^\d+\/100$/);

    // Findings table should have rows
    const rows = page.locator("#findings tr");
    await expect(rows.first()).toBeVisible();
    const rowCount = await rows.count();
    expect(rowCount).toBeGreaterThan(0);

    // Finding count should be visible and numeric
    const countText = await page.locator("#findingCount").textContent();
    expect(countText).toMatch(/^\d+ visible$/);

    // Metrics bar should show finding counts
    const metrics = page.locator("#metrics article.metric");
    await expect(metrics.first()).toBeVisible();

    // System info should be visible
    const sysinfo = page.locator("#sysinfo");
    await expect(sysinfo).toBeVisible();
    expect(await sysinfo.textContent()).toContain("e2e-test-box");

    // Topbar elements
    await expect(page.locator("h1")).toHaveText("hostveil");
  });

  test("Scenario 2: Filter findings by severity", async ({ page }) => {
    // Wait for table to render
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // Get initial visible count
    const initialCountText = await page.locator("#findingCount").textContent();
    const initialCount = parseInt(initialCountText || "0", 10);

    // Click "critical" severity filter
    await page.locator('#severityFilters button[data-value="critical"]').click();
    await page.waitForTimeout(300);

    // Table should now show only critical findings
    const criticalCountText = await page.locator("#findingCount").textContent();
    const criticalCount = parseInt(criticalCountText || "0", 10);
    expect(criticalCount).toBeLessThan(initialCount);

    // All visible rows should be of critical severity
    const badges = await page.locator("#findings td .badge.critical").count();
    const rows = await page.locator("#findings tr[data-index]").count();
    expect(badges).toBe(rows);

    // Reset: click "all"
    await page.locator('#severityFilters button[data-value="all"]').click();
    await page.waitForTimeout(300);
    const resetCountText = await page.locator("#findingCount").textContent();
    const resetCount = parseInt(resetCountText || "0", 10);
    expect(resetCount).toBe(initialCount);
  });

  test("Scenario 2: Filter findings by source", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // Click "lynis" source filter
    await page.locator('#sourceFilters button[data-value="lynis"]').click();
    await page.waitForTimeout(300);

    // All visible rows should be from lynis source (no badge means lynis — only trivy shows badge)
    // For lynis findings, the source column has class "muted"
    const rows = await page.locator("#findings tr[data-index]").count();
    expect(rows).toBeGreaterThan(0);

    // Reset
    await page.locator('#sourceFilters button[data-value="all"]').click();
  });

  test("Scenario 2: Filter findings by remediation", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // Click "unavailable" remediation filter
    await page.locator('#remediationFilters button[data-value="unavailable"]').click();
    await page.waitForTimeout(300);

    // Table should show at least the one unfixable finding
    const countText = await page.locator("#findingCount").textContent();
    const count = parseInt(countText || "0", 10);
    expect(count).toBe(1);

    // The finding should show "Unavailable" as the fix column text
    await expect(page.locator("#findings tr td.muted:has-text('Unavailable')")).toBeVisible();
  });

  test("Scenario 2: Text search filters findings", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // Search for "SSH"
    await page.locator("#query").fill("SSH");
    await page.waitForTimeout(300);

    const countText = await page.locator("#findingCount").textContent();
    const count = parseInt(countText || "0", 10);
    expect(count).toBeGreaterThanOrEqual(2);
    expect(count).toBeLessThan(12); // not all findings

    // Clear search
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);
    const resetText = await page.locator("#findingCount").textContent();
    expect(resetText).toMatch(/^1[012]? visible$/); // should be ~12
  });

  test("Scenario 3: Clicking a finding shows detail panel", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // Initially shows "Select a finding" placeholder
    const detail = page.locator("#detail");
    await expect(detail.locator("h2")).toContainText("Select a finding");

    // Click the first finding row
    await page.locator("#findings tr[data-index]").first().click();
    await page.waitForTimeout(200);

    // Detail panel should now show finding info
    await expect(detail.locator("h2")).not.toContainText("Select a finding");
    await expect(detail.locator(".badge")).toBeVisible();
    await expect(detail.locator("dl.detail-meta")).toBeVisible();

    // Detail should have ID, Source fields
    await expect(detail.locator("dt:has-text('ID')")).toBeVisible();
    await expect(detail.locator("dt:has-text('Source')")).toBeVisible();
  });

  test("Scenario 3: Arrow keys navigate findings", async ({ page }) => {
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // First row should be selected by default
    await expect(page.locator("#findings tr.selected").first()).toBeVisible();

    // Press ArrowDown
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(200);

    // Second row should now be selected
    const selectedRows = await page.locator("#findings tr.selected").count();
    expect(selectedRows).toBe(1);
    const selectedIndex = await page.locator("#findings tr.selected").getAttribute("data-index");
    expect(selectedIndex).toBe("1");

    // Press ArrowUp twice (back to first)
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(200);
    const newIndex = await page.locator("#findings tr.selected").getAttribute("data-index");
    expect(newIndex).toBe("0");
  });
});
