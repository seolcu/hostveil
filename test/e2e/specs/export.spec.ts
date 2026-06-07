import { test, expect } from "@playwright/test";

test.describe("Export", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  test("Scenario 8: JSON export downloads file", async ({ page }) => {
    // Click Export button
    const exportBtn = page.locator("#exportBtn");
    await expect(exportBtn).toBeVisible();
    await exportBtn.click();

    // Export modal should appear
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible();

    // Click JSON export option
    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      modal.locator("#exportJson").click(),
    ]);

    // Verify download properties
    expect(download.suggestedFilename()).toContain("hostveil-report.json");

    // Read the downloaded content
    const content = await (await download.createReadStream()).toArray();
    const json = Buffer.concat(content).toString("utf-8");
    const data = JSON.parse(json);

    // Verify it has the expected structure
    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("phase", "complete");
    expect(data.findings.length).toBeGreaterThan(0);
  });

  test("Scenario 8: CSV export downloads file", async ({ page }) => {
    // Click Export button
    await page.locator("#exportBtn").click();
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible();

    // Click CSV export option
    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      modal.locator("#exportCsv").click(),
    ]);

    // Verify download properties
    expect(download.suggestedFilename()).toContain("hostveil-report.csv");

    // Read CSV content
    const content = await (await download.createReadStream()).toArray();
    const csv = Buffer.concat(content).toString("utf-8");

    // Verify CSV structure
    expect(csv).toContain("ID,Severity,Source,Service,Title,Remediation,Fixed");
    expect(csv).toContain("trivy.cve-2024-0001");
    expect(csv).toContain("lynis.AUTH-9286");

    // Count data rows
    const lines = csv.trim().split("\n");
    expect(lines.length).toBeGreaterThan(1); // header + at least 1 data row
  });

  test("Scenario 10: Empty state handling", async ({ page }) => {
    // The non-empty state is already verified in dashboard tests.
    // Here we verify that when filters produce no matches,
    // the appropriate empty message is shown.

    // Filter by a non-existent severity value
    // Since the filter chips only show available values, we'll search
    // for something that shouldn't match any finding
    await page.locator("#query").fill("ZZZZ_NONEXISTENT_ZZZZ");
    await page.waitForTimeout(300);

    // Should show "No findings match the current filters" message
    await expect(page.locator("#findings")).toContainText("No findings match");
    const countText = await page.locator("#findingCount").textContent();
    expect(countText).toContain("0 visible");

    // Clear filters should restore all findings
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(200);
    const restoredText = await page.locator("#findingCount").textContent();
    expect(restoredText).not.toContain("0 visible");
  });

  test("Scenario 10: Fixed finding is visually distinct", async ({ page }) => {
    // The fixture has at least one fixed finding (trivy.cve-2024-0003)
    // Find a row with class "fixed"
    const fixedRow = page.locator("#findings tr.fixed");
    await expect(fixedRow.first()).toBeVisible();

    // Fixed findings should show checkmark instead of severity badge
    const checkmark = fixedRow.first().locator("td").first();
    await expect(checkmark).toContainText("✓");

    // The title should have strikethrough styling
    const titleCell = fixedRow.first().locator("td.title");
    const titleHtml = await titleCell.innerHTML();
    expect(titleHtml).toContain("line-through");
  });
});
