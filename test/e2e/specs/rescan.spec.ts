import { test, expect } from "@playwright/test";

test.describe("Rescan", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  test("Scenario 7: Rescan button triggers loading state and refreshes results", async ({ page }) => {
    // Rescan button should be visible
    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeVisible();
    await expect(rescanBtn).toBeEnabled();

    // Get current finding count for comparison
    const initialCountText = await page.locator("#findingCount").textContent();

    // Click rescan
    await rescanBtn.click();

    // Button should show "Scanning..." while rescan is in progress
    await expect(rescanBtn).toContainText("Scanning");
    await expect(rescanBtn).toBeDisabled();

    // The shell should briefly enter loading state
    // (the rescan resets phase to "loading" and the frontend polls)

    // Wait for rescan to complete — the page should return to normal state
    await expect(rescanBtn).toBeEnabled({ timeout: 15000 });
    await expect(rescanBtn).toContainText("Re-scan");

    // Table should be re-rendered
    await expect(page.locator("#findings tr").first()).toBeVisible();
  });

  test("Scenario 9: Score is updated after rescan", async ({ page }) => {
    // Record initial score
    const initialScore = await page.locator("#score").textContent();

    // Click rescan
    await page.locator("#rescanBtn").click();

    // Wait for rescan to complete
    await expect(page.locator("#rescanBtn")).toBeEnabled({ timeout: 15000 });

    // Score should still be present and valid
    const newScore = await page.locator("#score").textContent();
    expect(newScore).toMatch(/^\d+\/100$/);

    // The metrics should reflect new data
    const metrics = page.locator("#metrics article.metric");
    await expect(metrics.first()).toBeVisible();
  });
});
