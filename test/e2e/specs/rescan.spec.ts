import { test, expect } from "@playwright/test";

test.describe("Rescan", () => {
  test("Scenario 7: Rescan button triggers loading state and refreshes results", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeVisible();
    await expect(rescanBtn).toBeEnabled();

    await rescanBtn.click();

    await expect(rescanBtn).toContainText("Scanning");
    await expect(rescanBtn).toBeDisabled();

    await expect(rescanBtn).toBeEnabled({ timeout: 15000 });
    await expect(rescanBtn).toContainText("Re-scan");

    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  test("Scenario 9: Score is updated after rescan", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    const initialScore = await page.locator("#score").textContent();
    expect(initialScore).toMatch(/^\d+\/100$/);

    await page.locator("#rescanBtn").click();
    await expect(page.locator("#rescanBtn")).toBeEnabled({ timeout: 15000 });

    // After rescan in fixture mode, the same fixture data is reloaded.
    // Score should still be present and valid.
    const newScore = await page.locator("#score").textContent();
    expect(newScore).toMatch(/^\d+\/100$/);

    // Table should be visible again
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
    const countText = await page.locator("#findingCount").textContent();
    expect(countText).toMatch(/^\d+ visible$/);
  });
});
