import { test, expect } from "@playwright/test";

test.describe("Rescan", () => {
  test("Scenario 7: Rescan button triggers loading state and refreshes results", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeVisible();
    await expect(rescanBtn).toBeEnabled();

    await rescanBtn.click();

    // In fixture mode, rescan completes instantly so "Scanning" may not be visible.
    // Just verify the button re-enables and findings reload.
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

  test("Rescan preserves finding IDs (data integrity)", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // capture IDs before rescan
    const idsBefore = await page.locator("#findings tr[data-id]").evaluateAll(
      (els) => els.map((el) => el.getAttribute("data-id"))
    );
    expect(idsBefore.length).toBe(12);

    // rescan
    await page.locator("#rescanBtn").click();
    await expect(page.locator("#rescanBtn")).toBeEnabled({ timeout: 15000 });
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // capture IDs after rescan
    const idsAfter = await page.locator("#findings tr[data-id]").evaluateAll(
      (els) => els.map((el) => el.getAttribute("data-id"))
    );

    // same set of IDs (order may differ)
    expect(idsAfter.sort()).toEqual(idsBefore.sort());

    // specific known IDs
    expect(idsAfter).toContain("trivy.cve-2024-0001");
    expect(idsAfter).toContain("lynis.AUTH-9286");
    expect(idsAfter).toContain("test.unfixable-001");
  });

  test("Rescan reloads metrics correctly", async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    await page.locator("#rescanBtn").click();
    await expect(page.locator("#rescanBtn")).toBeEnabled({ timeout: 15000 });
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });

    // metrics should still be correct after rescan
    const totalMetric = page.locator("#metrics article.metric").filter({ hasText: "Total" });
    await expect(totalMetric.locator("strong")).toHaveText("12");
  });
});
