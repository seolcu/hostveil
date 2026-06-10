import { test, expect } from "@playwright/test";

test.describe("Recalculate", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });
  });

  test("Recalc button recalculates score and shows toast", async ({
    page,
  }) => {
    const recalcBtn = page.locator("#recalcBtn");
    await expect(recalcBtn).toBeVisible();

    const initialScore = await page.locator("#score").textContent();
    expect(initialScore).toMatch(/^\d+\/100$/);

    await recalcBtn.click();
    await page.waitForTimeout(500);

    // toast appears
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    await expect(toast).toContainText("Score recalculated");

    // score is still valid
    const newScore = await page.locator("#score").textContent();
    expect(newScore).toMatch(/^\d+\/100$/);

    // in fixture mode, score should be identical
    expect(newScore).toBe(initialScore);
  });

  test("Score breakdown is present in API response", async ({ page }) => {
    const result = await page.evaluate(() =>
      fetch("/api/result").then((r) => r.json())
    );

    expect(result.score_breakdown).toBeDefined();
    expect(result.score_breakdown.overall).toBe(result.score);
    expect(Array.isArray(result.score_breakdown.axes)).toBe(true);
    expect(result.score_breakdown.axes.length).toBeGreaterThan(0);

    for (const axis of result.score_breakdown.axes) {
      expect(typeof axis.id).toBe("string");
      expect(typeof axis.label).toBe("string");
      expect(typeof axis.score).toBe("number");
      expect(typeof axis.penalty).toBe("number");
      expect(typeof axis.max_penalty).toBe("number");
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
    }
  });

  test("Score class reflects severity tier", async ({ page }) => {
    const scoreEl = page.locator("#score");
    const classAttr = await scoreEl.getAttribute("class");

    // should have one of the severity classes
    const validClasses = ["critical", "high", "medium", "low"];
    const hasValidClass = validClasses.some(
      (cls) => classAttr?.includes(cls) ?? false
    );
    expect(hasValidClass).toBe(true);
  });
});
