import { test, expect } from "@playwright/test";

// v2.5.1: Tests for fix-action classification and UI behavior.
// These tests cover the contract between fix.Kind, fix.Actions, and the
// UI: Auto (1 action, no choice), Review (≥2 actions, user picks), Manual
// (0 actions, no apply button).
//
// See AGENTS.md "Review = alternatives, NOT stages" for the design rule.
//
// Tests look for ANY row with each remediation label rather than asserting
// specific counts, so they're resilient to fixture changes.

test.describe("Fix action classification", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  // Helper: find the first row index whose last-td.muted text matches `label`.
  // Returns -1 if not found.
  async function findFirstRowByLabel(page: import("@playwright/test").Page, label: string): Promise<number> {
    const rows = page.locator("#findings tr[data-index]");
    const rowCount = await rows.count();
    for (let i = 0; i < rowCount; i++) {
      const text = await rows.nth(i).locator("td.muted").last().textContent();
      if ((text || "").trim().toLowerCase() === label.toLowerCase()) {
        return i;
      }
    }
    return -1;
  }

  test("Review finding modal shows radio buttons for each action", async ({ page }) => {
    const idx = await findFirstRowByLabel(page, "review");
    test.skip(idx < 0, "no Review finding in fixture");

    const rows = page.locator("#findings tr[data-index]");
    await rows.nth(idx).click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    if (!(await fixBtn.isVisible().catch(() => false))) {
      test.skip(true, "this Review finding has no fix registered");
    }
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Review should show ≥2 radio buttons (one per action)
    const radioCount = await modal.locator('input[type="radio"]').count();
    expect(radioCount).toBeGreaterThanOrEqual(2);

    // Confirm button should be disabled until user selects
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeDisabled();

    await modal.locator("#modalFixNo").click();
  });

  test("Auto finding modal does not require user to pick an action", async ({ page }) => {
    const idx = await findFirstRowByLabel(page, "auto");
    test.skip(idx < 0, "no Auto finding in fixture");

    const rows = page.locator("#findings tr[data-index]");
    await rows.nth(idx).click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    if (!(await fixBtn.isVisible().catch(() => false))) {
      test.skip(true, "this Auto finding has no fix registered");
    }
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Auto should show 0 or 1 radio (no user choice needed)
    const radioCount = await modal.locator('input[type="radio"]').count();
    expect(radioCount).toBeLessThanOrEqual(1);

    await modal.locator("#modalFixNo").click();
  });

  test("Manual finding has no Apply button (guidance only)", async ({ page }) => {
    const idx = await findFirstRowByLabel(page, "manual");
    test.skip(idx < 0, "no Manual finding in fixture");

    const rows = page.locator("#findings tr[data-index]");
    await rows.nth(idx).click({ force: true });
    await page.waitForTimeout(300);

    // Manual findings should NOT have a fix button
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).not.toBeVisible();
  });
});
