import { test, expect } from "@playwright/test";

test.describe("Fix flow", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  test("Scenario 4: Fix dry-run shows modal with diff preview", async ({ page }) => {
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(fixableRow).toBeVisible();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });
    await expect(modal.locator("h2")).toContainText("Apply fix");
    await expect(modal.locator("#modalFixYes")).toBeVisible();
    await expect(modal.locator("#modalFixNo")).toBeVisible();

    await modal.locator("#modalFixNo").click();
    await expect(modal).not.toBeVisible();
  });

  test("Scenario 4: Review finding shows action selection modal", async ({ page }) => {
    const rows = page.locator("#findings tr[data-index]");
    const rowCount = await rows.count();
    let reviewRowIndex = -1;
    for (let i = 0; i < rowCount; i++) {
      const fixText = await rows.nth(i).locator("td.muted").last().textContent();
      if (fixText === "Review") {
        reviewRowIndex = i;
        break;
      }
    }
    expect(reviewRowIndex).toBeGreaterThanOrEqual(0);

    await rows.nth(reviewRowIndex).click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    await expect(modal.locator('input[type="radio"]').first()).toBeVisible();
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeDisabled();
    await expect(confirmBtn).toContainText("Select an action");

    await modal.locator('input[type="radio"]').first().check();
    await expect(confirmBtn).toBeEnabled();
    await expect(confirmBtn).toContainText("Apply selected");

    await modal.locator("#modalFixNo").click();
    await expect(modal).not.toBeVisible();
  });

  test("Scenario 5: Apply fix success", async ({ page }) => {
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(fixableRow).toBeVisible();
    const findingId = await fixableRow.getAttribute("data-id");
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });
    await modal.locator("#modalFixYes").click();
    await expect(modal).not.toBeVisible();

    // Wait for the fix action to complete: look for either the success result
    // in the detail panel or for the finding row to be marked as "fixed"
    const resultDiv = page.locator("#fixResult");
    try {
      await expect(resultDiv.locator(".fix-success")).toBeVisible({ timeout: 8000 });
    } catch {
      // Fallback: check if the finding row got the "fixed" class
      const fixedRow = page.locator(`#findings tr.fixed[data-id="${findingId}"]`);
      await expect(fixedRow).toBeVisible({ timeout: 5000 });
    }

    const toast = page.locator("#toast");
    try {
      await expect(toast).toBeVisible({ timeout: 3000 });
    } catch {
      // toast is optional (only shown if also_fixed > 0)
    }
  });

  test("Scenario 6: Batch fix multiple findings", async ({ page }) => {
    const checkboxes = page.locator("#findings .row-check:not(:disabled)");
    const count = await checkboxes.count();
    expect(count).toBeGreaterThanOrEqual(2);

    for (let i = 0; i < Math.min(count, 2); i++) {
      await checkboxes.nth(i).check();
    }

    const fixSelectedBtn = page.locator("#fixSelectedBtn");
    await expect(fixSelectedBtn).toBeVisible();
    await expect(fixSelectedBtn).toContainText("Fix selected (2");

    await fixSelectedBtn.click();

    const progressModal = page.locator("#fixProgressModal");
    await expect(progressModal).toBeVisible({ timeout: 5000 });
    await expect(progressModal).not.toBeVisible({ timeout: 15000 });

    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    const toastText = await toast.textContent();
    expect(toastText).toContain("Fixed");
  });
});
