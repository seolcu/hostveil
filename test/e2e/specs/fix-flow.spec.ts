import { test, expect } from "@playwright/test";

test.describe("Fix flow", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    // Wait for the table to be fully rendered
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  test("Scenario 4: Fix dry-run shows modal with diff preview", async ({ page }) => {
    // Click a fixable finding (first one that has a fix button)
    const row = page.locator("#findings tr[data-index]").first();
    await row.click();
    await page.waitForTimeout(200);

    // Click the Fix button in the detail panel
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    // Should show fix modal
    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Modal should have "Apply fix" title and action info
    await expect(modal.locator("h2")).toContainText("Apply fix");

    // Modal should have Apply and Cancel buttons
    await expect(modal.locator("#modalFixYes")).toBeVisible();
    await expect(modal.locator("#modalFixNo")).toBeVisible();

    // Close modal via Cancel
    await modal.locator("#modalFixNo").click();
    await expect(modal).not.toBeVisible();
  });

  test("Scenario 4: Review finding shows action selection modal", async ({ page }) => {
    // Find a review-type finding (trivy.dr001 has remediation: review = 2 actions)
    // Click the second row which has "trivy.dr001"
    const rows = page.locator("#findings tr[data-index]");
    const rowCount = await rows.count();
    for (let i = 0; i < rowCount; i++) {
      const row = rows.nth(i);
      const fixText = await row.locator("td.muted").last().textContent();
      if (fixText === "Review") {
        await row.click();
        break;
      }
    }
    await page.waitForTimeout(200);

    // Click the Fix button in the detail panel
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    // Should show action selection modal
    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Should have radio buttons and "Select an action" disabled button
    await expect(modal.locator('input[type="radio"]').first()).toBeVisible();
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeDisabled();
    await expect(confirmBtn).toContainText("Select an action");

    // Select an action
    await modal.locator('input[type="radio"]').first().check();
    await expect(confirmBtn).toBeEnabled();
    await expect(confirmBtn).toContainText("Apply selected");

    // Cancel
    await modal.locator("#modalFixNo").click();
    await expect(modal).not.toBeVisible();
  });

  test("Scenario 5: Apply fix success", async ({ page }) => {
    // Click the first finding row
    const row = page.locator("#findings tr[data-index]").first();
    const findingId = await row.getAttribute("data-id");
    await row.click();
    await page.waitForTimeout(200);

    // Click Fix button
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    // Wait for modal and click Apply
    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });
    await modal.locator("#modalFixYes").click();

    // Wait for fix to apply — success result should appear
    // The finding gets marked as fixed and the result div shows success
    const resultDiv = page.locator("#fixResult");
    await expect(resultDiv.locator(".fix-success")).toBeVisible({ timeout: 10000 });

    // After fix, the finding should be refreshed — table should show "Fixed" text
    // The fixture has another finding with same service (nginx:1.24), so "also_fixed" may appear
    // Instead, verify the finding data was updated
    await page.waitForTimeout(500);

    // The detail panel should reflect the fix was applied
    const successMsg = await resultDiv.locator(".fix-success").textContent();
    expect(successMsg).toContain("Fixed");

    // Toast notification should appear
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
  });

  test("Scenario 6: Batch fix multiple findings", async ({ page }) => {
    // Select two findings via their checkboxes
    const checkboxes = page.locator("#findings .row-check");
    const count = await checkboxes.count();

    let selected = 0;
    for (let i = 0; i < count && selected < 2; i++) {
      const cb = checkboxes.nth(i);
      if (!(await cb.isDisabled())) {
        await cb.check();
        selected++;
      }
      if (selected >= 2) break;
    }

    // Ensure at least 2 were selected
    expect(selected).toBe(2);

    // The "Fix selected" button should appear
    const fixSelectedBtn = page.locator("#fixSelectedBtn");
    await expect(fixSelectedBtn).toBeVisible();
    await expect(fixSelectedBtn).toContainText(`Fix selected (${selected})`);

    // Click batch fix
    await fixSelectedBtn.click();

    // Progress modal should appear
    const progressModal = page.locator("#fixProgressModal");
    await expect(progressModal).toBeVisible({ timeout: 5000 });

    // Wait for progress modal to disappear (batch fix completes)
    await expect(progressModal).not.toBeVisible({ timeout: 15000 });

    // Toast notification should show results
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    const toastText = await toast.textContent();
    expect(toastText).toContain("Fixed");
  });
});
