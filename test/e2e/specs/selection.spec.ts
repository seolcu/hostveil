import { test, expect } from "@playwright/test";

test.describe("Selection", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });
  });

  test("Individual checkbox toggles selection", async ({ page }) => {
    const firstCheck = page.locator("#findings .row-check:not(:disabled)").first();
    await expect(firstCheck).toBeVisible();

    // check
    await firstCheck.check();
    await page.waitForTimeout(200);
    await expect(firstCheck).toBeChecked();

    // fix selected button should show count
    const fixBtn = page.locator("#fixSelectedBtn");
    await expect(fixBtn).toContainText("Fix selected (1");

    // uncheck
    await firstCheck.uncheck();
    await page.waitForTimeout(200);
    await expect(firstCheck).not.toBeChecked();
  });

  test("Select-all checkbox checks and unchecks all active findings", async ({
    page,
  }) => {
    const selectAll = page.locator("#selectAllCheck");
    await expect(selectAll).toBeVisible();

    // check all
    await selectAll.check();
    await page.waitForTimeout(300);

    const checkedCount = await page
      .locator("#findings .row-check:checked")
      .count();
    expect(checkedCount).toBeGreaterThanOrEqual(10);

    // uncheck all
    await selectAll.uncheck();
    await page.waitForTimeout(300);

    const uncheckedCount = await page
      .locator("#findings .row-check:checked")
      .count();
    expect(uncheckedCount).toBe(0);
  });

  test("Double-click toggles row-selected class", async ({ page }) => {
    const firstRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(firstRow).toBeVisible();

    // double-click to select
    await firstRow.dblclick({ force: true });
    await page.waitForTimeout(200);
    await expect(firstRow).toHaveClass(/row-selected/);

    // double-click again to deselect
    await firstRow.dblclick({ force: true });
    await page.waitForTimeout(200);
    await expect(firstRow).not.toHaveClass(/row-selected/);
  });

  test("Unfixable finding has no fix button in detail panel", async ({
    page,
  }) => {
    // filter to show only unavailable
    await page.locator('#remediationFilters button[data-value="unavailable"]').click();
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(1);

    // click the row
    await page.locator("#findings tr[data-index='0']").click({ force: true });
    await page.waitForTimeout(300);

    // fix button should not exist
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toHaveCount(0);

    // reset filter
    await page.locator('#remediationFilters button[data-value="all"]').click();
  });

  test("Disabled row checkbox cannot be checked", async ({ page }) => {
    // search for the unfixable finding directly
    await page.locator("#query").fill("unfixable");
    await page.waitForTimeout(500);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);

    // the first matching row should have disabled class
    const row = page.locator("#findings tr[data-index]").first();
    await expect(row).toHaveClass(/disabled/);

    // the checkbox should be disabled
    const checkbox = row.locator(".row-check");
    await expect(checkbox).toBeDisabled();

    // reset
    await page.locator("#clearFilters").click();
  });
});
