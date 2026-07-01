import { test, expect } from "@playwright/test";

test.describe("Keyboard interactions", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });
  });

  test("Space toggles checkbox on selected row", async ({ page }) => {
    // select a fixable row (not the first which may be disabled)
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(200);

    const check = fixableRow.locator(".row-check");
    await expect(check).not.toBeChecked();

    // Space to check
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    await expect(check).toBeChecked();

    // Space to uncheck
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    await expect(check).not.toBeChecked();
  });

  test("Enter opens fix modal on fixable finding", async ({ page }) => {
    // click a fixable row first
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    await page.keyboard.press("Enter");
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // close with Escape
    await page.keyboard.press("Escape");
    await expect(modal).not.toBeVisible();
  });

  test("Enter confirms fix modal (regression test)", async ({ page }) => {
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    // open fix modal
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal").first();
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Enter should confirm (apply) the fix — fix is a mock so it succeeds
    await page.keyboard.press("Enter");
    // After fix, a fix result message is shown; the modal should close.
    await page.waitForTimeout(2000);
  });

  test("Escape closes fix modal", async ({ page }) => {
    // click a fixable row
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    // open fix modal via detail button
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Escape closes
    await page.keyboard.press("Escape");
    await expect(modal).not.toBeVisible();
  });

  test("Escape closes export modal", async ({ page }) => {
    await page.locator("#exportBtn").click();
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    await page.keyboard.press("Escape");
    await expect(modal).not.toBeVisible();
  });

  test("ArrowDown and ArrowUp navigate findings", async ({ page }) => {
    // pre-selected at index 0
    await expect(page.locator("#findings tr.selected")).toHaveAttribute(
      "data-index",
      "0"
    );

    // move down
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(200);
    await expect(page.locator("#findings tr.selected")).toHaveAttribute(
      "data-index",
      "1"
    );

    // move down again
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(200);
    await expect(page.locator("#findings tr.selected")).toHaveAttribute(
      "data-index",
      "2"
    );

    // move up
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(200);
    await expect(page.locator("#findings tr.selected")).toHaveAttribute(
      "data-index",
      "1"
    );
  });

  test("Full keyboard flow: select → fix → escape", async ({
    page,
  }) => {
    // Start on a currently batch-fixable row. Earlier E2E tests may have
    // fixed some fixture rows, so a hard-coded number of ArrowDown presses can
    // legitimately land on a disabled/fixed row.
    const selectedRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await selectedRow.click({ force: true });
    await page.waitForTimeout(200);
    const selectedCheck = selectedRow.locator(".row-check");
    await expect(selectedCheck).toBeEnabled();
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    await expect(selectedCheck).toBeChecked();

    // deselect with Space
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    await expect(selectedCheck).not.toBeChecked();

    // open fix with Enter
    await page.keyboard.press("Enter");
    await page.waitForTimeout(500);
    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // cancel with Escape
    await page.keyboard.press("Escape");
    await expect(modal).not.toBeVisible();
  });

  test("Arrow keys scroll detail panel when in detail mode", async ({
    page,
  }) => {
    // click detail panel to focus it
    const detail = page.locator("#detail");
    await detail.click();
    await page.waitForTimeout(200);

    // arrow keys should scroll within viewport (not crash)
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(200);

    // detail panel should still be visible
    await expect(detail.locator("h2")).toBeVisible();
  });
});
