import { test, expect, type Page } from "@playwright/test";

async function waitForFindings(page: Page): Promise<void> {
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

async function openHelp(page: Page): Promise<void> {
  await page.keyboard.press("?");
  await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
}

async function openExport(page: Page): Promise<void> {
  await page.keyboard.press("e");
  await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
}

async function clickOverlay(page: Page, modalSelector: string): Promise<void> {
  const modal = page.locator(modalSelector);
  const box = await modal.boundingBox();
  if (!box) throw new Error("modal not visible");
  await page.mouse.click(box.x + 5, box.y + 5);
}

test.describe("Modal overlay click-to-close", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("help modal closes when clicking outside the modal content", async ({
    page,
  }) => {
    await openHelp(page);
    await clickOverlay(page, "#helpModal");
    await expect(page.locator("#helpModal")).not.toBeVisible({ timeout: 2000 });
  });

  test("export modal closes when clicking outside the modal content", async ({
    page,
  }) => {
    await openExport(page);
    await clickOverlay(page, "#exportModal");
    await expect(page.locator("#exportModal")).not.toBeVisible({ timeout: 2000 });
  });

  test("fix modal closes when clicking outside the modal content", async ({
    page,
  }) => {
    const fixableRow = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    await fixableRow.click({ force: true });
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toHaveCount(1);
    await fixBtn.click();
    await expect(page.locator("#fixModal")).toBeVisible({ timeout: 3000 });
    await clickOverlay(page, "#fixModal");
    await expect(page.locator("#fixModal")).not.toBeVisible({ timeout: 2000 });
  });
});

test.describe("Finding selection edge cases", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("clicking a row shows detail panel content", async ({ page }) => {
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    await row.click({ force: true });
    await expect(page.locator("#detail")).not.toBeEmpty();
  });

  test("arrow keys move selection down", async ({ page }) => {
    const firstRow = page.locator("#findings tr[data-index='0']");
    const secondRow = page.locator("#findings tr[data-index='1']");
    await firstRow.click({ force: true });
    const firstId = await firstRow.getAttribute("data-id");
    await page.keyboard.press("ArrowDown");
    const secondId = await secondRow.getAttribute("data-id");
    expect(secondId).not.toEqual(firstId);
  });

  test("escape clears search filter", async ({ page }) => {
    const searchBox = page.locator("#query");
    await searchBox.fill("ssh");
    await expect(searchBox).toHaveValue("ssh");
    await page.keyboard.press("Escape");
    await expect(searchBox).toHaveValue("");
  });
});
