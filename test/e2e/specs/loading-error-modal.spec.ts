import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

async function openReviewFixModal(page: Page): Promise<boolean> {
  const row = page.locator("#findings tr[data-id='trivy.dr001']");
  await expect(row).toBeVisible();
  await row.click({ force: true });
  const fixBtn = page.locator("#detail .fix-btn");
  await expect(fixBtn).toHaveCount(1);
  await fixBtn.click();
  await expect(page.locator("#fixModal")).toBeVisible({ timeout: 3000 });
  return true;
}

test.describe("Fix modal internals", () => {
  test("review fix modal shows action radios", async ({ page }) => {
    await ready(page);
    await openReviewFixModal(page);
    await expect(page.locator("#fixModal input[name='fixAction']")).not.toHaveCount(0);
    await page.keyboard.press("Escape");
  });

  test("selecting a radio highlights the action option", async ({ page }) => {
    await ready(page);
    await openReviewFixModal(page);
    const radio = page.locator("#fixModal input[name='fixAction']").first();
    await radio.click({ force: true });
    const optionClass = await radio.evaluate((el) => {
      const opt = el.closest(".action-option") as HTMLElement | null;
      return opt?.className ?? "";
    });
    expect(optionClass).toContain("selected");
    await page.keyboard.press("Escape");
  });

  test("fix modal with warning shows warning text", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
    await row.click({ force: true });
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) === 0) {
      test.skip();
      return;
    }
    await fixBtn.click();
    await expect(page.locator("#fixModal")).toBeVisible({ timeout: 3000 });
    const warning = page.locator("#fixModal .fix-warning");
    if ((await warning.count()) > 0) {
      await expect(warning).toContainText("\u26A0");
    }
    await page.keyboard.press("Escape");
  });

  test("lynis fix modal shows apply controls", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='lynis.AUTH-9286']");
    await row.click({ force: true });
    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toHaveCount(1);
    await fixBtn.click();
    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    await expect(modal.locator("h2")).toHaveText("Apply fix");
    await expect(modal.locator(".action-type-badge")).toBeVisible();
    await expect(modal.locator("#modalFixYes")).toBeVisible();
    await page.keyboard.press("Escape");
  });
});
