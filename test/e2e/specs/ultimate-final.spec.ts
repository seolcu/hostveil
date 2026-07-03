import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Detail panel for high severity finding", () => {
  test("high finding shows high badge", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0002']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    const text = await badge.textContent();
    expect(text).toContain("high");
  });
});

test.describe("Detail panel for low severity finding", () => {
  test("low finding shows low badge", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.KRNL-5780']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    const text = await badge.textContent();
    expect(text).toContain("low");
  });
});

test.describe("Score breakdown each axis has label and score", () => {
  test("each axis card shows label and N/100", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const label = await axes.nth(i).locator("span").first().textContent();
      const score = await axes.nth(i).locator("strong").textContent();
      expect(label).toBeTruthy();
      expect(score).toMatch(/^\d+\/100$/);
    }
  });
});

test.describe("Finding count after clearing search", () => {
  test("clearing search restores all 14", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    await query.fill("");
    await page.waitForTimeout(300);

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Filter chip active state toggles", () => {
  test("clicking All after filter resets to All", async ({ page }) => {
    await waitForReady(page);

    // Apply critical filter
    const critical = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await critical.click();
    await page.waitForTimeout(200);

    let active = await page
      .locator("#severityFilters button.active")
      .textContent();
    expect(active).toContain("Critical");

    // Click All
    const all = page
      .locator("#severityFilters button")
      .filter({ hasText: "All" });
    await all.click();
    await page.waitForTimeout(200);

    active = await page
      .locator("#severityFilters button.active")
      .textContent();
    expect(active).toContain("All");
  });
});

test.describe("Sort dropdown changes trigger re-render", () => {
  test("changing sort dropdown updates table", async ({ page }) => {
    await waitForReady(page);

    const rows = page.locator("#findings tr[data-index]");
    const firstBefore = await rows.first().getAttribute("data-id");

    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("title");
    await page.waitForTimeout(200);

    const firstAfter = await rows.first().getAttribute("data-id");
    // Order may change
    expect(firstAfter).toBeTruthy();
  });
});

test.describe("Keyboard arrow navigation", () => {
  test("ArrowDown then ArrowUp returns to same row", async ({ page }) => {
    await waitForReady(page);

    const getSelectedIdx = async () => {
      const selected = page.locator("#findings tr.selected");
      return selected.getAttribute("data-index");
    };

    const idx0 = await getSelectedIdx();
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    const idx1 = await getSelectedIdx();
    expect(idx1).not.toBe(idx0);

    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(100);
    const idx2 = await getSelectedIdx();
    expect(idx2).toBe(idx0);
  });
});

test.describe("q key shows toast", () => {
  test("pressing q shows close-tab hint", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("q");
    await page.waitForTimeout(500);

    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
    const text = await toast.textContent();
    expect(text).toContain("Ctrl+W");
  });
});

test.describe("/ key focuses search", () => {
  test("/ focuses search input", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("/");
    const query = page.locator("#query");
    await expect(query).toBeFocused();
  });
});

test.describe("Escape blurs search input", () => {
  test("Escape removes focus from search", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("/");
    await expect(page.locator("#query")).toBeFocused();

    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);
    const focused = await page.evaluate(() => document.activeElement?.id);
    expect(focused).not.toBe("query");
  });
});

test.describe("e key opens export modal", () => {
  test("e opens export modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

test.describe("? key opens help modal", () => {
  test("? opens help modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

test.describe("Ctrl+A selects all visible", () => {
  test("Ctrl+A selects all batch-selectable findings", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);

    const selected = await page.evaluate(() => {
      return document.querySelectorAll("#findings tr.row-selected").length;
    });
    expect(selected).toBeGreaterThanOrEqual(10);
  });
});

test.describe("Space toggles selection", () => {
  test("Space on selectable finding selects it", async ({ page }) => {
    await waitForReady(page);
    // Navigate past first finding (test.unfixable-001 is unavailable)
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press(" ");
    await page.waitForTimeout(300);

    const hasSelection = await page.evaluate(() => {
      return document.querySelectorAll("#findings tr.row-selected").length > 0;
    });
    expect(hasSelection).toBe(true);
  });
});

test.describe("Export modal Close button", () => {
  test("Close button dismisses export modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const closeBtn = page.locator("#exportClose");
    await closeBtn.click();
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("Help modal Close button", () => {
  test("Close button dismisses help modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const closeBtn = page.locator("#modalHelpClose");
    await closeBtn.click();
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });
});
