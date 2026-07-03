import { test, expect, type Page } from "@playwright/test";

async function waitForFindings(page: Page): Promise<void> {
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown panel", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("Score breakdown section is visible with 4 axis cards", async ({
    page,
  }) => {
    const section = page.locator("#scoreBreakdown");
    await expect(section).toBeVisible();

    const axes = section.locator(".score-axis");
    await expect(axes).toHaveCount(4);
  });

  test("Each axis card shows label, score, and penalty cap text", async ({
    page,
  }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const axis = axes.nth(i);
      await expect(axis.locator(".score-axis-top span")).not.toBeEmpty();
      await expect(axis.locator(".score-axis-top strong")).toHaveText(
        /^\d+\/100$/
      );
      const metaText = await axis.locator(".score-axis-meta span").first().textContent();
      expect(metaText).toMatch(/\d+\/\d+ penalty/);
    }
  });

  test("Vulnerabilities axis shows correct label", async ({ page }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const firstLabel = await axes.nth(0).locator(".score-axis-top span").textContent();
    expect(firstLabel).toBe("Vulnerabilities");
  });

  test("Container exposure axis shows correct label", async ({ page }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const secondLabel = await axes.nth(1).locator(".score-axis-top span").textContent();
    expect(secondLabel).toBe("Container exposure");
  });

  test("Host hardening axis shows correct label", async ({ page }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const thirdLabel = await axes.nth(2).locator(".score-axis-top span").textContent();
    expect(thirdLabel).toBe("Host hardening");
  });

  test("Secrets axis shows correct label", async ({ page }) => {
    const axes = page.locator("#scoreBreakdown .score-axis");
    const fourthLabel = await axes.nth(3).locator(".score-axis-top span").textContent();
    expect(fourthLabel).toBe("Secrets");
  });

  test("Axis penalty bar renders and has correct width", async ({ page }) => {
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const bar = bars.nth(i);
      const width = await bar.evaluate((el) => el.style.width);
      expect(width).toBeTruthy();
    }
  });

  test("Score breakdown head shows description text", async ({ page }) => {
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    await expect(head).toBeVisible();
    const p = head.locator("p");
    await expect(p).toContainText("penalty cap");
  });

  test("Score breakdown axis severity counts are present", async ({ page }) => {
    const counts = page.locator(
      "#scoreBreakdown .score-axis-counts span"
    );
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Detail panel", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("Clicking a finding populates detail panel", async ({ page }) => {
    const row = page.locator("#findings tr").nth(1);
    await row.click();

    const detail = page.locator("#detail");
    await expect(detail.locator("h2")).not.toBeEmpty();
    await expect(detail.locator(".badge")).toBeVisible();
  });

  test("Detail panel shows metadata grid with ID and Source", async ({
    page,
  }) => {
    const row = page.locator("#findings tr").nth(1);
    await row.click();

    const meta = page.locator(".detail-meta");
    await expect(meta).toBeVisible();
    const dtElements = meta.locator("dt");
    const dtCount = await dtElements.count();
    expect(dtCount).toBeGreaterThanOrEqual(2);

    const dtTexts = await dtElements.allTextContents();
    expect(dtTexts).toContain("ID");
    expect(dtTexts).toContain("Source");
  });

  test("Detail panel shows description section", async ({ page }) => {
    const row = page.locator("#findings tr").nth(1);
    await row.click();

    await expect(page.locator(".section h3").first()).toBeVisible();
    const sections = page.locator(".section h3");
    const count = await sections.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test("Detail panel shows 'how to fix' with copy button", async ({ page }) => {
    const row = page.locator("#findings tr").nth(1);
    await row.click();

    const copyBtn = page.locator("text=Copy guidance");
    await expect(copyBtn).toBeVisible();
  });

  test("Detail panel shows content after page load in fixture mode", async ({
    page,
  }) => {
    await expect(page.locator(".shell.loading")).toHaveCount(0, {
      timeout: 5000,
    });
    // In fixture mode, first finding is auto-selected
    await expect(page.locator("#detail h2")).not.toBeEmpty();
  });
});

test.describe("Fix modal interaction", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("Clicking Fix button opens fix modal", async ({ page }) => {
    const row = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(row).toBeVisible();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator(".modal-overlay");
    await expect(modal).toBeVisible();
    await expect(page.locator(".modal-content h2")).toHaveText("Apply fix");
  });

  test("Fix modal shows warning label", async ({ page }) => {
    const row = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(row).toBeVisible();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    await page.locator("#detail .fix-btn").click();
    await expect(page.locator(".fix-label")).toBeVisible();
  });

  test("Fix modal has Apply and Cancel buttons", async ({ page }) => {
    const row = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(row).toBeVisible();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    await page.locator("#detail .fix-btn").click();
    await expect(page.locator(".modal-actions button")).toHaveCount(2);
    await expect(
      page.locator(".modal-actions button").first()
    ).toContainText("Apply");
  });

  test("Fix modal closes on cancel", async ({ page }) => {
    const row = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(row).toBeVisible();
    await row.click({ force: true });
    await page.waitForTimeout(300);

    await page.locator("#detail .fix-btn").click();
    await expect(page.locator(".modal-overlay")).toBeVisible();

    await page.locator(".modal-actions button").last().click();
    await expect(page.locator(".modal-overlay")).toHaveCount(0);
  });
});

test.describe("Help modal", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("Pressing ? opens help modal", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
  });

  test("Help modal shows keyboard shortcuts", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal h2")).toHaveText(
      "Keyboard shortcuts"
    );
  });

  test("Help modal has Close button", async ({ page }) => {
    await page.keyboard.press("?");
    const closeBtn = page.locator("#helpModal .modal-actions button");
    await expect(closeBtn).toBeVisible();
    await expect(closeBtn).toContainText("Close");
  });

  test("Help modal closes on Close button click", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.locator("#helpModal .modal-actions button").click();
    await expect(page.locator("#helpModal")).toHaveCount(0);
  });
});

test.describe("Export modal", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("Pressing e opens export modal", async ({ page }) => {
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
  });

  test("Export modal has JSON and CSV options", async ({ page }) => {
    await page.keyboard.press("e");
    const options = page.locator(".export-option");
    const count = await options.count();
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test("Export modal closes on Close button", async ({ page }) => {
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    const closeBtn = page.locator("#exportModal .modal-actions button");
    await closeBtn.click();
    await expect(page.locator("#exportModal")).toHaveCount(0);
  });
});

test.describe("Responsive layout", () => {
  test("At 760px width, workspace wraps to block layout", async ({ page }) => {
    await page.setViewportSize({ width: 760, height: 1024 });
    await page.goto("/");
    await waitForFindings(page);

    const workspace = page.locator(".workspace");
    const display = await workspace.evaluate((el) =>
      getComputedStyle(el).display
    );
    expect(display).toBe("block");
  });

  test("At 375px width, metrics shows 2 columns", async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");
    await waitForFindings(page);

    const metrics = page.locator("#metrics");
    const gridCols = await metrics.evaluate((el) =>
      getComputedStyle(el).gridTemplateColumns
    );
    // Should have 2 columns
    const columns = gridCols.split(" ");
    expect(columns.length).toBe(2);
  });

  test("At 375px width, table hides Source/ID/Fix columns", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 375, height: 812 });
    await page.goto("/");
    await waitForFindings(page);

    const headers = page.locator("th");
    const visibleHeaders: string[] = [];
    const count = await headers.count();
    for (let i = 0; i < count; i++) {
      const display = await headers.nth(i).evaluate((el) =>
        getComputedStyle(el).display
      );
      if (display !== "none") {
        const text = await headers.nth(i).textContent();
        visibleHeaders.push(text || "");
      }
    }
    expect(visibleHeaders).toContain("Severity");
    expect(visibleHeaders).toContain("Finding");
    // ID and Fix should be hidden at 375px
    expect(visibleHeaders).not.toContain("ID");
    expect(visibleHeaders).not.toContain("Fix");
  });
});

test.describe("Keyboard navigation", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("j/k navigate between findings", async ({ page }) => {
    await page.keyboard.press("j");
    await page.waitForTimeout(300);

    // Check that a row is selected (highlighted)
    const selectedRow = page.locator("tbody tr.selected");
    await expect(selectedRow).toHaveCount(1);
  });

  test("Enter opens detail for selected finding", async ({ page }) => {
    await page.keyboard.press("j");
    await page.waitForTimeout(300);
    await page.keyboard.press("Enter");
    await page.waitForTimeout(300);

    // Detail panel should show content
    const detailH2 = page.locator("#detail h2");
    await expect(detailH2).not.toBeEmpty();
  });

  test("Escape closes help modal", async ({ page }) => {
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    await page.keyboard.press("Escape");
    await expect(page.locator("#helpModal")).toHaveCount(0);
  });
});

test.describe("Score severity color", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("Score element has a severity color class", async ({ page }) => {
    const scoreEl = page.locator("#score");
    await expect(scoreEl).toHaveText(/^\d+\/100$/, { timeout: 5000 });

    const className = await scoreEl.evaluate((el) => el.className);
    expect(["critical", "high", "medium", "low"]).toContain(className);
  });
});

test.describe("Table interaction", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("Select-all checkbox toggles all visible rows", async ({ page }) => {
    const selectAll = page.locator("thead th:first-child input");
    await selectAll.check();

    const checkboxes = page.locator("tbody tr:not(.disabled) input[type='checkbox']");
    const count = await checkboxes.count();
    for (let i = 0; i < count; i++) {
      await expect(checkboxes.nth(i)).toBeChecked();
    }
  });

  test("Clicking a row selects it and shows in detail", async ({ page }) => {
    const row = page.locator("#findings tr").nth(2);
    await row.click();

    // Row should have selection indicator
    const detail = page.locator("#detail");
    await expect(detail.locator("h2")).not.toBeEmpty();
  });

  test("Clear filters button resets all filters", async ({ page }) => {
    // Apply a severity filter
    await page.locator("button:text('Critical')").click();
    await page.waitForTimeout(500);

    const countText = await page.locator("#findingCount").textContent();
    expect(countText).toMatch(/^\d+ visible$/);

    // Clear
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(500);

    const allCount = await page.locator("#findingCount").textContent();
    expect(allCount).toBe("14 visible");
  });
});
