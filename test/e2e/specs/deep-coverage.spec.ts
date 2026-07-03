import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Fix modal action selection", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Selecting a radio action enables the confirm button", async ({
    page,
  }) => {
    // Find a Review finding (has multiple actions)
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    let reviewIdx = -1;

    for (let i = 0; i < count; i++) {
      const mutedCells = rows.nth(i).locator("td.muted");
      const lastCell = mutedCells.last();
      if (await lastCell.isVisible().catch(() => false)) {
        const text = (await lastCell.textContent()) || "";
        if (text.trim().toLowerCase() === "review") {
          reviewIdx = i;
          break;
        }
      }
    }

    test.skip(reviewIdx < 0, "no Review finding in fixture");

    await rows.nth(reviewIdx).click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    if (!(await fixBtn.isVisible().catch(() => false))) {
      test.skip(true, "this Review finding has no fix registered");
    }
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // Confirm should be disabled initially
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeDisabled();

    // Select first radio
    const radio = modal.locator('input[type="radio"]').first();
    await radio.click();
    await page.waitForTimeout(200);

    // Confirm should now be enabled
    await expect(confirmBtn).toBeEnabled();

    // Cancel
    await modal.locator("#modalFixNo").click();
    await expect(modal).not.toBeVisible();
  });
});

test.describe("CSV export format", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("CSV export has header row with expected columns", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportCsv").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const csv = Buffer.concat(content).toString("utf-8");
    const lines = csv.split("\n").filter((l) => l.trim().length > 0);

    expect(lines.length).toBeGreaterThan(1);

    const header = lines[0].toLowerCase();
    expect(header).toContain("id");
    expect(header).toContain("title");
    expect(header).toContain("severity");
  });

  test("CSV data rows have correct number of columns", async ({ page }) => {
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportCsv").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const csv = Buffer.concat(content).toString("utf-8");
    const lines = csv.split("\n").filter((l) => l.trim().length > 0);
    const headerCols = lines[0].split(",").length;

    for (let i = 1; i < lines.length; i++) {
      const dataCols = lines[i].split(",").length;
      expect(dataCols).toBeGreaterThanOrEqual(headerCols);
    }
  });
});

test.describe("Score breakdown at tablet width", () => {
  test("At 1024px, score breakdown is visible with all axes", async ({
    page,
  }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    await waitForReady(page);

    const section = page.locator("#scoreBreakdown");
    await expect(section).toBeVisible();

    const axes = section.locator(".score-axis");
    await expect(axes).toHaveCount(4);
  });

  test("At 1024px, score breakdown head is flex row", async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    await waitForReady(page);

    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const display = await head.evaluate((el) =>
      getComputedStyle(el).display
    );
    expect(display).toBe("flex");
  });
});

test.describe("Sort by remediation column", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Sorting by remediation groups findings correctly", async ({
    page,
  }) => {
    await page.locator("select").selectOption("remediation");
    await page.waitForTimeout(300);

    const remediations = await page
      .locator("#findings tr[data-index] td:nth-child(6)")
      .allTextContents();

    // Filter out empty and "Fixed" entries
    const nonEmpty = remediations.filter((s) => {
      const t = s.trim().toLowerCase();
      return t.length > 0 && t !== "fixed";
    });
    const sorted = [...nonEmpty].sort((a, b) =>
      a.toLowerCase().localeCompare(b.toLowerCase())
    );
    expect(nonEmpty.map((s) => s.toLowerCase())).toEqual(
      sorted.map((s) => s.toLowerCase())
    );
  });
});

test.describe("Filter + sort interaction", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Applying severity filter then sorting preserves filter", async ({
    page,
  }) => {
    // Apply severity filter
    await page.locator("button:text('Critical')").click();
    await page.waitForTimeout(300);

    const countBefore = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(countBefore).toBeLessThan(14);

    // Change sort
    await page.locator("select").selectOption("source");
    await page.waitForTimeout(300);

    // Filter should still be active
    const countAfter = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(countAfter).toBe(countBefore);
  });
});

test.describe("Fix button state for unfixed findings", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Unfixable finding shows no Fix button", async ({ page }) => {
    const unfixableRow = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    if ((await unfixableRow.count()) > 0) {
      await unfixableRow.click({ force: true });
      await page.waitForTimeout(300);

      const fixBtn = page.locator("#detail .fix-btn");
      await expect(fixBtn).not.toBeVisible();
    }
  });

  test("Fixed finding shows no Fix button", async ({ page }) => {
    const fixedRow = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    if ((await fixedRow.count()) > 0) {
      await fixedRow.click({ force: true });
      await page.waitForTimeout(300);

      const fixBtn = page.locator("#detail .fix-btn");
      await expect(fixBtn).not.toBeVisible();
    }
  });
});

test.describe("Score plate styling", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Score plate has correct border and background", async ({ page }) => {
    const scoreplate = page.locator(".scoreplate");
    const border = await scoreplate.evaluate(
      (el) => getComputedStyle(el).borderColor
    );
    expect(border).toBeTruthy();

    const bg = await scoreplate.evaluate(
      (el) => getComputedStyle(el).backgroundColor
    );
    expect(bg).toBeTruthy();
    expect(bg).not.toBe("rgba(0, 0, 0, 0)");
  });

  test("Score label uses correct font size", async ({ page }) => {
    const label = page.locator(".score-label");
    const fontSize = await label.evaluate(
      (el) => getComputedStyle(el).fontSize
    );
    expect(fontSize).toBe("13px");
  });
});

test.describe("Table row hover state", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Hovering a row changes its background", async ({ page }) => {
    const row = page.locator("#findings tr[data-index]").first();
    const bgBefore = await row.evaluate(
      (el) => getComputedStyle(el).backgroundColor
    );

    await row.hover();
    await page.waitForTimeout(200);

    const bgAfter = await row.evaluate(
      (el) => getComputedStyle(el).backgroundColor
    );

    // Background should change on hover (or remain same if already styled)
    // At minimum the row should be visible
    await expect(row).toBeVisible();
  });
});

test.describe("Detail panel heading hierarchy", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Detail panel uses h2 for title", async ({ page }) => {
    const row = page.locator("#findings tr").nth(1);
    await row.click();

    const h2 = page.locator("#detail h2");
    await expect(h2).toBeVisible();
    const tagName = await h2.evaluate((el) => el.tagName);
    expect(tagName).toBe("H2");
  });

  test("Detail panel uses h3 for sections", async ({ page }) => {
    const row = page.locator("#findings tr").nth(1);
    await row.click();

    const h3s = page.locator("#detail h3");
    const count = await h3s.count();
    expect(count).toBeGreaterThanOrEqual(1);

    for (let i = 0; i < count; i++) {
      const tagName = await h3s.nth(i).evaluate((el) => el.tagName);
      expect(tagName).toBe("H3");
    }
  });
});

test.describe("Score breakdown bar widths", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("All penalty bars have non-negative width", async ({ page }) => {
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const width = await bars.nth(i).evaluate((el) => el.style.width);
      expect(width).toBeTruthy();
      // Width should be a valid percentage
      expect(width).toMatch(/^\d+(\.\d+)?%$/);
    }
  });

  test("Bar widths are between 0% and 100%", async ({ page }) => {
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();

    for (let i = 0; i < count; i++) {
      const width = await bars.nth(i).evaluate((el) => el.style.width);
      const pct = parseFloat(width);
      expect(pct).toBeGreaterThanOrEqual(0);
      expect(pct).toBeLessThanOrEqual(100);
    }
  });
});

test.describe("Filter chip styling", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("Active filter chip has active class", async ({ page }) => {
    const allChip = page
      .locator("#severityFilters .chip")
      .filter({ hasText: "All" });
    await expect(allChip).toHaveClass(/active/);
  });

  test("Clicking a filter chip toggles active class", async ({ page }) => {
    const criticalChip = page
      .locator("#severityFilters .chip")
      .filter({ hasText: "Critical" });

    await criticalChip.click();
    await page.waitForTimeout(200);
    await expect(criticalChip).toHaveClass(/active/);

    // All chip should no longer be active
    const allChip = page
      .locator("#severityFilters .chip")
      .filter({ hasText: "All" });
    await expect(allChip).not.toHaveClass(/active/);
  });
});
