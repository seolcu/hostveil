import { test, expect } from "@playwright/test";

test.describe("Filters and sorting", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });
  });

  test("Service filter narrows findings by service", async ({ page }) => {
    const initialCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(initialCount).toBe(14);

    // click nginx service filter
    await page
      .locator('#serviceFilters button[data-value="nginx:1.24"]')
      .click();
    await page.waitForTimeout(300);

    const nginxCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(nginxCount).toBe(2);

    // switch to webapp service
    await page
      .locator('#serviceFilters button[data-value="webapp"]')
      .click();
    await page.waitForTimeout(300);

    const webappCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(webappCount).toBe(4);

    // reset
    await page.locator('#serviceFilters button[data-value="all"]').click();
    await page.waitForTimeout(300);
    const resetCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(resetCount).toBe(initialCount);
  });

  test("Combined filters: severity + source + search", async ({ page }) => {
    // high severity
    await page
      .locator('#severityFilters button[data-value="high"]')
      .click();
    await page.waitForTimeout(300);
    const highCount = await page.locator(
      "#findings tr[data-index]"
    ).count();

    // high + trivy
    await page
      .locator('#sourceFilters button[data-value="trivy"]')
      .click();
    await page.waitForTimeout(300);
    const highTrivyCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(highTrivyCount).toBeLessThanOrEqual(highCount);

    // high + trivy + "nginx" search
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(300);
    const combinedCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(combinedCount).toBeLessThanOrEqual(highTrivyCount);

    // clear all restores
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);
    const allCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(allCount).toBe(14);
  });

  test("Column header click toggles sort direction", async ({ page }) => {
    const titleTh = page.locator('th.sortable[data-col="4"]');
    await expect(titleTh).toBeVisible();

    // click to sort by title asc
    await titleTh.click();
    await page.waitForTimeout(300);
    await expect(titleTh).toHaveClass(/asc/);

    // click again to toggle to desc
    await titleTh.click();
    await page.waitForTimeout(300);
    await expect(titleTh).toHaveClass(/desc/);

    // click severity column
    const sevTh = page.locator('th.sortable[data-col="1"]');
    await sevTh.click();
    await page.waitForTimeout(300);
    await expect(sevTh).toHaveClass(/asc/);
    await expect(titleTh).not.toHaveClass(/asc|desc/);
  });

  test("Sort dropdown changes sort field", async ({ page }) => {
    const sortSelect = page.locator("#sortBy");
    await expect(sortSelect).toBeVisible();

    // change to title
    await sortSelect.selectOption("title");
    await page.waitForTimeout(300);

    // change to source
    await sortSelect.selectOption("source");
    await page.waitForTimeout(300);

    // change back to severity
    await sortSelect.selectOption("severity");
    await page.waitForTimeout(300);
  });

  test("Clear filters button resets all filters", async ({ page }) => {
    // set multiple filters
    await page
      .locator('#severityFilters button[data-value="critical"]')
      .click();
    await page
      .locator('#sourceFilters button[data-value="lynis"]')
      .click();
    await page.locator("#query").fill("SSH");
    await page.waitForTimeout(300);

    const filteredCount = await page.locator(
      "#findings tr[data-index]"
    ).count();

    // clear all
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);

    const resetCount = await page.locator(
      "#findings tr[data-index]"
    ).count();
    expect(resetCount).toBe(14);
    expect(resetCount).toBeGreaterThan(filteredCount);

    // search input should be empty
    const queryValue = await page.locator("#query").inputValue();
    expect(queryValue).toBe("");
  });

  test("Finding count updates with filters", async ({ page }) => {
    const countEl = page.locator("#findingCount");
    await expect(countEl).toContainText("14 visible");

    await page
      .locator('#severityFilters button[data-value="low"]')
      .click();
    await page.waitForTimeout(300);
    await expect(countEl).toContainText("2 visible");

    await page
      .locator('#severityFilters button[data-value="all"]')
      .click();
    await page.waitForTimeout(300);
    await expect(countEl).toContainText("14 visible");
  });
});
