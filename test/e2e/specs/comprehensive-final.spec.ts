import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown axis penalty bars", () => {
  test("each axis has a penalty bar", async ({ page }) => {
    await waitForReady(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    const count = await bars.count();
    expect(count).toBe(4);
  });
});

test.describe("Score breakdown axis meta text", () => {
  test("each axis has meta with penalty text", async ({ page }) => {
    await waitForReady(page);
    const metas = page.locator("#scoreBreakdown .score-axis-meta");
    const count = await metas.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const text = await metas.nth(i).textContent();
      expect(text).toContain("penalty");
    }
  });
});

test.describe("Detail panel has description and how_to_fix", () => {
  test("detail shows both Description and How to fix sections", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Description");
    expect(text).toContain("How to fix");
    expect(text).toContain("Update nginx");
  });
});

test.describe("Score plate minimum width", () => {
  test("score plate has minimum width of 250px", async ({ page }) => {
    await waitForReady(page);
    const scoreplate = page.locator(".scoreplate");
    const width = await scoreplate.evaluate((el) => el.offsetWidth);
    expect(width).toBeGreaterThanOrEqual(250);
  });
});

test.describe("Filter chip active class", () => {
  test("default All chip is active", async ({ page }) => {
    await waitForReady(page);
    const active = page.locator("#severityFilters button.active");
    const text = await active.textContent();
    expect(text).toContain("All");
  });

  test("clicking chip adds active class", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "High" });
    await chip.click();
    await page.waitForTimeout(200);

    const active = page.locator("#severityFilters button.active");
    const text = await active.textContent();
    expect(text).toContain("High");
  });
});

test.describe("Sort dropdown default value", () => {
  test("sort dropdown defaults to severity", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("severity");
  });
});

test.describe("Metrics row structure", () => {
  test("metrics has 6 metric items", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBe(6);
  });
});

test.describe("Help modal has keyboard shortcuts", () => {
  test("help modal mentions arrows and Escape", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const text = await page.locator("#helpModal").textContent();
    expect(text).toContain("↑");
    expect(text).toContain("↓");
    expect(text).toContain("Esc");

    await page.keyboard.press("Escape");
  });
});

test.describe("Export modal has format descriptions", () => {
  test("export modal shows JSON, CSV, AI descriptions", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const text = await page.locator("#exportModal").textContent();
    expect(text).toContain("Full scan data");
    expect(text).toContain("Spreadsheet");
    expect(text).toContain("Markdown");

    await page.keyboard.press("Escape");
  });
});

test.describe("Table header has sortable columns", () => {
  test("4 sortable column headers exist", async ({ page }) => {
    await waitForReady(page);
    const sortable = page.locator("table thead th.sortable");
    const count = await sortable.count();
    expect(count).toBe(4);
  });
});

test.describe("Detail panel fix button visibility", () => {
  test("auto finding shows Fix button", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 3000 });
    const text = await fixBtn.textContent();
    expect(text).toBe("Fix");
  });
});


test.describe("Score breakdown penalty cap values", () => {
  test("vulnerabilities max penalty is 35", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const vuln = result.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "vulnerabilities"
    );
    expect(vuln.max_penalty).toBe(35);
  });

  test("host_hardening max penalty is 25", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const host = result.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "host_hardening"
    );
    expect(host.max_penalty).toBe(25);
  });

  test("container_exposure max penalty is 30", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const container = result.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "container_exposure"
    );
    expect(container.max_penalty).toBe(30);
  });
});

test.describe("Finding count after multiple filters", () => {
  test("multiple filters narrow correctly", async ({ page }) => {
    await waitForReady(page);

    // Filter to critical
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await chip.click();
    await page.waitForTimeout(200);

    // Also search for CVE
    const query = page.locator("#query");
    await query.fill("CVE");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Critical + CVE: cve-2024-0001 = 1
    expect(count).toBe(1);
  });
});
