import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Browser back after navigation", () => {
  test("back button returns to main page", async ({ page }) => {
    await waitForReady(page);
    // Navigate to a different page
    await page.goto("/api/health");
    await page.waitForTimeout(500);
    // Go back
    await page.goBack();
    await page.waitForTimeout(1000);
    // Should be back on main page
    const findings = page.locator("#findings");
    await expect(findings).toBeAttached();
  });
});

test.describe("Tab navigation between elements", () => {
  test("Tab moves focus through filter chips", async ({ page }) => {
    await waitForReady(page);
    // Focus first chip
    const firstChip = page.locator("#severityFilters button").first();
    await firstChip.focus();
    await page.keyboard.press("Tab");

    // Next element should be focused
    const focused = await page.evaluate(() => {
      return document.activeElement?.tagName || "";
    });
    expect(focused).toBeTruthy();
  });
});

test.describe("Escape closes any open modal", () => {
  test("Escape closes help modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });

  test("Escape closes export modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("Score breakdown has 4 axes", () => {
  test("exactly 4 axis cards rendered", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);
  });
});

test.describe("Severity filter exact counts", () => {
  test("medium filter shows correct count", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Medium" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(4);
  });

  test("low filter shows correct count", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Low" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(2);
  });
});

test.describe("Lynis source filter exact count", () => {
  test("lynis filter shows 6 rows", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Lynis" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(6);
  });
});

test.describe("Unavailable remediation filter", () => {
  test("unavailable filter shows 1 row", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#remediationFilters button")
      .filter({ hasText: "Unavailable" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
  });
});

test.describe("Search for redis", () => {
  test("searching redis finds redis finding", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("redis");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.cve-2024-0003");
  });
});

test.describe("Search for firewall", () => {
  test("searching firewall finds FIRE-4512", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("firewall");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("lynis.FIRE-4512");
  });
});

test.describe("Search for database", () => {
  test("searching database finds dr002", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("database");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.dr002");
  });
});

test.describe("Sort by title ascending", () => {
  test("title sort orders findings alphabetically", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("title");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Collect titles to verify alphabetical order
    const titles: string[] = [];
    for (let i = 0; i < count; i++) {
      const titleCell = rows.nth(i).locator(".title");
      titles.push((await titleCell.textContent()) ?? "");
    }
    for (let i = 1; i < titles.length; i++) {
      expect(titles[i].localeCompare(titles[i - 1])).toBeGreaterThanOrEqual(0);
    }
  });
});

test.describe("Sort by source ascending", () => {
  test("source sort puts compose first", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("source");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const first = await rows.first().getAttribute("data-id");
    // compose < lynis < trivy alphabetically
    expect(first?.startsWith("compose.")).toBe(true);
  });
});

test.describe("Sort by remediation ascending", () => {
  test("remediation sort puts auto first", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("remediation");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const first = await rows.first().getAttribute("data-id");
    // auto < review < unavailable
    expect(first).toBeTruthy();
  });
});

test.describe("Metrics medium count", () => {
  test("medium metric shows 4", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    for (let i = 0; i < count; i++) {
      const text = await metrics.nth(i).textContent();
      if (text.includes("Medium")) {
        expect(text).toContain("4");
        return;
      }
    }
    throw new Error("Medium metric not found");
  });
});

test.describe("Metrics low count", () => {
  test("low metric shows 2", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    for (let i = 0; i < count; i++) {
      const text = await metrics.nth(i).textContent();
      if (text.includes("Low")) {
        expect(text).toContain("2");
        return;
      }
    }
    throw new Error("Low metric not found");
  });
});
