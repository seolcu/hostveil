import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Detail panel shows source correctly", () => {
  test("trivy finding shows trivy source in detail", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("trivy");
  });

  test("lynis finding shows lynis source in detail", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("lynis");
  });

  test("compose finding shows compose source in detail", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='compose.ds001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("compose");
  });
});

test.describe("Score breakdown penalty cap text", () => {
  test("each axis shows penalty cap ratio", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const meta = axes.nth(i).locator(".score-axis-meta span").first();
      const text = await meta.textContent();
      expect(text).toMatch(/\d+\/\d+ penalty/);
    }
  });
});

test.describe("Metrics row has 6 items", () => {
  test("metrics row shows 6 metric cards", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBe(6);
  });
});

test.describe("Filter chip text content", () => {
  test("severity chips have correct labels", async ({ page }) => {
    await waitForReady(page);
    const chips = page.locator("#severityFilters button");
    const texts: string[] = [];
    const count = await chips.count();
    for (let i = 0; i < count; i++) {
      texts.push((await chips.nth(i).textContent()) ?? "");
    }
    expect(texts).toContain("All");
    expect(texts).toContain("Critical");
    expect(texts).toContain("High");
    expect(texts).toContain("Medium");
    expect(texts).toContain("Low");
  });

  test("source chips have correct labels", async ({ page }) => {
    await waitForReady(page);
    const chips = page.locator("#sourceFilters button");
    const texts: string[] = [];
    const count = await chips.count();
    for (let i = 0; i < count; i++) {
      texts.push((await chips.nth(i).textContent()) ?? "");
    }
    expect(texts).toContain("All");
    expect(texts).toContain("Trivy");
    expect(texts).toContain("Lynis");
    expect(texts).toContain("Compose");
  });
});

test.describe("Score breakdown head description", () => {
  test("score breakdown head has description text", async ({ page }) => {
    await waitForReady(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const text = await head.textContent();
    expect(text).toContain("penalty cap");
  });
});

test.describe("Detail panel evidence keys are sorted", () => {
  test("evidence keys appear in alphabetical order", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    // Open the evidence details
    const details = page.locator("#detail .evidence-details").first();
    const summary = details.locator("summary");
    await summary.click();
    await page.waitForTimeout(200);

    const strongs = details.locator("pre strong");
    const count = await strongs.count();
    const keys: string[] = [];
    for (let i = 0; i < count; i++) {
      keys.push((await strongs.nth(i).textContent()) ?? "");
    }

    // Should be alphabetical
    for (let i = 1; i < keys.length; i++) {
      expect(keys[i].localeCompare(keys[i - 1])).toBeGreaterThanOrEqual(0);
    }
  });
});

test.describe("Table header columns", () => {
  test("table has 6 column headers", async ({ page }) => {
    await waitForReady(page);
    const headers = page.locator("table thead th");
    const count = await headers.count();
    expect(count).toBe(6);
  });
});

test.describe("Score plate has score-label", () => {
  test("score-label text is Security score", async ({ page }) => {
    await waitForReady(page);
    const label = page.locator(".scoreplate .score-label");
    const text = await label.textContent();
    expect(text).toContain("Security score");
  });
});

test.describe("Topbar eyebrow", () => {
  test("eyebrow says security", async ({ page }) => {
    await waitForReady(page);
    const eyebrow = page.locator(".topbar .eyebrow");
    const text = await eyebrow.textContent();
    expect(text).toContain("security");
  });
});

test.describe("Finding panel eyebrow", () => {
  test("findings panel eyebrow says Findings", async ({ page }) => {
    await waitForReady(page);
    const eyebrow = page.locator(".findings-panel .eyebrow");
    const text = await eyebrow.textContent();
    expect(text).toContain("Findings");
  });
});

test.describe("Score breakdown has exactly 4 axes", () => {
  test("score breakdown renders 4 axis cards", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);
  });
});

test.describe("Search by description", () => {
  test("searching for root login finds AUTH-9308", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("root login");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("lynis.AUTH-9308");
  });
});

test.describe("Search by service name", () => {
  test("searching for webapp finds webapp findings", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("webapp");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // webapp service: trivy.ds001, trivy.dr001, compose.ds001, compose.dr004 = 4
    expect(count).toBe(4);
  });
});

test.describe("Sort by source then severity", () => {
  test("source sort groups compose together", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("source");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const ids: string[] = [];
    for (let i = 0; i < count; i++) {
      ids.push((await rows.nth(i).getAttribute("data-id")) ?? "");
    }

    // Find first and last compose
    const first = ids.findIndex((id) => id.startsWith("compose."));
    const last = ids.findLastIndex((id) => id.startsWith("compose."));
    expect(first).toBeGreaterThanOrEqual(0);
    expect(last).toBeGreaterThanOrEqual(first);

    // All between should be compose
    for (let i = first; i <= last; i++) {
      expect(ids[i].startsWith("compose.")).toBe(true);
    }
  });
});
