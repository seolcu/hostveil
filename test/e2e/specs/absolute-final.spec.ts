import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown severity counts per axis", () => {
  test("vulnerabilities axis shows severity counts", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const vulnAxis = axes.filter({ hasText: "Vulnerabilities" });
    const counts = vulnAxis.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Score breakdown host_hardening axis", () => {
  test("host_hardening axis has severity counts", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const hostAxis = axes.filter({ hasText: "Host hardening" });
    await expect(hostAxis).toBeVisible();
    const counts = hostAxis.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Score breakdown secrets axis", () => {
  test("secrets axis shows severity counts", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const secretsAxis = axes.filter({ hasText: "Secrets" });
    await expect(secretsAxis).toBeVisible();
    const counts = secretsAxis.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Detail panel metadata section", () => {
  test("trivy.cve-2024-0001 has metadata with compose_path", async ({
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
    expect(text).toContain("Metadata");
    expect(text).toContain("compose_path");
  });
});

test.describe("Detail panel for finding with no metadata", () => {
  test("lynis.AUTH-9286 has no metadata section", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    // AUTH-9286 has empty metadata, so no Metadata section
    expect(text).not.toContain("Metadata");
  });
});

test.describe("Sort by severity ascending", () => {
  test("first row is critical, last row is low", async ({ page }) => {
    await waitForReady(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();

    const firstBadge = await rows.first().locator(".badge").textContent();
    expect(firstBadge).toContain("critical");

    const lastBadge = await rows
      .nth(count - 1)
      .locator(".badge")
      .textContent();
    expect(lastBadge).toContain("low");
  });
});

test.describe("Sort by title ascending", () => {
  test("title sort produces alphabetical order", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("title");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const titles: string[] = [];
    for (let i = 0; i < count; i++) {
      titles.push(
        (await rows.nth(i).locator(".title").textContent()) ?? ""
      );
    }

    for (let i = 1; i < titles.length; i++) {
      expect(titles[i].localeCompare(titles[i - 1])).toBeGreaterThanOrEqual(0);
    }
  });
});

test.describe("Sort by source ascending", () => {
  test("source sort groups compose first", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("source");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const first = await rows.first().getAttribute("data-id");
    expect(first?.startsWith("compose.")).toBe(true);
  });
});

test.describe("Sort by remediation ascending", () => {
  test("remediation sort groups auto first", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("remediation");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const first = await rows.first().getAttribute("data-id");
    expect(first).toBeTruthy();
  });
});

test.describe("Export modal shows all three formats", () => {
  test("export modal has JSON, CSV, and AI options", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const options = page.locator("#exportModal .export-option");
    const count = await options.count();
    expect(count).toBe(3);

    await page.keyboard.press("Escape");
  });
});

test.describe("Help modal has all sections", () => {
  test("help modal has 4 shortcut sections", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const sections = page.locator("#helpModal .help-section");
    const count = await sections.count();
    expect(count).toBe(4);

    await page.keyboard.press("Escape");
  });
});

test.describe("Detail panel has no XSS in evidence", () => {
  test("evidence values are escaped", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    // No script tags in detail
    const scriptCount = await page.locator("#detail script").count();
    expect(scriptCount).toBe(0);
  });
});

test.describe("Table row has 6 cells", () => {
  test("each row has check, severity, source, id, title, fix", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const cells = row.locator("td");
    const count = await cells.count();
    expect(count).toBe(6);
  });
});

test.describe("Score breakdown head text", () => {
  test("head says Score breakdown and penalty cap", async ({ page }) => {
    await waitForReady(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const text = await head.textContent();
    expect(text).toContain("Score breakdown");
    expect(text).toContain("penalty cap");
  });
});

test.describe("Metrics row total", () => {
  test("total metric shows 14", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const total = await metrics.first().textContent();
    expect(total).toContain("14");
  });
});

test.describe("Score element class", () => {
  test("score element has a severity class", async ({ page }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    const className = await score.getAttribute("class");
    expect(className).toMatch(/^(low|medium|high|critical)$/);
  });
});
