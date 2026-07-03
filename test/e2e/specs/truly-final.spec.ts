import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown container_exposure axis", () => {
  test("container_exposure has severity counts", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const container = axes.filter({ hasText: "Container" });
    const counts = container.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Score breakdown vulnerability axis counts", () => {
  test("vulnerabilities has severity counts", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const vuln = axes.filter({ hasText: "Vulnerabilities" });
    const counts = vuln.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Score breakdown host_hardening axis counts", () => {
  test("host_hardening has severity counts", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const host = axes.filter({ hasText: "Host" });
    const counts = host.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Detail panel for compose finding", () => {
  test("compose.ds001 shows compose source and webapp service", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='compose.ds001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("compose");
    expect(text).toContain("webapp");
    expect(text).toContain("Service");
  });
});

test.describe("Detail panel for compose.dr004", () => {
  test("compose.dr004 shows compose source and env_file", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='compose.dr004']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("env_file");
    expect(text).toContain("compose");
  });
});

test.describe("Score breakdown axis score values", () => {
  test("each axis score is between 0 and 100", async ({ page }) => {
    await waitForReady(page);
    const scores = page.locator("#scoreBreakdown .score-axis-top strong");
    const count = await scores.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const text = await scores.nth(i).textContent();
      const match = text?.match(/^(\d+)\/100$/);
      expect(match).toBeTruthy();
    }
  });
});

test.describe("Search for specific findings", () => {
  test("searching for redis finds cve-2024-0003", async ({ page }) => {
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

  test("searching for database finds dr002", async ({ page }) => {
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

test.describe("Filter and clear cycle", () => {
  test("filter to medium then clear restores 14", async ({ page }) => {
    await waitForReady(page);

    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Medium" });
    await chip.click();
    await page.waitForTimeout(200);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(4);

    const all = page
      .locator("#severityFilters button")
      .filter({ hasText: "All" });
    await all.click();
    await page.waitForTimeout(200);

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Sort dropdown options", () => {
  test("sort dropdown has severity, source, title, remediation", async ({
    page,
  }) => {
    await waitForReady(page);
    const options = page.locator("#sortBy option");
    const count = await options.count();
    expect(count).toBe(4);

    const texts: string[] = [];
    for (let i = 0; i < count; i++) {
      texts.push((await options.nth(i).textContent()) ?? "");
    }
    expect(texts.some((t) => t.includes("Severity"))).toBe(true);
    expect(texts.some((t) => t.includes("Source"))).toBe(true);
    expect(texts.some((t) => t.includes("Title"))).toBe(true);
    expect(texts.some((t) => t.includes("Remediation"))).toBe(true);
  });
});

test.describe("Table header structure", () => {
  test("table has Severity, Source, ID, Finding, Fix headers", async ({
    page,
  }) => {
    await waitForReady(page);
    const headers = page.locator("table thead th");
    const texts: string[] = [];
    const count = await headers.count();
    for (let i = 0; i < count; i++) {
      texts.push((await headers.nth(i).textContent()) ?? "");
    }
    expect(texts.some((t) => t.includes("Severity"))).toBe(true);
    expect(texts.some((t) => t.includes("Source"))).toBe(true);
    expect(texts.some((t) => t.includes("ID"))).toBe(true);
    expect(texts.some((t) => t.includes("Finding"))).toBe(true);
    expect(texts.some((t) => t.includes("Fix"))).toBe(true);
  });
});

test.describe("Score breakdown head", () => {
  test("head says Score breakdown", async ({ page }) => {
    await waitForReady(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const text = await head.textContent();
    expect(text).toContain("Score breakdown");
  });
});

test.describe("Metrics row structure", () => {
  test("metrics has Total, Critical, High, Medium, Low, Fixable", async ({
    page,
  }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBe(6);

    const texts: string[] = [];
    for (let i = 0; i < count; i++) {
      texts.push((await metrics.nth(i).textContent()) ?? "");
    }
    expect(texts.some((t) => t.includes("Total"))).toBe(true);
    expect(texts.some((t) => t.includes("Critical"))).toBe(true);
    expect(texts.some((t) => t.includes("High"))).toBe(true);
    expect(texts.some((t) => t.includes("Medium"))).toBe(true);
    expect(texts.some((t) => t.includes("Low"))).toBe(true);
    expect(texts.some((t) => t.includes("Fixable"))).toBe(true);
  });
});

test.describe("Score element", () => {
  test("score has class low/medium/high/critical", async ({ page }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    const cls = await score.getAttribute("class");
    expect(cls).toMatch(/^(low|medium|high|critical)$/);
  });
});
