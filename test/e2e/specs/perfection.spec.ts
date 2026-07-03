import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown container_exposure score", () => {
  test("container_exposure has N/100 score", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const container = axes.filter({ hasText: "Container" });
    const score = container.locator(".score-axis-top strong");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Score breakdown vulnerability score", () => {
  test("vulnerabilities has N/100 score", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const vuln = axes.filter({ hasText: "Vulnerabilities" });
    const score = vuln.locator(".score-axis-top strong");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Score breakdown host_hardening score", () => {
  test("host_hardening has N/100 score", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const host = axes.filter({ hasText: "Host" });
    const score = host.locator(".score-axis-top strong");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Score breakdown secrets score", () => {
  test("secrets has N/100 score", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const secrets = axes.filter({ hasText: "Secrets" });
    const score = secrets.locator(".score-axis-top strong");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Detail panel for lynis.AUTH-9286", () => {
  test("shows SSH password authentication description", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("SSH password authentication");
    expect(text).toContain("brute-force");
  });
});

test.describe("Detail panel for lynis.FIRE-4512", () => {
  test("shows no firewall description", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.FIRE-4512']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("No firewall");
    expect(text).toContain("Review");
  });
});

test.describe("Search for firewall", () => {
  test("firewall search finds FIRE-4512", async ({ page }) => {
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

test.describe("Search for SSH", () => {
  test("SSH search finds multiple findings", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("SSH");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // AUTH-9286, AUTH-9308 = 2 (SSH in description)
    expect(count).toBeGreaterThanOrEqual(2);
  });
});

test.describe("Filter then search combined", () => {
  test("lynis + SSH narrows to 2", async ({ page }) => {
    await waitForReady(page);

    const lynisChip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Lynis" });
    await lynisChip.click();
    await page.waitForTimeout(200);

    const query = page.locator("#query");
    await query.fill("SSH");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(2);
  });
});

test.describe("Metrics fixable count", () => {
  test("fixable shows 13", async ({ page }) => {
    await waitForReady(page);
    const fixable = page.locator("#metrics .metric--fixable");
    const text = await fixable.textContent();
    expect(text).toContain("13");
  });
});

test.describe("Score breakdown axis labels", () => {
  test("labels match expected text", async ({ page }) => {
    await waitForReady(page);
    const labels = page.locator("#scoreBreakdown .score-axis-top span");
    const texts: string[] = [];
    const count = await labels.count();
    for (let i = 0; i < count; i++) {
      texts.push((await labels.nth(i).textContent()) ?? "");
    }
    expect(texts).toContain("Vulnerabilities");
    expect(texts).toContain("Container exposure");
    expect(texts).toContain("Host hardening");
    expect(texts).toContain("Secrets");
  });
});

test.describe("Sort by title then severity", () => {
  test("title sort is stable", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("title");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const ids1: string[] = [];
    for (let i = 0; i < count; i++) {
      ids1.push((await rows.nth(i).getAttribute("data-id")) ?? "");
    }

    // Re-sort
    await page.keyboard.press("O");
    await page.waitForTimeout(200);
    await page.keyboard.press("O");
    await page.waitForTimeout(200);

    const ids2: string[] = [];
    for (let i = 0; i < count; i++) {
      ids2.push((await rows.nth(i).getAttribute("data-id")) ?? "");
    }

    expect(ids1).toEqual(ids2);
  });
});

test.describe("Table row severity badge color", () => {
  test("critical badge has critical class", async ({ page }) => {
    await waitForReady(page);
    await page.waitForTimeout(500);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const badge = row.locator(".badge");
    const cls = await badge.getAttribute("class");
    expect(cls).toContain("critical");
  });

  test("low badge has low class", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.KRNL-5780']"
    );
    const badge = row.locator(".badge");
    const cls = await badge.getAttribute("class");
    expect(cls).toContain("low");
  });
});
