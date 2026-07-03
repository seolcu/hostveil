import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Detail panel for all critical findings", () => {
  test("trivy.cve-2024-0001 shows critical badge", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);
    const badge = page.locator("#detail .badge");
    const text = await badge.textContent();
    expect(text).toContain("critical");
  });

  test("test.unfixable-001 shows critical badge", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);
    const badge = page.locator("#detail .badge");
    const text = await badge.textContent();
    expect(text).toContain("critical");
  });
});

test.describe("Detail panel for all high findings", () => {
  test("trivy.cve-2024-0002 shows high badge", async ({ page }) => {
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

test.describe("Score breakdown vulnerability axis penalty", () => {
  test("vulnerabilities axis has penalty info", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const vuln = axes.filter({ hasText: "Vulnerabilities" });
    const meta = vuln.locator(".score-axis-meta span").first();
    const text = await meta.textContent();
    expect(text).toMatch(/\d+\/35 penalty/);
  });
});

test.describe("Score breakdown host_hardening penalty", () => {
  test("host_hardening axis has penalty info", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const host = axes.filter({ hasText: "Host hardening" });
    const meta = host.locator(".score-axis-meta span").first();
    const text = await meta.textContent();
    expect(text).toMatch(/\d+\/25 penalty/);
  });
});

test.describe("Score breakdown container_exposure penalty", () => {
  test("container_exposure axis has penalty info", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const container = axes.filter({ hasText: "Container" });
    const meta = container.locator(".score-axis-meta span").first();
    const text = await meta.textContent();
    expect(text).toMatch(/\d+\/30 penalty/);
  });
});

test.describe("Score breakdown secrets penalty", () => {
  test("secrets axis has penalty info", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const secrets = axes.filter({ hasText: "Secrets" });
    const meta = secrets.locator(".score-axis-meta span").first();
    const text = await meta.textContent();
    expect(text).toMatch(/\d+\/10 penalty/);
  });
});

test.describe("Search for specific CVE IDs", () => {
  test("searching CVE-2024-0002 finds exactly 1", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("CVE-2024-0002");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.cve-2024-0002");
  });

  test("searching CVE-2024-0003 finds exactly 1", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("CVE-2024-0003");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.cve-2024-0003");
  });
});

test.describe("Filter then clear restores state", () => {
  test("critical filter then clear restores 14", async ({ page }) => {
    await waitForReady(page);

    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await chip.click();
    await page.waitForTimeout(200);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    const all = page
      .locator("#severityFilters button")
      .filter({ hasText: "All" });
    await all.click();
    await page.waitForTimeout(200);

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Multiple rapid filter changes", () => {
  test("rapid severity changes settle correctly", async ({ page }) => {
    await waitForReady(page);

    // Rapidly click: Critical → High → Medium → Low → All
    for (const sev of ["Critical", "High", "Medium", "Low", "All"]) {
      const chip = page
        .locator("#severityFilters button")
        .filter({ hasText: sev });
      await chip.click();
    }
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Sort direction toggle", () => {
  test("O key reverses sort order", async ({ page }) => {
    await waitForReady(page);

    const rows = page.locator("#findings tr[data-index]");
    const firstBefore = await rows.first().locator(".badge").textContent();

    await page.keyboard.press("O");
    await page.waitForTimeout(200);

    const firstAfter = await rows.first().locator(".badge").textContent();
    // Reversed: low should now be first
    expect(firstAfter).toContain("low");
    expect(firstBefore).toContain("critical");
  });
});

test.describe("Score breakdown all axes visible", () => {
  test("all 4 axes are visible simultaneously", async ({ page }) => {
    await waitForReady(page);

    const vuln = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Vulnerabilities" });
    const container = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Container" });
    const host = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Host" });
    const secrets = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Secrets" });

    await expect(vuln).toBeVisible();
    await expect(container).toBeVisible();
    await expect(host).toBeVisible();
    await expect(secrets).toBeVisible();
  });
});

test.describe("Detail panel ID field", () => {
  test("detail shows full finding ID", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("lynis.AUTH-9286");
  });
});

test.describe("Metrics high count", () => {
  test("high metric shows 6", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    for (let i = 0; i < count; i++) {
      const text = await metrics.nth(i).textContent();
      if (text.includes("High")) {
        expect(text).toContain("6");
        return;
      }
    }
    throw new Error("High metric not found");
  });
});

test.describe("Score plate has correct score", () => {
  test("score plate shows numeric score", async ({ page }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    const text = await score.textContent();
    const match = text?.match(/^(\d+)\//);
    expect(match).toBeTruthy();
    if (match) {
      const val = parseInt(match[1]);
      expect(val).toBeGreaterThanOrEqual(0);
      expect(val).toBeLessThanOrEqual(100);
    }
  });
});
