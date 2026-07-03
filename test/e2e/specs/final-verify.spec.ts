import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Detail panel for compose finding with metadata", () => {
  test("compose finding shows metadata section", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='compose.dr004']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("compose");
    expect(text).toContain("webapp");
  });
});

test.describe("Score breakdown axes have data-axis", () => {
  test("each axis card has data-axis attribute", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const axisId = await axes.nth(i).getAttribute("data-axis");
      expect(axisId).toBeTruthy();
      expect(axisId.length).toBeGreaterThan(0);
    }
  });
});

test.describe("Severity filter exact counts", () => {
  test("critical=2, high=6, medium=4, low=2", async ({ page }) => {
    await waitForReady(page);

    const counts: Record<string, number> = {};
    for (const sev of ["Critical", "High", "Medium", "Low"]) {
      const chip = page
        .locator("#severityFilters button")
        .filter({ hasText: sev });
      await chip.click();
      await page.waitForTimeout(200);
      counts[sev] = await page.locator("#findings tr[data-index]").count();
    }

    expect(counts["Critical"]).toBe(2);
    expect(counts["High"]).toBe(6);
    expect(counts["Medium"]).toBe(4);
    expect(counts["Low"]).toBe(2);
  });
});

test.describe("Source filter exact counts", () => {
  test("trivy=6, lynis=6, compose=2", async ({ page }) => {
    await waitForReady(page);

    const counts: Record<string, number> = {};
    for (const src of ["Trivy", "Lynis", "Compose"]) {
      const chip = page
        .locator("#sourceFilters button")
        .filter({ hasText: src });
      await chip.click();
      await page.waitForTimeout(200);
      counts[src] = await page.locator("#findings tr[data-index]").count();
    }

    expect(counts["Trivy"]).toBe(6);
    expect(counts["Lynis"]).toBe(6);
    expect(counts["Compose"]).toBe(2);
  });
});

test.describe("Remediation filter exact counts", () => {
  test("auto=10, review=3, unavailable=1", async ({ page }) => {
    await waitForReady(page);

    const counts: Record<string, number> = {};
    for (const rem of ["Auto", "Review", "Unavailable"]) {
      const chip = page
        .locator("#remediationFilters button")
        .filter({ hasText: rem });
      await chip.click();
      await page.waitForTimeout(200);
      counts[rem] = await page.locator("#findings tr[data-index]").count();
    }

    expect(counts["Auto"]).toBe(10);
    expect(counts["Review"]).toBe(3);
    expect(counts["Unavailable"]).toBe(1);
  });
});

test.describe("Service filter exact counts", () => {
  test("nginx:1.24=2, webapp=4, redis:7=1, database=1", async ({ page }) => {
    await waitForReady(page);

    const counts: Record<string, number> = {};
    for (const svc of ["nginx:1.24", "webapp", "redis:7", "database"]) {
      const chip = page
        .locator("#serviceFilters button")
        .filter({ hasText: svc });
      await chip.click();
      await page.waitForTimeout(200);
      counts[svc] = await page.locator("#findings tr[data-index]").count();
    }

    expect(counts["nginx:1.24"]).toBe(2);
    expect(counts["webapp"]).toBe(4);
    expect(counts["redis:7"]).toBe(1);
    expect(counts["database"]).toBe(1);
  });
});

test.describe("Search finds specific findings", () => {
  test("search for privileged finds ds001", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("privileged");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(2); // trivy.ds001 + compose.ds001
  });

  test("search for password finds AUTH-9286", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("password");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
    const ids = await rows.evaluateAll((els) =>
      els.map((el) => el.getAttribute("data-id"))
    );
    expect(ids).toContain("lynis.AUTH-9286");
  });

  test("search for shadow finds FILE-6310", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("shadow");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("lynis.FILE-6310");
  });
});

test.describe("Metrics total and fixable counts", () => {
  test("total=14, fixable=13", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBe(6);

    // Check total
    const total = await metrics.first().textContent();
    expect(total).toContain("14");

    // Check fixable
    const fixable = page.locator("#metrics .metric--fixable");
    const fixableText = await fixable.textContent();
    expect(fixableText).toContain("13");
  });
});

test.describe("Score breakdown penalty bars have width", () => {
  test("each penalty bar has a width percentage", async ({ page }) => {
    await waitForReady(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const style = await bars.nth(i).getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
    }
  });
});

test.describe("Detail panel shows how_to_fix with copy button", () => {
  test("how_to_fix section has Copy guidance button", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const copyBtn = page.locator("#detail .copy");
    await expect(copyBtn).toBeVisible();
    const text = await copyBtn.textContent();
    expect(text).toContain("Copy guidance");
  });
});

test.describe("Fixed finding has disabled checkbox", () => {
  test("fixed finding checkbox is disabled", async ({ page }) => {
    await waitForReady(page);
    const checkbox = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003'] .row-check"
    );
    const isDisabled = await checkbox.isDisabled();
    expect(isDisabled).toBe(true);
  });
});

test.describe("Unavailable finding has disabled checkbox", () => {
  test("unavailable finding checkbox is disabled", async ({ page }) => {
    await waitForReady(page);
    const checkbox = page.locator(
      "#findings tr[data-id='test.unfixable-001'] .row-check"
    );
    const isDisabled = await checkbox.isDisabled();
    expect(isDisabled).toBe(true);
  });
});

test.describe("Score plate score element", () => {
  test("score shows N/100 format", async ({ page }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Topbar h1", () => {
  test("h1 contains hostveil", async ({ page }) => {
    await waitForReady(page);
    const h1 = page.locator(".topbar h1");
    const text = await h1.textContent();
    expect(text).toContain("hostveil");
  });
});

test.describe("Findings panel heading", () => {
  test("panel eyebrow says Findings", async ({ page }) => {
    await waitForReady(page);
    const eyebrow = page.locator(".findings-panel .eyebrow");
    const text = await eyebrow.textContent();
    expect(text).toContain("Findings");
  });
});
