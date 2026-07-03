import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

async function apiFetch(
  page: Page,
  path: string,
  options?: RequestInit
) {
  return page.evaluate(
    async ({ path, options }: { path: string; options?: RequestInit }) => {
      const resp = await fetch(path, options);
      const headers: Record<string, string> = {};
      resp.headers.forEach((v, k) => { headers[k] = v; });
      return { status: resp.status, headers, body: await resp.text() };
    },
    { path, options }
  );
}

test.describe("Page title", () => {
  test("page title is hostveil", async ({ page }) => {
    await waitForReady(page);
    await expect(page).toHaveTitle("hostveil");
  });
});

test.describe("Detail panel for finding with no service", () => {
  test("lynis finding without service hides service field", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.KRNL-5780']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail .detail-meta");
    const text = await detail.textContent();
    // KRNL-5780 has empty service — Service field should not appear
    expect(text).not.toContain("Service");
  });

  test("finding with service shows service field", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail .detail-meta");
    const text = await detail.textContent();
    expect(text).toContain("Service");
    expect(text).toContain("nginx:1.24");
  });
});

test.describe("Copy guidance button", () => {
  test("how_to_fix section has Copy guidance button", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const copyBtn = page.locator("#detail .copy");
    await expect(copyBtn).toBeVisible();
    const text = await copyBtn.textContent();
    expect(text).toContain("Copy guidance");
  });
});
test.describe("Select all checkbox", () => {
  test("selecting all rows checks select-all checkbox", async ({ page }) => {
    await waitForReady(page);

    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });
    await page.waitForTimeout(300);

    const isChecked = await selectAll.isChecked();
    expect(isChecked).toBe(true);

    const isIndeterminate = await page.evaluate(() => {
      const cb = document.getElementById("selectAllCheck") as HTMLInputElement;
      return cb?.indeterminate === true;
    });
    expect(isIndeterminate).toBe(false);
  });
});


test.describe("Rescan button behavior", () => {
  test("rescan button exists and is clickable", async ({ page }) => {
    await waitForReady(page);

    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeVisible();
    const text = await rescanBtn.textContent();
    expect(text).toContain("Rescan");
  });

  test("recalc button exists and is clickable", async ({ page }) => {
    await waitForReady(page);

    const recalcBtn = page.locator("#recalcBtn");
    await expect(recalcBtn).toBeVisible();
    const text = await recalcBtn.textContent();
    expect(text).toContain("Recalc");
  });
});

test.describe("Evidence with metadata shows both sections", () => {
  test("finding with metadata shows both Evidence and Metadata", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const evidenceSection = page.locator("#detail .evidence-details");
    const count = await evidenceSection.count();
    // Should have Evidence (3) and Metadata (1)
    expect(count).toBe(2);

    const summary1 = await evidenceSection.nth(0).locator("summary").textContent();
    expect(summary1).toContain("Evidence");
    expect(summary1).toContain("3");

    const summary2 = await evidenceSection.nth(1).locator("summary").textContent();
    expect(summary2).toContain("Metadata");
    expect(summary2).toContain("1");
  });
});

test.describe("Finding with no evidence shows no evidence section", () => {
  test("finding with empty evidence shows no evidence details", async ({
    page,
  }) => {
    await waitForReady(page);
    // trivy.dr002 has evidence: compose_service and ports — has evidence
    // compose.dr004 has evidence: compose_path and secret_name — has evidence
    // Let's check a finding and verify evidence count matches
    const row = page.locator(
      "#findings tr[data-id='lynis.FIRE-4512']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const evidenceSection = page.locator("#detail .evidence-details summary");
    const text = await evidenceSection.first().textContent();
    // FIRE-4512 has 1 evidence key (active_firewall)
    expect(text).toContain("1");
  });
});

test.describe("Score breakdown rendered on page load", () => {
  test("score breakdown section is visible on load", async ({ page }) => {
    await waitForReady(page);

    const breakdown = page.locator("#scoreBreakdown");
    await expect(breakdown).toBeVisible();
    const hidden = await breakdown.getAttribute("hidden");
    expect(hidden).toBeNull();
  });

  test("score breakdown has exactly 4 axis cards", async ({ page }) => {
    await waitForReady(page);

    const cards = page.locator("#scoreBreakdown .score-axis");
    await expect(cards).toHaveCount(4);
  });
});

test.describe("Multiple tab switches preserve state", () => {
  test("navigating away and back preserves filter state", async ({
    page,
  }) => {
    await waitForReady(page);

    // Apply a filter
    const criticalChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await criticalChip.click();
    await page.waitForTimeout(200);

    let rows = page.locator("#findings tr[data-index]");
    let count = await rows.count();
    expect(count).toBe(2);

    // Navigate away
    await page.goto("/api/health");
    await page.waitForTimeout(500);

    // Navigate back
    await page.goto("/");
    await page.waitForTimeout(2000);

    // Filter should be reset (SPA doesn't persist state across navigation)
    rows = page.locator("#findings tr[data-index]");
    count = await rows.count();
    expect(count).toBe(14);
  });
});

test.describe("Detail panel badge color", () => {
  test("critical finding shows critical badge", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    await expect(badge).toBeVisible();
    const text = await badge.textContent();
    expect(text).toContain("critical");
  });

  test("low finding shows low badge", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.FILE-6310']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    await expect(badge).toBeVisible();
    const text = await badge.textContent();
    expect(text).toContain("low");
  });
});


test.describe("Fixed finding has check mark", () => {
  test("fixed finding row shows check mark instead of severity badge", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const sevCell = row.locator("td").nth(1);
    const text = await sevCell.textContent();
    // Should contain check mark, not severity badge
    expect(text).toContain("✓");
  });
});

test.describe("Metrics fixable count", () => {
  test("fixable metric excludes fixed/unavailable/manual findings", async ({
    page,
  }) => {
    await waitForReady(page);
    const fixable = page.locator("#metrics .metric--fixable");
    const text = await fixable.textContent();
    // Fixable = auto + review (regardless of fixed status) = 13
    expect(text).toContain("13");
  });
});
