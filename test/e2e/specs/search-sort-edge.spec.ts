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

test.describe("Search includes evidence values", () => {
  test("searching by evidence value finds the finding", async ({ page }) => {
    await waitForReady(page);
    // searchable() joins evidence VALUES (not keys). cve_url contains "CVE-2024-0001"
    const query = page.locator("#query");
    await query.fill("CVE-2024-0001");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });

  test("searching by description text finds the finding", async ({
    page,
  }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("brute-force");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("lynis.AUTH-9286");
  });

  test("searching by how_to_fix text finds the finding", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("chmod 640");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("lynis.FILE-6310");
  });

  test("searching by severity label finds matching findings", async ({
    page,
  }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("low");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // "low" matches severity label + descriptions/evidence containing "low"
    expect(count).toBeGreaterThanOrEqual(2);
  });

  test("searching by source label finds matching findings", async ({
    page,
  }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("compose");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // "compose" matches source label + descriptions/metadata containing "compose"
    expect(count).toBeGreaterThanOrEqual(2);
  });
});

test.describe("Service filter shows correct services", () => {
  test("service filter chip shows available services", async ({ page }) => {
    await waitForReady(page);
    const serviceChips = page.locator("#serviceFilters button");
    const count = await serviceChips.count();
    // Should have "all" + services: nginx:1.24, webapp, redis:7, database = 5
    expect(count).toBeGreaterThanOrEqual(5);
  });

  test("service filter to nginx shows only nginx findings", async ({
    page,
  }) => {
    await waitForReady(page);
    const nginxChip = page
      .locator("#serviceFilters button")
      .filter({ hasText: "nginx:1.24" });
    await nginxChip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // nginx findings: cve-2024-0001, cve-2024-0002 = 2
    expect(count).toBe(2);
  });
});

test.describe("AI brief export content", () => {
  test("AI brief contains finding summaries", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=ai");
    // AI brief is markdown with finding info
    expect(body).toContain("#");
    expect(body).toContain("Security");
  });
});

test.describe("CSV export content validation", () => {
  test("CSV export has correct header and row format", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=csv");
    const lines = body.trim().split("\n");
    // Header + 14 data rows
    expect(lines.length).toBe(15);
    expect(lines[0]).toBe(
      "ID,Severity,Source,Service,Title,Description,Remediation,Fixed"
    );

    // Each data row should have 8 fields
    for (let i = 1; i < lines.length; i++) {
      // Simple field count — CSV may have quoted fields with commas
      const fields = lines[i].split(",");
      expect(fields.length).toBeGreaterThanOrEqual(8);
    }
  });

  test("CSV export contains all finding IDs", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=csv");
    expect(body).toContain("trivy.cve-2024-0001");
    expect(body).toContain("lynis.AUTH-9286");
    expect(body).toContain("compose.ds001");
    expect(body).toContain("test.unfixable-001");
  });
});

test.describe("Detail panel for different finding types", () => {
  test("lynis finding shows source as lynis", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.FIRE-4512']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("lynis");
    expect(text).toContain("No firewall");
    expect(text).toContain("Review");
  });

  test("compose finding shows compose source", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='compose.dr004']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("compose");
    expect(text).toContain("env_file");
  });
});

test.describe("Score breakdown data-axis attributes", () => {
  test("each axis card has data-axis attribute", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const axisId = await axes.nth(i).getAttribute("data-axis");
      expect(axisId).toBeTruthy();
      expect(axisId?.length).toBeGreaterThan(0);
    }
  });
});

test.describe("Rapid filter changes", () => {
  test("multiple rapid filter changes settle to correct state", async ({
    page,
  }) => {
    await waitForReady(page);

    // Rapidly change severity filters
    const criticalChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    const highChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "High" });
    const allChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "All" });

    await criticalChip.click();
    await highChip.click();
    await allChip.click();
    await page.waitForTimeout(300);

    // Should show all 14 findings
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);
  });
});

test.describe("Sort stability", () => {
  test("title sort maintains consistent ordering", async ({ page }) => {
    await waitForReady(page);

    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("title");
    await page.waitForTimeout(200);

    // Collect all titles
    const rows = page.locator("#findings tr[data-index] .title");
    const titles1: string[] = [];
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      titles1.push((await rows.nth(i).textContent()) ?? "");
    }

    // Re-sort by triggering render
    await page.keyboard.press("O");
    await page.waitForTimeout(200);
    await page.keyboard.press("O");
    await page.waitForTimeout(200);

    const titles2: string[] = [];
    for (let i = 0; i < count; i++) {
      titles2.push((await rows.nth(i).textContent()) ?? "");
    }

    // Same sort field, same direction → same order
    expect(titles1).toEqual(titles2);
  });
});

test.describe("Finding count text accuracy", () => {
  test("count shows exact visible number", async ({ page }) => {
    await waitForReady(page);
    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    expect(text).toBe("14 visible");
  });

  test("count updates after source filter", async ({ page }) => {
    await waitForReady(page);

    const trivyChip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" });
    await trivyChip.click();
    await page.waitForTimeout(200);

    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    // Trivy findings: cve-0001, cve-0002, ds001, dr001, cve-0003, dr002 = 6
    expect(text).toBe("6 visible");
  });
});

test.describe("Detail panel section rendering", () => {
  test("detail shows Description section", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Description");
  });

  test("detail shows How to fix section", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("How to fix");
    expect(text).toContain("PasswordAuthentication");
  });
});
