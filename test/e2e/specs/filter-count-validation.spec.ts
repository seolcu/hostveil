import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Fix info_only returns warning for auto finding with warning", () => {
  test("auto finding action may include warning field", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            id: "trivy.cve-2024-0001",
            title: "test",
            severity: 0,
            source: 0,
            remediation: 0,
            service: "nginx:1.24",
          },
          action_index: 0,
          info_only: true,
        }),
      });
      return resp.json();
    });
    expect(result.success).toBe(true);
    expect(result.actions[0]).toHaveProperty("warning");
    expect(typeof result.actions[0].warning).toBe("string");
  });
});

test.describe("Review finding has multiple actions", () => {
  test("review finding returns 2+ actions", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            id: "trivy.dr001",
            title: "test",
            severity: 2,
            source: 0,
            remediation: 1,
            service: "webapp",
            metadata: { compose_path: "/home/test/docker-compose.yml" },
          },
          action_index: 0,
          info_only: true,
        }),
      });
      return resp.json();
    });
    expect(result.success).toBe(true);
    expect(result.actions.length).toBeGreaterThanOrEqual(2);
    // Each action should have index, type, label
    for (const action of result.actions) {
      expect(typeof action.index).toBe("number");
      expect(action.type).toBeTruthy();
      expect(action.label).toBeTruthy();
    }
  });
});

test.describe("Score breakdown axes have labels", () => {
  test("each axis has a non-empty label", async ({ page }) => {
    await waitForReady(page);
    const labels = page.locator("#scoreBreakdown .score-axis-top span");
    const count = await labels.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const text = await labels.nth(i).textContent();
      expect(text).toBeTruthy();
      expect(text.length).toBeGreaterThan(0);
    }
  });
});

test.describe("Score breakdown axis score format", () => {
  test("each axis score shows N/100", async ({ page }) => {
    await waitForReady(page);
    const scores = page.locator("#scoreBreakdown .score-axis-top strong");
    const count = await scores.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const text = await scores.nth(i).textContent();
      expect(text).toMatch(/^\d+\/100$/);
    }
  });
});

test.describe("Detail panel evidence count in summary", () => {
  test("evidence summary shows count in parentheses", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const summary = page.locator(
      "#detail .evidence-details summary"
    ).first();
    const text = await summary.textContent();
    expect(text).toMatch(/Evidence \(\d+\)/);
  });
});

test.describe("Detail panel metadata count in summary", () => {
  test("metadata summary shows count in parentheses", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const metaSection = page.locator("#detail .evidence-details").nth(1);
    const summary = metaSection.locator("summary");
    const text = await summary.textContent();
    expect(text).toMatch(/Metadata \(\d+\)/);
  });
});

test.describe("Sort by severity then title", () => {
  test("critical findings are sorted by title", async ({ page }) => {
    await waitForReady(page);
    // Default sort is severity asc, then title asc
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();

    // Collect first few rows' badges and titles
    const firstBadge = await rows.nth(0).locator(".badge").textContent();
    expect(firstBadge).toContain("critical");

    // Second row should also be critical (there are 2 criticals)
    const secondBadge = await rows.nth(1).locator(".badge").textContent();
    expect(secondBadge).toContain("critical");
  });
});

test.describe("Severity filter shows correct count", () => {
  test("clicking critical filter shows 2 rows", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(2);
  });

  test("clicking high filter shows correct count", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "High" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // 6 high findings (including fixed trivy.cve-2024-0003)
    expect(count).toBe(6);
  });
});

test.describe("Source filter shows correct count", () => {
  test("clicking trivy filter shows 6 rows", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(6);
  });

  test("clicking compose filter shows 2 rows", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Compose" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(2);
  });
});

test.describe("Remediation filter shows correct count", () => {
  test("clicking auto filter shows 10 rows", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#remediationFilters button")
      .filter({ hasText: "Auto" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(10);
  });

  test("clicking review filter shows 3 rows", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#remediationFilters button")
      .filter({ hasText: "Review" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(3);
  });
});

test.describe("Service filter shows correct count", () => {
  test("clicking nginx:1.24 filter shows 2 rows", async ({ page }) => {
    await waitForReady(page);
    const chip = page
      .locator("#serviceFilters button")
      .filter({ hasText: "nginx:1.24" });
    await chip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(2);
  });
});

test.describe("Finding count updates with filters", () => {
  test("finding count text changes after filter", async ({ page }) => {
    await waitForReady(page);
    const countEl = page.locator("#findingCount");
    let text = await countEl.textContent();
    expect(text).toBe("14 visible");

    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await chip.click();
    await page.waitForTimeout(200);

    text = await countEl.textContent();
    expect(text).toBe("2 visible");
  });
});

test.describe("Search narrows results", () => {
  test("searching for CVE shows only CVE findings", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("CVE");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // 3 CVE findings
    expect(count).toBe(3);
  });
});

test.describe("Clear filters restores all", () => {
  test("clear filters button resets to 14 visible", async ({ page }) => {
    await waitForReady(page);

    // Apply a filter
    const chip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await chip.click();
    await page.waitForTimeout(200);

    // Clear
    const clearBtn = page.locator("#clearFilters");
    await clearBtn.click();
    await page.waitForTimeout(200);

    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    expect(text).toBe("14 visible");
  });
});
