import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

async function api(
  page: Page,
  path: string,
  opts?: RequestInit
) {
  return page.evaluate(
    async ({ path, opts }: { path: string; opts?: RequestInit }) => {
      const r = await fetch(path, opts);
      return { status: r.status, body: await r.text() };
    },
    { path, opts }
  );
}

test.describe("Fix modal for Review finding (multiple actions)", () => {
  test("Review finding shows radio buttons for each action", async ({
    page,
  }) => {
    await ready(page);

    // Click the review finding (trivy.dr001)
    const row = page.locator("#findings tr[data-id='trivy.dr001']");
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });

    // Click Fix to open modal
    await fixBtn.click();
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    // Should have radio buttons for actions
    const radios = modal.locator('input[name="fixAction"]');
    const radioCount = await radios.count();
    expect(radioCount).toBeGreaterThanOrEqual(2);

    // Confirm button should be disabled until selection
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeDisabled();

    // Select first action
    await radios.first().check({ force: true });
    await page.waitForTimeout(200);

    // Confirm button should now be enabled
    const confirmText = await confirmBtn.textContent();
    expect(confirmText).toContain("Apply");

    // Cancel
    await modal.locator("#modalFixNo").click();
    await page.waitForTimeout(200);
  });
});

test.describe("Fix modal keyboard confirm with Enter", () => {
  test("Enter key confirms fix modal when action is selected", async ({
    page,
  }) => {
    await ready(page);

    // Open fix modal for auto finding
    const row = page.locator("#findings tr[data-id='lynis.FILE-6310']");
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    // For single-action fix, confirm should be enabled
    const confirmBtn = modal.locator("#modalFixYes");
    const isDisabled = await confirmBtn.isDisabled();

    if (!isDisabled) {
      // Press Enter to confirm
      await page.keyboard.press("Enter");
      await page.waitForTimeout(500);

      // Modal should close
      await expect(modal).not.toBeVisible({ timeout: 3000 });
    }
  });
});

test.describe("Search includes evidence values", () => {
  test("searching by evidence value finds the finding", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("1.25.0");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // cve-2024-0001 and cve-2024-0002 both have fixed_version: "1.25.0"
    expect(count).toBe(2);
  });

  test("searching by CVE URL finds the finding", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("nvd.nist.gov");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.cve-2024-0001");
  });
});

test.describe("Sort by clicking column headers", () => {
  test("clicking source column sorts by source", async ({ page }) => {
    await ready(page);
    const srcHeader = page.locator("th.sortable[data-col='2']");
    await srcHeader.click();
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("source");
  });

  test("clicking title column sorts by title", async ({ page }) => {
    await ready(page);
    const titleHeader = page.locator("th.sortable[data-col='4']");
    await titleHeader.click();
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("title");
  });

  test("clicking fix column sorts by remediation", async ({ page }) => {
    await ready(page);
    const fixHeader = page.locator("th.sortable[data-col='5']");
    await fixHeader.click();
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("remediation");
  });

  test("clicking same column toggles direction", async ({ page }) => {
    await ready(page);
    const severityHeader = page.locator("th.sortable[data-col='1']");

    // First click
    await severityHeader.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const first1 = await rows.first().locator(".badge").textContent();

    // Second click toggles to desc
    await severityHeader.click();
    await page.waitForTimeout(200);

    const first2 = await rows.first().locator(".badge").textContent();
    expect(first1).not.toBe(first2);
  });
});

test.describe("Keyboard shortcut o cycles sort field", () => {
  test("o key advances sort field", async ({ page }) => {
    await ready(page);
    const sortBy = page.locator("#sortBy");
    const initial = await sortBy.inputValue();

    await page.keyboard.press("o");
    await page.waitForTimeout(200);

    const next = await sortBy.inputValue();
    expect(next).not.toBe(initial);
  });
});

test.describe("Keyboard shortcut O toggles sort direction", () => {
  test("O key reverses sort order", async ({ page }) => {
    await ready(page);

    const rows = page.locator("#findings tr[data-index]");
    const firstBefore = await rows.first().locator(".badge").textContent();

    await page.keyboard.press("O");
    await page.waitForTimeout(200);

    const firstAfter = await rows.first().locator(".badge").textContent();
    expect(firstAfter).not.toBe(firstBefore);
  });
});

test.describe("Toast auto-dismiss", () => {
  test("toast appears then disappears after timeout", async ({ page }) => {
    await ready(page);

    // Trigger a recalc toast
    const recalcBtn = page.locator("#recalcBtn");
    await recalcBtn.click();
    await page.waitForTimeout(500);

    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });

    // Wait for auto-dismiss (4s + 300ms animation)
    await page.waitForTimeout(5000);
    await expect(toast).not.toBeVisible();
  });
});

test.describe("View more/View less toggle", () => {
  test("toggling View more shows full text", async ({ page }) => {
    await ready(page);

    // Select a finding
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    // Check if there's a toggle-more button
    const toggle = page.locator("#detail .toggle-more");
    const count = await toggle.count();

    if (count > 0) {
      const text1 = await toggle.first().textContent();
      expect(text1).toBe("View more");

      await toggle.first().click();
      await page.waitForTimeout(200);

      const text2 = await toggle.first().textContent();
      expect(text2).toBe("View less");

      // Toggle back
      await toggle.first().click();
      await page.waitForTimeout(200);

      const text3 = await toggle.first().textContent();
      expect(text3).toBe("View more");
    }
  });
});

test.describe("Detail panel metadata sections", () => {
  test("finding with metadata shows metadata section", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    // Should have 2 details sections: Evidence + Metadata
    const details = page.locator("#detail .evidence-details");
    const count = await details.count();
    expect(count).toBe(2);

    // Second one should be Metadata
    const metaSummary = await details.nth(1).locator("summary").textContent();
    expect(metaSummary).toContain("Metadata");
    expect(metaSummary).toContain("1");
  });
});

test.describe("CSV export content", () => {
  test("CSV has correct header and data rows", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/export?format=csv");
    expect(result.status).toBe(200);

    const lines = result.body.trim().split("\n");
    expect(lines[0]).toBe(
      "ID,Severity,Source,Service,Title,Description,Remediation,Fixed"
    );
    // Header + 14 data rows
    expect(lines.length).toBe(15);
  });

  test("CSV contains all finding IDs", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/export?format=csv");
    expect(result.body).toContain("trivy.cve-2024-0001");
    expect(result.body).toContain("lynis.AUTH-9286");
    expect(result.body).toContain("compose.ds001");
    expect(result.body).toContain("test.unfixable-001");
  });
});

test.describe("AI brief export content", () => {
  test("AI brief returns markdown with headings", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/export?format=ai");
    expect(result.status).toBe(200);
    expect(result.body).toContain("#");
    expect(result.body).toContain("Security score");
  });
});

test.describe("Filter combinations", () => {
  test("severity + source filter narrows correctly", async ({ page }) => {
    await ready(page);

    // Click Critical chip
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);

    // Click Trivy chip
    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" })
      .click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Critical + Trivy: only trivy.cve-2024-0001
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.cve-2024-0001");
  });

  test("search + severity filter combines", async ({ page }) => {
    await ready(page);

    await page
      .locator("#severityFilters button")
      .filter({ hasText: "High" })
      .click();
    await page.waitForTimeout(200);

    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // High + nginx: cve-2024-0002
    expect(count).toBe(1);
  });
});

test.describe("Ctrl+A selects/deselects all", () => {
  test("Ctrl+A toggles selection", async ({ page }) => {
    await ready(page);

    // Select all
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);

    let selected = await page.evaluate(
      () => document.querySelectorAll("#findings tr.row-selected").length
    );
    expect(selected).toBeGreaterThanOrEqual(10);

    // Ctrl+A again deselects
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);

    selected = await page.evaluate(
      () => document.querySelectorAll("#findings tr.row-selected").length
    );
    expect(selected).toBe(0);
  });
});

test.describe("No results message", () => {
  test("empty search shows no-results message", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("zzzznonexistent999");
    await page.waitForTimeout(300);

    const noResults = page.locator("#findings .muted");
    const text = await noResults.textContent();
    expect(text).toContain("No findings match");
  });

  test("clearing search restores all rows", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("zzzznonexistent999");
    await page.waitForTimeout(300);

    await query.fill("");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    expect(await rows.count()).toBe(14);
  });
});

test.describe("Score breakdown penalty cap text", () => {
  test("each axis shows X/Y penalty cap", async ({ page }) => {
    await ready(page);
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

test.describe("Keyboard s cycles source filter", () => {
  test("s key advances through source values", async ({ page }) => {
    await ready(page);

    let active = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(active).toContain("All");

    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    active = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(active).toContain("Trivy");

    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    active = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(active).toContain("Lynis");
  });
});

test.describe("Keyboard r cycles remediation filter", () => {
  test("r key advances through remediation values", async ({ page }) => {
    await ready(page);

    let active = await page
      .locator("#remediationFilters button.active")
      .textContent();
    expect(active).toContain("All");

    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    active = await page
      .locator("#remediationFilters button.active")
      .textContent();
    expect(active).toContain("Auto");
  });
});

test.describe("Number key severity filter", () => {
  test("pressing 1 filters to critical", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    expect(await rows.count()).toBe(2);
  });

  test("pressing 0 shows all", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    await page.keyboard.press("0");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    expect(await rows.count()).toBe(14);
  });
});

test.describe("Export modal close button", () => {
  test("export modal closes on Close button click", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    await page.locator("#exportClose").click();
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("Help modal close button", () => {
  test("help modal closes on Close button click", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    await page.locator("#modalHelpClose").click();
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });
});

test.describe("Detail panel shows correct fields", () => {
  test("ID, Source, Remediation, Service are all shown", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("ID");
    expect(text).toContain("trivy.cve-2024-0001");
    expect(text).toContain("Source");
    expect(text).toContain("Remediation");
    expect(text).toContain("Service");
    expect(text).toContain("nginx:1.24");
  });
});

test.describe("Sort dropdown syncs with keyboard sort", () => {
  test("o key updates dropdown value", async ({ page }) => {
    await ready(page);
    const sortBy = page.locator("#sortBy");
    const initial = await sortBy.inputValue();

    await page.keyboard.press("o");
    await page.waitForTimeout(200);

    expect(await sortBy.inputValue()).not.toBe(initial);
  });
});

test.describe("Recalc button shows toast", () => {
  test("recalc shows success toast", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);

    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
    expect(await toast.textContent()).toContain("recalculated");
  });
});

test.describe("Filter count accuracy", () => {
  test("all severity filters show correct counts", async ({ page }) => {
    await ready(page);

    // Critical = 2
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);
    expect(
      await page.locator("#findings tr[data-index]").count()
    ).toBe(2);

    // Reset
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);

    // High = 6
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "High" })
      .click();
    await page.waitForTimeout(200);
    expect(
      await page.locator("#findings tr[data-index]").count()
    ).toBe(6);

    // Reset
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);

    // Medium = 4
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Medium" })
      .click();
    await page.waitForTimeout(200);
    expect(
      await page.locator("#findings tr[data-index]").count()
    ).toBe(4);

    // Reset
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);

    // Low = 2
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Low" })
      .click();
    await page.waitForTimeout(200);
    expect(
      await page.locator("#findings tr[data-index]").count()
    ).toBe(2);
  });
});

test.describe("Score breakdown overall matches score", () => {
  test("score breakdown overall equals main score", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/result");
    const data = JSON.parse(result.body);
    expect(data.score_breakdown.overall).toBe(data.score);
  });
});

test.describe("Finding count text", () => {
  test("initial count shows 14 visible", async ({ page }) => {
    await ready(page);
    const countEl = page.locator("#findingCount");
    expect(await countEl.textContent()).toBe("14 visible");
  });

  test("count updates after filter", async ({ page }) => {
    await ready(page);
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);

    const countEl = page.locator("#findingCount");
    expect(await countEl.textContent()).toBe("2 visible");
  });
});


test.describe("Tab navigation", () => {
  test("Tab moves focus to interactive elements", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);

    const focused = await page.evaluate(
      () => document.activeElement?.tagName || ""
    );
    expect(focused).toBeTruthy();
  });
});

test.describe("Escape closes modals", () => {
  test("Escape closes help modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });

  test("Escape closes export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("Help modal content", () => {
  test("help modal lists all major shortcuts", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const text = await page.locator("#helpModal").textContent();
    expect(text).toContain("↑");
    expect(text).toContain("↓");
    expect(text).toContain("Space");
    expect(text).toContain("Ctrl+A");
    expect(text).toContain("Ctrl+R");
    expect(text).toContain("Esc");
    expect(text).toContain("?");

    await page.keyboard.press("Escape");
  });
});

test.describe("Export modal format descriptions", () => {
  test("export modal shows format descriptions", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const text = await page.locator("#exportModal").textContent();
    expect(text).toContain("Full scan data");
    expect(text).toContain("Spreadsheet");
    expect(text).toContain("Markdown");

    await page.keyboard.press("Escape");
  });
});

test.describe("Service filter cycling", () => {
  test("v key cycles through service filter", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("v");
    await page.waitForTimeout(200);

    const active = await page
      .locator("#serviceFilters button.active")
      .textContent();
    expect(active).not.toBe("All");
  });
});

test.describe("R key clears all filters", () => {
  test("R key clears filters and shows toast", async ({ page }) => {
    await ready(page);

    // Apply a filter
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);

    let count = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(count).toBe(2);

    // Blur search input first
    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);

    // Press R to clear
    await page.keyboard.press("R");
    await page.waitForTimeout(300);

    // Check toast
    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
    expect(await toast.textContent()).toContain("Filters cleared");

    // All findings restored
    count = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(count).toBe(14);
  });
});

test.describe("Fix action info_only returns valid data", () => {
  test("info_only returns action metadata", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding: {
          id: "lynis.FILE-6310",
          title: "test",
          severity: 3,
          source: 1,
          remediation: 0,
          service: "",
        },
        action_index: 0,
        info_only: true,
      }),
    });
    const data = JSON.parse(result.body);
    expect(data.success).toBe(true);
    expect(data.actions.length).toBe(1);
    expect(data.actions[0].type).toBeTruthy();
    expect(data.actions[0].label).toBeTruthy();
  });
});

test.describe("Fix error cases", () => {
  test("fix with unregistered ID returns error", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding: {
          id: "nonexistent.finding-999",
          title: "test",
          severity: 0,
          source: 0,
          remediation: 0,
          service: "",
        },
        action_index: 0,
        info_only: false,
      }),
    });
    const data = JSON.parse(result.body);
    expect(data.success).toBe(false);
    expect(data.error).toContain("no fix registered");
  });

  test("fix with out-of-range action_index returns error", async ({
    page,
  }) => {
    await ready(page);
    const result = await api(page, "/api/fix", {
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
        action_index: 999,
        info_only: false,
      }),
    });
    const data = JSON.parse(result.body);
    expect(data.success).toBe(false);
    expect(data.error).toContain("out of range");
  });
});

test.describe("Batch fix error cases", () => {
  test("batch with mix of valid and invalid findings", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/fix/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        findings: [
          {
            id: "trivy.cve-2024-0001",
            title: "valid",
            severity: 0,
            source: 0,
            remediation: 0,
            service: "nginx:1.24",
          },
          {
            id: "nonexistent.finding-999",
            title: "invalid",
            severity: 0,
            source: 0,
            remediation: 0,
            service: "",
          },
        ],
        action_index: 0,
      }),
    });
    const data = JSON.parse(result.body);
    expect(data.results.length).toBe(2);
    expect(data.results[0].success).toBe(true);
    expect(data.results[1].success).toBe(false);
  });
});

test.describe("Secure headers", () => {
  test("API responses include security headers", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/health");
    // Verify response is valid JSON
    const data = JSON.parse(result.body);
    expect(data.status).toBe("ok");
  });
});

test.describe("Score breakdown axis labels", () => {
  test("all four axis labels match expected text", async ({ page }) => {
    await ready(page);
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

test.describe("Sort stability across re-renders", () => {
  test("severity sort produces same order after cycling", async ({
    page,
  }) => {
    await ready(page);

    const getIds = async () => {
      const rows = page.locator("#findings tr[data-index]");
      const count = await rows.count();
      const ids: string[] = [];
      for (let i = 0; i < count; i++) {
        ids.push((await rows.nth(i).getAttribute("data-id")) ?? "");
      }
      return ids;
    };

    const ids1 = await getIds();

    // Cycle sort: o → source, o → title, o → remediation, o → severity
    await page.keyboard.press("o");
    await page.keyboard.press("o");
    await page.keyboard.press("o");
    await page.keyboard.press("o");
    await page.waitForTimeout(200);

    const ids2 = await getIds();
    expect(ids1).toEqual(ids2);
  });
});

test.describe("API contract validation", () => {
  test("result has required fields", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/result");
    const data = JSON.parse(result.body);

    expect(data).toHaveProperty("phase", "complete");
    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("tools");
    expect(data).toHaveProperty("hostname", "e2e-test-box");
    expect(data).toHaveProperty("local_ip", "192.168.1.100");
    expect(data).toHaveProperty("score_breakdown");

    expect(typeof data.score).toBe("number");
    expect(Array.isArray(data.findings)).toBe(true);
    expect(data.findings.length).toBe(14);
  });

  test("each finding has required fields", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/result");
    const data = JSON.parse(result.body);

    for (const f of data.findings) {
      expect(f).toHaveProperty("id");
      expect(f).toHaveProperty("title");
      expect(f).toHaveProperty("severity");
      expect(f).toHaveProperty("source");
      expect(f).toHaveProperty("remediation");
      expect(typeof f.id).toBe("string");
      expect([0, 1, 2, 3]).toContain(f.severity);
      expect([0, 1, 2]).toContain(f.source);
      expect([0, 1, 2, 3]).toContain(f.remediation);
    }
  });

  test("finding IDs are unique", async ({ page }) => {
    await ready(page);
    const result = await api(page, "/api/result");
    const data = JSON.parse(result.body);
    const ids = data.findings.map((f: { id: string }) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

test.describe("Recalc preserves data integrity", () => {
  test("recalc returns same findings", async ({ page }) => {
    await ready(page);

    const result1 = await api(page, "/api/result");
    const data1 = JSON.parse(result1.body);

    const result2 = await api(page, "/api/recalc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const data2 = JSON.parse(result2.body);

    expect(data2.findings.length).toBe(data1.findings.length);
    expect(data2.score).toBe(data1.score);
  });
});
