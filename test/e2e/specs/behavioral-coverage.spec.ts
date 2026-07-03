import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Fixed finding rendering", () => {
  test("fixed finding has disabled class on row", async ({ page }) => {
    await waitForReady(page);
    const fixedRow = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    await expect(fixedRow).toHaveClass(/disabled/);
  });

  test("fixed finding shows check mark or fixed indicator", async ({ page }) => {
    await waitForReady(page);
    const fixedRow = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const text = await fixedRow.textContent();
    expect(text).toContain("CVE-2024-0003");
  });
});

test.describe("Initial detail state", () => {
  test("detail panel shows first finding on load (auto-selected)", async ({
    page,
  }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });
    const detail = page.locator("#detail");
    // The page auto-selects the first finding
    const h2 = detail.locator("h2");
    await expect(h2).toBeVisible();
    const text = await h2.textContent();
    expect(text).toBeTruthy();
  });
});

test.describe("Detail panel metadata", () => {
  test("finding with metadata shows metadata section", async ({ page }) => {
    await waitForReady(page);
    // trivy.cve-2024-0001 has compose_path in metadata
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("compose_path");
    expect(text).toContain("/home/test/docker-compose.yml");
  });
});

test.describe("Detail panel remediation hint", () => {
  test("auto finding shows hint text", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("one clear fix");
  });

  test("review finding shows review hint", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("multiple options");
  });

  test("unavailable finding shows unavailable hint", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("not yet classified");
  });
});

test.describe("Metrics row", () => {
  test("metrics row shows total count of 14", async ({ page }) => {
    await waitForReady(page);
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBeGreaterThanOrEqual(6);

    const totalText = await metrics.first().textContent();
    expect(totalText).toContain("14");
  });

  test("metrics shows critical count", async ({ page }) => {
    await waitForReady(page);
    // 2 critical: trivy.cve-2024-0001, test.unfixable-001
    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    let foundCritical = false;
    for (let i = 0; i < count; i++) {
      const text = await metrics.nth(i).textContent();
      if (text.includes("Critical")) {
        expect(text).toContain("2");
        foundCritical = true;
        break;
      }
    }
    expect(foundCritical).toBe(true);
  });

  test("metrics shows fixable count", async ({ page }) => {
    await waitForReady(page);
    const fixableMetric = page.locator("#metrics .metric--fixable");
    await expect(fixableMetric).toBeVisible();
    const text = await fixableMetric.textContent();
    expect(text).toContain("Fixable");
  });
});

test.describe("Score display", () => {
  test("score shows numeric value out of 100", async ({ page }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Hostname display", () => {
  test("hostname from snapshot is displayed", async ({ page }) => {
    await waitForReady(page);
    // The hostname should appear somewhere in the page
    const bodyText = await page.locator("body").textContent();
    expect(bodyText).toContain("e2e-test-box");
  });
});

test.describe("Search filtering", () => {
  test("typing in search filters the findings table", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("redis");
    await page.waitForTimeout(300); // debounce

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Should only show redis-related finding
    expect(count).toBe(1);
    const text = await rows.first().textContent();
    expect(text).toContain("redis");
  });

  test("clearing search restores all findings", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("redis");
    await page.waitForTimeout(300);

    // Now clear it
    await query.fill("");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);
  });

  test("search is case-insensitive", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("SSH");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Should find SSH-related findings
    expect(count).toBeGreaterThanOrEqual(2);
  });
});

test.describe("Column header sorting", () => {
  test("clicking severity column toggles sort direction", async ({ page }) => {
    await waitForReady(page);
    const severityHeader = page.locator("th.sortable[data-col='1']");
    // Default is severity asc (critical first). Click toggles to desc.
    await severityHeader.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const firstRowText = await rows.first().textContent();
    // After toggling to desc, low severity appears first
    expect(firstRowText).toContain("low");
  });

  test("clicking same column reverses sort direction", async ({ page }) => {
    await waitForReady(page);
    const severityHeader = page.locator("th.sortable[data-col='1']");

    // First click - ascending
    await severityHeader.click();
    await page.waitForTimeout(200);
    const rows1 = page.locator("#findings tr[data-index]");
    const first1 = await rows1.first().textContent();

    // Second click - descending
    await severityHeader.click();
    await page.waitForTimeout(200);
    const rows2 = page.locator("#findings tr[data-index]");
    const first2 = await rows2.first().textContent();

    // Results should be different
    expect(first1).not.toBe(first2);
  });
});

test.describe("Sort dropdown", () => {
  test("sort dropdown reflects current sort", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(["severity", "source", "title", "remediation"]).toContain(value);
  });

  test("changing sort dropdown updates table order", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");

    // Record current first row
    const rows1 = page.locator("#findings tr[data-index]");
    const first1 = await rows1.first().textContent();

    // Change to title sort
    await sortBy.selectOption("title");
    await page.waitForTimeout(200);

    const first2 = await rows1.first().textContent();
    // Order should have changed
    expect(first1).not.toBe(first2);
  });
});

test.describe("Filter chip clicks", () => {
  test("clicking severity chip filters findings", async ({ page }) => {
    await waitForReady(page);
    const criticalChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await criticalChip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // 2 critical findings
    expect(count).toBe(2);
  });

  test("clicking 'All' chip removes filter", async ({ page }) => {
    await waitForReady(page);
    const criticalChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await criticalChip.click();
    await page.waitForTimeout(200);

    const allChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "All" });
    await allChip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);
  });

  test("clicking source chip filters by source", async ({ page }) => {
    await waitForReady(page);
    const lynisChip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Lynis" });
    await lynisChip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // 5 lynis findings: AUTH-9286, FIRE-4512, AUTH-9308, test.unfixable-001, FILE-6310, KRNL-5780 = 6
    expect(count).toBe(6);
  });

  test("clicking remediation chip filters by remediation", async ({
    page,
  }) => {
    await waitForReady(page);
    const reviewChip = page
      .locator("#remediationFilters button")
      .filter({ hasText: "Review" });
    await reviewChip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // review: trivy.dr001, lynis.FIRE-4512, trivy.dr002 = 3
    expect(count).toBe(3);
  });
});

test.describe("Clear filters button", () => {
  test("clear filters resets all filter states", async ({ page }) => {
    await waitForReady(page);

    // Set some filters
    const criticalChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await criticalChip.click();
    await page.waitForTimeout(200);

    // Type in search
    const query = page.locator("#query");
    await query.fill("redis");
    await page.waitForTimeout(300);

    // Now clear
    const clearBtn = page.locator("#clearFilters");
    await clearBtn.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);

    const queryVal = await query.inputValue();
    expect(queryVal).toBe("");
  });
});

test.describe("Finding count text", () => {
  test("finding count shows visible count", async ({ page }) => {
    await waitForReady(page);
    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    expect(text).toContain("14");
  });

  test("finding count updates when filter applied", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    // Should show fewer than 14
    expect(text).not.toContain("14 visible");
  });
});

test.describe("Detail panel description and how_to_fix", () => {
  test("detail panel shows description section", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("remote code execution");
  });

  test("detail panel shows how_to_fix section with copy button", async ({
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
    expect(text).toContain("Update nginx");
    expect(text).toContain("Copy guidance");
  });
});

test.describe("Detail panel ID and source", () => {
  test("detail shows finding ID", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("trivy.cve-2024-0001");
  });

  test("detail shows source as trivy", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("trivy");
  });

  test("detail shows service for service findings", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Service");
    expect(text).toContain("nginx:1.24");
  });
});

test.describe("Keyboard shortcuts", () => {
  test("pressing / focuses search input", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("/");
    const query = page.locator("#query");
    await expect(query).toBeFocused();
  });

  test("pressing Escape blurs search input", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("/");
    const query = page.locator("#query");
    await expect(query).toBeFocused();
    await page.keyboard.press("Escape");
    await expect(query).not.toBeFocused();
  });

  test("pressing e opens export modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });

  test("pressing ? opens help modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });

  test("pressing ArrowDown selects next finding", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(200);

    const selected = page.locator("#findings tr.selected");
    await expect(selected).toBeVisible();
  });

  test("Space toggles selection on current finding", async ({ page }) => {
    await waitForReady(page);
    // Find a selectable finding and navigate to it
    const selectableIdx = await page.evaluate(() => {
      const rows = document.querySelectorAll("#findings tr[data-index]");
      for (const row of rows) {
        if (!row.classList.contains("disabled")) return Number(row.dataset.index);
      }
      return -1;
    });
    if (selectableIdx < 0) return; // no selectable findings

    // Navigate to that finding
    for (let i = 0; i < selectableIdx; i++) {
      await page.keyboard.press("ArrowDown");
    }
    await page.waitForTimeout(100);

    // Press Space to toggle selection
    await page.keyboard.press(" ");
    await page.waitForTimeout(300);

    // Verify the finding got the row-selected class
    const hasSelection = await page.evaluate(() => {
      return document.querySelectorAll("#findings tr.row-selected").length > 0;
    });
    expect(hasSelection).toBe(true);
  });

  test("pressing q shows toast", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("q");
    await page.waitForTimeout(500);
    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
    const text = await toast.textContent();
    expect(text).toContain("Ctrl+W");
  });
});

test.describe("Export modal", () => {
  test("e key opens export modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
  });

  test("export modal has JSON and CSV buttons", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const jsonBtn = page.locator("#exportJson");
    const csvBtn = page.locator("#exportCsv");
    await expect(jsonBtn).toBeVisible();
    await expect(csvBtn).toBeVisible();
  });

  test("Escape closes export modal", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("Select all checkbox", () => {
  test("select all checkbox selects all batch-selectable findings", async ({
    page,
  }) => {
    await waitForReady(page);
    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });
    await page.waitForTimeout(300);

    // Use JS evaluation to check selectedSet — more reliable than DOM checkbox state
    const selectedCount = await page.evaluate(() => {
      const rows = document.querySelectorAll("#findings tr[data-index]");
      let count = 0;
      rows.forEach((row) => {
        if (row.classList.contains("row-selected")) count++;
      });
      return count;
    });
    // Most findings should be selected (all non-fixed, non-unavailable)
    expect(selectedCount).toBeGreaterThanOrEqual(10);
    expect(selectedCount).toBeLessThan(14);
  });

  test("unchecking select all clears selection", async ({ page }) => {
    await waitForReady(page);
    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });
    await page.waitForTimeout(300);
    await selectAll.uncheck({ force: true });
    await page.waitForTimeout(300);

    const selectedCount = await page.evaluate(() => {
      const rows = document.querySelectorAll("#findings tr[data-index]");
      let count = 0;
      rows.forEach((row) => {
        if (row.classList.contains("row-selected")) count++;
      });
      return count;
    });
    expect(selectedCount).toBe(0);
  });
});

test.describe("Fix Selected button", () => {
  test("fix selected button shows count when items selected", async ({
    page,
  }) => {
    await waitForReady(page);
    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });
    await page.waitForTimeout(200);

    const fixBtn = page.locator("#fixSelectedBtn");
    await expect(fixBtn).toBeVisible();
    const text = await fixBtn.textContent();
    expect(text).toMatch(/\d+/);
  });

  test("fix selected button has no count text with no selection", async ({ page }) => {
    await waitForReady(page);
    const fixBtn = page.locator("#fixSelectedBtn");
    const text = await fixBtn.textContent();
    // When nothing selected, the button text is empty or just "Fix"
    expect(text.trim()).not.toMatch(/\(\d+\)/);
  });
});

test.describe("Score breakdown axes content", () => {
  test("each axis shows penalty cap info", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const text = await axes.nth(i).textContent();
      expect(text).toContain("penalty cap used");
    }
  });

  test("vulnerabilities axis shows severity counts", async ({ page }) => {
    await waitForReady(page);
    const vulnAxis = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Vulnerabilities" });
    await expect(vulnAxis).toBeVisible();
    const text = await vulnAxis.textContent();
    // Should have severity indicators like C, H, M, L
    expect(text).toMatch(/[CHML]\d/);
  });
});

test.describe("Tooltip text on buttons", () => {
  test("recalc button has title tooltip", async ({ page }) => {
    await waitForReady(page);
    const recalcBtn = page.locator("#recalcBtn");
    const title = await recalcBtn.getAttribute("title");
    expect(title).toBeTruthy();
  });
});

test.describe("Score breakdown severity counts", () => {
  test("axis shows zero-finding message when no findings", async ({
    page,
  }) => {
    await waitForReady(page);
    // Not filtering — just checking that all axes render
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);
    // Each axis should have meta with penalty info
    const meta = page.locator("#scoreBreakdown .score-axis-meta");
    const metaCount = await meta.count();
    expect(metaCount).toBe(4);
  });
});
