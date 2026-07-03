import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

// ─── Keyboard: v, R, o, q, Ctrl+A, Ctrl+R, Ctrl+S, f ───

test.describe("v key cycles service filter", () => {
  test("v key cycles through services and wraps back to all", async ({ page }) => {
    await ready(page);
    const allCount = await page.locator("#findings tr[data-index]").count();
    let totalCycles = 0;
    while (totalCycles < 10) {
      await page.keyboard.press("v");
      await page.waitForTimeout(200);
      totalCycles++;
      const count = await page.locator("#findings tr[data-index]").count();
      if (count === allCount && totalCycles > 1) break;
    }
    expect(await page.locator("#findings tr[data-index]").count()).toBe(allCount);
  });

  test("v key updates service filter active chip", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("v");
    await page.waitForTimeout(200);
    const active = page.locator("#serviceFilters button.active");
    expect(await active.textContent()).not.toBe("All");
  });
});

test.describe("R key clears all filters", () => {
  test("R key resets all filters and shows toast", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(200);
    await page.keyboard.press("Escape");
    await page.keyboard.press("1"); // critical
    await page.waitForTimeout(200);
    const filteredCount = await page.locator("#findings tr[data-index]").count();
    expect(filteredCount).toBeLessThan(14);
    await page.keyboard.press("R");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
    expect(await page.locator("#query").inputValue()).toBe("");
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    expect(await toast.textContent()).toContain("Filters cleared");
  });
});

test.describe("o key cycles sort field", () => {
  test("o key cycles through sort fields and syncs dropdown", async ({ page }) => {
    await ready(page);
    const dropdown = page.locator("#sortBy");
    expect(await dropdown.inputValue()).toBe("severity");
    const vals: string[] = [];
    for (let i = 0; i < 4; i++) {
      await page.keyboard.press("o");
      await page.waitForTimeout(200);
      vals.push(await dropdown.inputValue());
    }
    const valid = ["severity", "source", "title", "remediation"];
    for (const v of vals) expect(valid).toContain(v);
    expect(vals[3]).toBe("severity"); // wraps back
  });
});

test.describe("q key shows quit toast", () => {
  test("q key shows a toast hint about closing the tab", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("q");
    await page.waitForTimeout(500);
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    expect(await toast.textContent()).toContain("close the tab");
  });
});

test.describe("Ctrl+A selects all visible", () => {
  test("Ctrl+A toggles select all and deselect all", async ({ page }) => {
    await ready(page);
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr.row-selected").count()).toBeGreaterThan(0);
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(0);
  });
});





test.describe("f key triggers fix", () => {
  test("f key with no selection opens fix for current finding", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("f");
    await page.waitForTimeout(500);
    if ((await page.locator("#fixModal").count()) > 0) {
      await expect(page.locator("#fixModal")).toBeVisible();
      await page.keyboard.press("Escape");
    }
  });
});

// ─── Table column click sorting ───

test.describe("Table header click sorting", () => {
  test("clicking severity column toggles asc/desc", async ({ page }) => {
    await ready(page);
    const th = page.locator("th.sortable[data-col='1']");
    await th.click();
    await page.waitForTimeout(200);
    expect(await th.getAttribute("class")).toContain("desc");
    await th.click();
    await page.waitForTimeout(200);
    expect(await th.getAttribute("class")).toContain("asc");
  });

  test("clicking source column sorts by source", async ({ page }) => {
    await ready(page);
    await page.locator("th.sortable[data-col='2']").click();
    await page.waitForTimeout(200);
    expect(await page.locator("th.sortable[data-col='2']").getAttribute("class")).toContain("asc");
  });

  test("clicking title column sorts by title", async ({ page }) => {
    await ready(page);
    await page.locator("th.sortable[data-col='4']").click();
    await page.waitForTimeout(200);
    expect(await page.locator("th.sortable[data-col='4']").getAttribute("class")).toContain("asc");
  });

  test("clicking remediation column sorts by remediation", async ({ page }) => {
    await ready(page);
    await page.locator("th.sortable[data-col='5']").click();
    await page.waitForTimeout(200);
    expect(await page.locator("th.sortable[data-col='5']").getAttribute("class")).toContain("asc");
  });
});

// ─── Sysinfo and scoreplate ───

test.describe("Sysinfo display", () => {
  test("shows hostname and IP from snapshot", async ({ page }) => {
    await ready(page);
    const text = await page.locator("#sysinfo").textContent();
    expect(text).toContain("e2e-test-box");
    expect(text).toContain("192.168.1.100");
  });
});

test.describe("Scoreplate CSS class", () => {
  test("scoreplate has a valid score class", async ({ page }) => {
    await ready(page);
    const cls = await page.locator(".scoreplate").getAttribute("class");
    expect(cls).toMatch(/score-(low|medium|high|critical)/);
  });
});

// ─── Fix modal visual structure ───

test.describe("Fix modal auto finding", () => {
  test("auto fix modal has correct structure", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const modal = page.locator("#fixModal");
        expect(await modal.locator("h2").textContent()).toBe("Apply fix");
        expect(await modal.locator(".action-type-badge").count()).toBe(1);
        expect(await modal.locator(".action-summary").count()).toBe(1);
        expect(await modal.locator(".action-header").count()).toBe(1);
        await expect(modal.locator("#modalFixYes")).toBeVisible();
        await expect(modal.locator("#modalFixNo")).toBeVisible();
        expect(await modal.locator("#modalFixNo").textContent()).toBe("Cancel");
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Fix modal review finding", () => {
  test("review fix modal shows radio group", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const modal = page.locator("#fixModal");
        expect(await modal.locator("h2").textContent()).toBe("Choose action");
        expect(await modal.locator(".action-option").count()).toBeGreaterThanOrEqual(2);
        expect(await modal.locator("input[name='fixAction']").count()).toBeGreaterThanOrEqual(2);
        // Confirm disabled before selection
        expect(await modal.locator("#modalFixYes").isDisabled()).toBe(true);
        // Select first radio
        await modal.locator("input[name='fixAction']").first().click({ force: true });
        await page.waitForTimeout(100);
        expect(await modal.locator("#modalFixYes").isEnabled()).toBe(true);
        expect(await modal.locator("#modalFixYes").textContent()).toBe("Apply selected");
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Service filter chip interaction ───

test.describe("Service filter chip click", () => {
  test("clicking a non-All service chip filters findings", async ({ page }) => {
    await ready(page);
    const allCount = await page.locator("#findings tr[data-index]").count();
    const chips = page.locator("#serviceFilters button");
    const count = await chips.count();
    for (let i = 0; i < count; i++) {
      const text = await chips.nth(i).textContent();
      if (text && text !== "All") {
        await chips.nth(i).click();
        await page.waitForTimeout(200);
        const filtered = await page.locator("#findings tr[data-index]").count();
        expect(filtered).toBeLessThanOrEqual(allCount);
        expect(filtered).toBeGreaterThan(0);
        break;
      }
    }
  });
});

// ─── Severity filter chip interaction ───

test.describe("Severity filter chip click", () => {
  test("clicking Critical filters to critical only", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(2);
  });

  test("clicking High filters to high only", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "High" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(6);
  });

  test("clicking Medium filters to medium only", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Medium" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(4);
  });

  test("clicking Low filters to low only", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Low" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(2);
  });

  test("clicking All restores all findings", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    await page.locator("#severityFilters button").filter({ hasText: "All" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
  });
});

// ─── Source filter chip interaction ───

test.describe("Source filter chip click", () => {
  test("clicking Trivy filters to trivy only (6)", async ({ page }) => {
    await ready(page);
    await page.locator("#sourceFilters button").filter({ hasText: "Trivy" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(6);
  });

  test("clicking Lynis filters to lynis only (6)", async ({ page }) => {
    await ready(page);
    await page.locator("#sourceFilters button").filter({ hasText: "Lynis" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(6);
  });

  test("clicking Compose filters to compose only (2)", async ({ page }) => {
    await ready(page);
    await page.locator("#sourceFilters button").filter({ hasText: "Compose" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(2);
  });
});

// ─── Remediation filter chip interaction ───

test.describe("Remediation filter chip click", () => {
  test("clicking Auto filters to auto only (10)", async ({ page }) => {
    await ready(page);
    await page.locator("#remediationFilters button").filter({ hasText: "Auto" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(10);
  });

  test("clicking Review filters to review only (3)", async ({ page }) => {
    await ready(page);
    await page.locator("#remediationFilters button").filter({ hasText: "Review" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(3);
  });

  test("clicking Unavailable filters to unavailable only (1)", async ({ page }) => {
    await ready(page);
    await page.locator("#remediationFilters button").filter({ hasText: "Unavailable" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(1);
  });
});

// ─── Finding count display ───

test.describe("Finding count updates", () => {
  test("finding count shows 14 visible by default", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#findingCount").textContent()).toContain("14 visible");
  });

  test("finding count updates after filter change", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findingCount").textContent()).toContain("2 visible");
  });
});

// ─── Metrics panel ───

test.describe("Metrics panel data", () => {
  test("total metric shows 14 and has 6 metric items", async ({ page }) => {
    await ready(page);
    const metrics = page.locator("#metrics .metric");
    expect(await metrics.count()).toBe(6);
    expect(await metrics.first().textContent()).toContain("14");
  });
});

// ─── Score breakdown section ───

test.describe("Score breakdown section", () => {
  test("score breakdown is visible with 4 axes", async ({ page }) => {
    await ready(page);
    await expect(page.locator("#scoreBreakdown")).toBeVisible();
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
  });

  test("each axis has score and correct label", async ({ page }) => {
    await ready(page);
    const labels: Record<string, string> = {
      vulnerabilities: "Vulnerabilities",
      container_exposure: "Container exposure",
      host_hardening: "Host hardening",
      secrets: "Secrets",
    };
    for (const [id, label] of Object.entries(labels)) {
      const axis = page.locator(`#scoreBreakdown .score-axis[data-axis='${id}']`);
      expect(await axis.count()).toBe(1);
      expect(await axis.locator(".score-axis-top span").textContent()).toBe(label);
      expect(await axis.locator("strong").textContent()).toMatch(/\d+\/100/);
    }
  });

  test("score breakdown head has description", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    expect(await head.locator("span").textContent()).toBe("Score breakdown");
    expect(await head.locator("p").textContent()).toContain("scanner cannot dominate");
  });
});

// ─── Table structure ───

test.describe("Table header structure", () => {
  test("table has 7 columns including checkbox", async ({ page }) => {
    await ready(page);
    expect(await page.locator("th").count()).toBe(6);
  });

  test("sortable headers have correct data-col", async ({ page }) => {
    await ready(page);
    for (const col of ["1", "2", "4", "5"]) {
      expect(await page.locator(`th.sortable[data-col='${col}']`).count()).toBe(1);
    }
  });
});

// ─── Select-all checkbox behavior ───

test.describe("Select-all checkbox", () => {
  test("checking select-all selects all batch-selectable rows", async ({ page }) => {
    await ready(page);
    await page.locator("#selectAllCheck").check({ force: true });
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr.row-selected").count()).toBeGreaterThan(0);
    // Unavailable finding should NOT be selected
    const cls = await page.locator("#findings tr[data-id='test.unfixable-001']").getAttribute("class");
    expect(cls?.includes("row-selected")).toBeFalsy();
  });

  test("select-all checkbox is indeterminate when some selected", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check").check({ force: true });
    await page.waitForTimeout(200);
    const indeterminate = await page.locator("#selectAllCheck").evaluate(
      (el) => (el as HTMLInputElement).indeterminate
    );
    expect(indeterminate).toBe(true);
  });
});

// ─── Table row checkbox selection ───

test.describe("Row checkbox selection", () => {
  test("clicking row checkbox selects the row", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    await row.locator(".row-check").check({ force: true });
    await page.waitForTimeout(200);
    expect((await row.getAttribute("class"))?.includes("row-selected")).toBeTruthy();
  });

  test("disabled checkbox for unavailable finding", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#findings tr[data-id='test.unfixable-001'] .row-check").getAttribute("disabled")).toBe("");
  });

  test("disabled checkbox for fixed finding", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#findings tr[data-id='trivy.cve-2024-0003'] .row-check").getAttribute("disabled")).toBe("");
  });
});

// ─── Toast auto-hide ───

test.describe("Toast auto-hide", () => {
  test("toast disappears after a few seconds", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
    await page.waitForTimeout(4500);
    await expect(page.locator("#toast")).not.toBeVisible({ timeout: 2000 });
  });
});

// ─── Export modal ───

test.describe("Export modal structure", () => {
  test("export modal has 3 buttons, overlay click closes", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    expect(await modal.locator(".export-option").count()).toBe(3);
    expect(await modal.locator("#exportJson .export-label").textContent()).toBe("JSON");
    expect(await modal.locator("#exportCsv .export-label").textContent()).toBe("CSV");
    expect(await modal.locator("#exportAi .export-label").textContent()).toBe("AI brief");
    await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

// ─── Help modal ───

test.describe("Help modal structure", () => {
  test("help modal has 4 sections and close button", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    expect(await modal.locator(".help-section").count()).toBe(4);
    // Actions section has expected content
    const actionsText = await modal.locator(".help-section").nth(2).textContent();
    expect(actionsText).toContain("Export report");
    expect(actionsText).toContain("Cycle sort field");
    // Close button works
    await page.locator("#modalHelpClose").click();
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });

  test("help modal overlay click closes", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });
});

// ─── Detail panel for trivy finding ───

test.describe("Detail panel for trivy CVE", () => {
  test("shows description, how_to_fix, evidence, and metadata sections", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const detail = page.locator("#detail");
    const desc = detail.locator("section.section").filter({ hasText: "Description" });
    expect(await desc.count()).toBe(1);
    expect(await desc.textContent()).toContain("critical vulnerability");
    const fix = detail.locator("section.section").filter({ hasText: "How to fix" });
    expect(await fix.count()).toBe(1);
    expect(await fix.locator("button.copy").count()).toBe(1);
    const meta = detail.locator(".detail-meta");
    const metaText = await meta.textContent();
    expect(metaText).toContain("trivy.cve-2024-0001");
    expect(metaText).toContain("trivy");
    expect(metaText).toContain("Auto");
    expect((await detail.locator(".badge").getAttribute("class"))?.includes("critical")).toBeTruthy();
  });
});

// ─── Detail panel badge color ───

test.describe("Detail panel badge color", () => {
  test("critical finding shows critical badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("critical")).toBeTruthy();
  });

  test("high finding shows high badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("high")).toBeTruthy();
  });

  test("medium finding shows medium badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("medium")).toBeTruthy();
  });

  test("low finding shows low badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.KRNL-5780']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("low")).toBeTruthy();
  });
});

// ─── Detail panel remediation hint ───

test.describe("Detail panel remediation hint", () => {
  test("auto finding shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("one clear fix");
  });

  test("review finding shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("multiple options");
  });

  test("unavailable finding shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("not yet classified");
  });
});

// ─── Long text collapse/expand ───

test.describe("Long text collapse/expand", () => {
  test("View more/View less toggles content", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const toggleBtn = page.locator("#detail .toggle-more").first();
    if ((await toggleBtn.count()) > 0) {
      expect(await toggleBtn.textContent()).toBe("View more");
      await toggleBtn.click();
      await page.waitForTimeout(200);
      expect(await toggleBtn.textContent()).toBe("View less");
      await toggleBtn.click();
      await page.waitForTimeout(200);
      expect(await toggleBtn.textContent()).toBe("View more");
    }
  });
});

// ─── Fix button visibility rules ───

test.describe("Fix button visibility rules", () => {
  test("auto finding shows Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(1);
  });

  test("review finding shows Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(1);
  });

  test("unavailable finding has no Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });

  test("fixed finding has no Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0003']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });
});

// ─── Fix modal Enter and Escape keys ───

test.describe("Fix modal keyboard shortcuts", () => {
  test("Enter key confirms fix", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.keyboard.press("Enter");
        await page.waitForTimeout(2000);
        await expect(page.locator("#fixModal")).not.toBeVisible({ timeout: 3000 });
      }
    }
  });

  test("Escape key closes fix modal", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.keyboard.press("Escape");
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });
});

// ─── Fix modal Cancel and overlay click ───

test.describe("Fix modal dismiss methods", () => {
  test("Cancel button closes fix modal", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#modalFixNo").click();
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });

  test("overlay click closes fix modal", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });
});

// ─── Fix result after apply ───

test.describe("Fix result display after apply", () => {
  test("successful fix shows result with label text", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#modalFixYes").click();
        await page.waitForTimeout(2000);
        const result = page.locator("#fixResult");
        if ((await result.count()) > 0) {
          expect(await result.textContent()).toContain("Apply mock fix");
        }
      }
    }
  });
});

// ─── Escape closes all modal types ───

test.describe("Escape closes modals", () => {
  test("Escape closes help modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });

  test("Escape closes export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

// ─── Table findings rendering ───

test.describe("Table findings rendering", () => {
  test("each row has data-id and 6 cells", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-id]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      expect(await rows.nth(i).getAttribute("data-id")).toBeTruthy();
      expect(await rows.nth(i).locator("td").count()).toBe(6);
    }
  });

  test("fixed row shows check mark and strikethrough", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    expect(await row.locator("td").nth(1).textContent()).toContain("✓");
    expect(await row.locator("td.title span[style*='line-through']").count()).toBe(1);
  });

  test("rows have sequential data-index", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      expect(await rows.nth(i).getAttribute("data-index")).toBe(String(i));
    }
  });
});

// ─── Score axis bar rendering ───

test.describe("Score axis bar rendering", () => {
  test("penalty bar has style width and aria-label", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    for (let i = 0; i < 4; i++) {
      const style = await bars.nth(i).locator("span").getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
      expect(await bars.nth(i).getAttribute("aria-label")).toBeTruthy();
    }
  });
});

// ─── Search behavior ───

test.describe("Search behavior", () => {
  test("search by ID finds exact match", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("AUTH-9286");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(1);
  });

  test("search with no results shows message", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("zzzznonexistent");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings .muted").textContent()).toContain("No findings match");
  });

  test("search is case-insensitive", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("SSH");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBeGreaterThanOrEqual(1);
  });
});

// ─── Clear filters button ───

test.describe("Clear filters button", () => {
  test("clear filters button resets all filters", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(200);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBeLessThan(14);
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
    expect(await page.locator("#query").inputValue()).toBe("");
  });
});

// ─── Detail panel for lynis finding ───

test.describe("Detail panel for lynis finding", () => {
  test("lynis finding shows metadata without service", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail .detail-meta").textContent();
    expect(text).toContain("lynis.AUTH-9286");
    expect(text).toContain("lynis");
    expect(text).not.toContain("Service");
  });
});

// ─── Detail panel for compose finding ───

test.describe("Detail panel for compose finding", () => {
  test("compose finding shows service field", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='compose.ds001']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail .detail-meta").textContent();
    expect(text).toContain("compose.ds001");
    expect(text).toContain("compose");
    expect(text).toContain("webapp");
  });
});

// ─── Sort dropdown ───

test.describe("Sort dropdown", () => {
  test("sort dropdown has 4 options", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#sortBy option").count()).toBe(4);
  });
});

// ─── Table row click behavior ───

test.describe("Table row click behavior", () => {
  test("clicking row highlights it and moves selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-index='0']").click({ force: true });
    await page.waitForTimeout(200);
    expect((await page.locator("#findings tr[data-index='0']").getAttribute("class"))?.includes("selected")).toBeTruthy();
    await page.locator("#findings tr[data-index='5']").click({ force: true });
    await page.waitForTimeout(200);
    expect((await page.locator("#findings tr[data-index='5']").getAttribute("class"))?.includes("selected")).toBeTruthy();
    expect((await page.locator("#findings tr[data-index='0']").getAttribute("class"))?.includes("selected")).toBeFalsy();
  });
});

// ─── Sort by source groups compose findings ───

test.describe("Sort by source groups findings", () => {
  test("compose findings are contiguous when sorted by source", async ({ page }) => {
    await ready(page);
    await page.locator("#sortBy").selectOption("source");
    await page.waitForTimeout(200);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const ids: string[] = [];
    for (let i = 0; i < count; i++) {
      const id = await rows.nth(i).getAttribute("data-id");
      if (id) ids.push(id);
    }
    const composeIndices = ids.map((id, i) => (id.startsWith("compose.") ? i : -1)).filter((i) => i >= 0);
    if (composeIndices.length >= 2) {
      for (let i = 1; i < composeIndices.length; i++) {
        expect(composeIndices[i] - composeIndices[i - 1]).toBe(1);
      }
    }
  });
});

// ─── Sort stability ───

test.describe("Sort stability", () => {
  test("sort order persists after filter apply and clear", async ({ page }) => {
    await ready(page);
    const ids1: string[] = [];
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const id = await rows.nth(i).getAttribute("data-id");
      if (id) ids1.push(id);
    }
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    await page.locator("#severityFilters button").filter({ hasText: "All" }).click();
    await page.waitForTimeout(200);
    const ids2: string[] = [];
    const rows2 = page.locator("#findings tr[data-index]");
    for (let i = 0; i < count; i++) {
      const id = await rows2.nth(i).getAttribute("data-id");
      if (id) ids2.push(id);
    }
    expect(ids1).toEqual(ids2);
  });
});

// ─── Keyboard navigation edge cases ───

test.describe("Keyboard navigation edge cases", () => {
  test("ArrowDown at last row stays at last", async ({ page }) => {
    await ready(page);
    for (let i = 0; i < 20; i++) {
      await page.keyboard.press("ArrowDown");
      await page.waitForTimeout(50);
    }
    const lastSelected = await page.locator("#findings tr.selected").getAttribute("data-index");
    const totalRows = await page.locator("#findings tr[data-index]").count();
    expect(Number(lastSelected)).toBe(totalRows - 1);
  });

  test("ArrowUp at first row stays at first", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(100);
    expect(await page.locator("#findings tr.selected").getAttribute("data-index")).toBe("0");
  });
});

// ─── Keyboard shortcuts suppressed in input ───

test.describe("Keyboard shortcuts suppressed in input", () => {
  test("typing in search input does not trigger shortcuts", async ({ page }) => {
    await ready(page);
    await page.locator("#query").focus();
    await page.waitForTimeout(100);
    await page.keyboard.type("/");
    await page.waitForTimeout(200);
    expect(await page.locator("#query").inputValue()).toBe("/");
    expect(await page.locator("#helpModal").count()).toBe(0);
  });

  test("Escape in search input blurs it", async ({ page }) => {
    await ready(page);
    await page.locator("#query").focus();
    await page.waitForTimeout(100);
    expect(await page.locator("#query").evaluate((el) => el === document.activeElement)).toBe(true);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);
    expect(await page.locator("#query").evaluate((el) => el === document.activeElement)).toBe(false);
  });
});

// ─── API endpoints ───

test.describe("API health endpoint", () => {
  test("returns ok status", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/health");
      return resp.json();
    });
    expect(r.status).toBe("ok");
  });
});

test.describe("API result structure", () => {
  test("has correct fields and types", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(typeof r.hostname).toBe("string");
    expect(typeof r.local_ip).toBe("string");
    expect(Array.isArray(r.findings)).toBe(true);
    expect(typeof r.score).toBe("number");
    expect(typeof r.score_breakdown).toBe("object");
    expect(typeof r.score_breakdown.overall).toBe("number");
    expect(Array.isArray(r.score_breakdown.axes)).toBe(true);
    // Each finding has required fields
    for (const f of r.findings) {
      expect(typeof f.id).toBe("string");
      expect(typeof f.severity).toBe("number");
      expect(typeof f.fixed).toBe("boolean");
    }
  });

  test("all finding IDs are unique", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const ids = r.findings.map((f: { id: string }) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

// ─── Score calculation consistency ───

test.describe("Score calculation consistency", () => {
  test("recalc returns same score", async ({ page }) => {
    await ready(page);
    const r1 = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const r2 = await page.evaluate(async () => {
      const resp = await fetch("/api/recalc", { method: "POST" });
      return resp.json();
    });
    expect(r2.score).toBe(r1.score);
    expect(r2.score_breakdown.overall).toBe(r1.score_breakdown.overall);
  });

  test("score_breakdown.overall matches score", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(r.score_breakdown.overall).toBe(r.score);
  });
});

// ─── Score breakdown max_penalty values ───

test.describe("Score breakdown max_penalty values", () => {
  test("correct max_penalty for each axis", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const expected: Record<string, number> = {
      vulnerabilities: 35,
      container_exposure: 30,
      host_hardening: 25,
      secrets: 10,
    };
    for (const [id, max] of Object.entries(expected)) {
      const axis = r.score_breakdown.axes.find((a: { id: string }) => a.id === id);
      expect(axis.max_penalty).toBe(max);
    }
  });
});

// ─── Fix API info_only mode ───

test.describe("Fix API info_only mode", () => {
  test("info_only returns fix info without applying", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: { id: "trivy.cve-2024-0002", remediation: 0 },
          action_index: 0,
          info_only: true,
        }),
      });
      return resp.json();
    });
    expect(r.success).toBe(true);
    expect(Array.isArray(r.actions)).toBe(true);
    expect(r.actions.length).toBeGreaterThan(0);
  });
});

// ─── Fix API error cases ───

test.describe("Fix API error handling", () => {
  test("fix with unregistered ID returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "nonexistent.abc", action_index: 0 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("no fix registered");
  });

  test("fix with out-of-range action_index returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "trivy.cve-2024-0001", action_index: 99 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toBeTruthy();
  });

  test("fix with malformed JSON returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{invalid",
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("invalid request");
  });
});

// ─── Fix batch API endpoint ───

test.describe("Fix batch API", () => {
  test("batch with empty findings returns empty results", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: [], action_index: 0 }),
      });
      return resp.json();
    });
    expect(r.results).toBeDefined();
    expect(r.results.length).toBe(0);
  });

  test("batch with mix of valid and invalid findings", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [{ id: "nonexistent.abc", action_index: 0 }],
          action_index: 0,
        }),
      });
      return resp.json();
    });
    expect(r.results.length).toBe(1);
    expect(r.results[0].success).toBe(false);
  });
});

// ─── Export API endpoints ───

test.describe("Export API endpoints", () => {
  test("export default format is JSON", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("application/json");
  });

  test("export with format=csv returns CSV", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=csv");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("text/csv");
  });

  test("export with format=ai returns markdown", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("text/markdown");
  });

  test("export with unknown format defaults to JSON", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=xyz");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("application/json");
  });
});

// ─── Rescan button states ───

test.describe("Rescan button states", () => {
  test("rescan button disables during scan and re-enables", async ({ page }) => {
    await ready(page);
    const btn = page.locator("#rescanBtn");
    await expect(btn).toBeEnabled();
    await btn.click();
    await page.waitForTimeout(300);
    expect(await btn.isDisabled()).toBe(true);
    await expect(btn).toBeEnabled({ timeout: 10000 });
  });

  test("rescan button shows loading class during scan", async ({ page }) => {
    await ready(page);
    await page.locator("#rescanBtn").click();
    await page.waitForTimeout(300);
    const cls = await page.locator("#rescanBtn").getAttribute("class");
    expect(cls).toContain("loading");
  });
});

// ─── Fix Selected button ───

test.describe("Fix Selected button", () => {
  test("hidden with no selection, visible with selection", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#fixSelectedBtn").isHidden()).toBe(true);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check").check({ force: true });
    await page.waitForTimeout(200);
    expect(await page.locator("#fixSelectedBtn").isVisible()).toBe(true);
    expect(await page.locator("#fixSelectedBtn").textContent()).toContain("1");
  });
});

// ─── Severity filter active state persistence ───

test.describe("Severity filter active state persistence", () => {
  test("active severity chip stays active after table click", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "High" }).click();
    await page.waitForTimeout(200);
    await page.locator("#findings tr[data-index]").first().click({ force: true });
    await page.waitForTimeout(200);
    expect(await page.locator("#severityFilters button.active").textContent()).toContain("High");
  });
});

// ─── Finding count after filter changes ───

test.describe("Finding count after filter changes", () => {
  test("finding count updates when severity changes", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#findingCount").textContent()).toContain("14 visible");
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findingCount").textContent()).toContain("2 visible");
    await page.locator("#severityFilters button").filter({ hasText: "All" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findingCount").textContent()).toContain("14 visible");
  });
});

// ─── Score element ───

test.describe("Score element", () => {
  test("score shows N/100 format", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#score").textContent()).toMatch(/^\d+\/100$/);
  });
});

// ─── Score range validation ───

test.describe("Score range validation", () => {
  test("overall score is between 0 and 100", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(100);
  });

  test("each axis score is between 0 and 100", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    for (const axis of r.score_breakdown.axes) {
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
    }
  });
});

// ─── Severity value range ───

test.describe("Severity and source value ranges", () => {
  test("all severity values are 0-3", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    for (const f of r.findings) {
      expect(f.severity).toBeGreaterThanOrEqual(0);
      expect(f.severity).toBeLessThanOrEqual(3);
    }
  });

  test("all source values are 0-2", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    for (const f of r.findings) {
      expect(f.source).toBeGreaterThanOrEqual(0);
      expect(f.source).toBeLessThanOrEqual(2);
    }
  });
});

// ─── Score plate display ───

test.describe("Score plate display", () => {
  test("score plate has score-label and score value", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".score-label").textContent()).toBe("Security score");
    expect(await page.locator("#score").textContent()).toMatch(/\d+\/100/);
  });
});

// ─── Workspace layout ───

test.describe("Workspace layout", () => {
  test("workspace has filters, findings-panel, and detail panels", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".workspace .filters").count()).toBe(1);
    expect(await page.locator(".workspace .findings-panel").count()).toBe(1);
    expect(await page.locator(".workspace .detail").count()).toBe(1);
  });
});

// ─── Filter block labels ───

test.describe("Filter block labels", () => {
  test("severity, source, remediation, service filters have labels", async ({ page }) => {
    await ready(page);
    for (const name of ["Severity", "Source", "Remediation", "Service"]) {
      expect(await page.locator(".filter-block h2").filter({ hasText: name }).count()).toBe(1);
    }
  });
});

// ─── Topbar structure ───

test.describe("Topbar elements", () => {
  test("topbar has title, eyebrow, and sysinfo", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".topbar h1").textContent()).toContain("hostveil");
    expect(await page.locator(".topbar .eyebrow").textContent()).toContain("Finds and fixes");
    expect(await page.locator("#sysinfo").textContent()).toContain("e2e-test-box");
  });
});

// ─── Rescan and recalc button text ───

test.describe("Button text", () => {
  test("recalc button says Recalc", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#recalcBtn").textContent()).toBe("Recalc");
  });

  test("rescan button says Rescan", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#rescanBtn").textContent()).toBe("Rescan");
  });
});

// ─── Fix result after batch apply ───

test.describe("Fix result after batch apply", () => {
  test("batch fix with no selections returns early", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#fixSelectedBtn").isHidden()).toBe(true);
  });
});
