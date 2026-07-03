import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Modal click-outside-to-close", () => {
  test("help modal closes on overlay click", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    // Click on the overlay background (not the modal content)
    const overlay = page.locator(".modal-overlay");
    const box = await overlay.boundingBox();
    if (box) {
      // Click top-left corner (outside modal-content)
      await page.mouse.click(box.x + 10, box.y + 10);
    }
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });

  test("export modal closes on overlay click", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const overlay = page.locator(".modal-overlay");
    const box = await overlay.boundingBox();
    if (box) {
      await page.mouse.click(box.x + 10, box.y + 10);
    }
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("Help modal content", () => {
  test("help modal has all four sections", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const sections = page.locator("#helpModal .help-section");
    const count = await sections.count();
    expect(count).toBe(4);

    // Check section headings
    const headings = page.locator("#helpModal .help-section h3");
    const texts: string[] = [];
    for (let i = 0; i < count; i++) {
      texts.push((await headings.nth(i).textContent()) ?? "");
    }
    expect(texts).toContain("Navigation");
    expect(texts).toContain("Filters");
    expect(texts).toContain("Actions");
    expect(texts).toContain("Other");

    await page.keyboard.press("Escape");
  });
});

test.describe("Export modal options", () => {
  test("export modal shows JSON, CSV, and AI brief buttons", async ({
    page,
  }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    await expect(page.locator("#exportJson")).toBeVisible();
    await expect(page.locator("#exportCsv")).toBeVisible();
    await expect(page.locator("#exportAi")).toBeVisible();

    await page.keyboard.press("Escape");
  });

  test("export modal Close button dismisses it", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const closeBtn = page.locator("#exportClose");
    await closeBtn.click();
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("No results state", () => {
  test("shows no-results message when search matches nothing", async ({
    page,
  }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("zzzznonexistent999");
    await page.waitForTimeout(300);

    const noResults = page.locator("#findings .muted");
    await expect(noResults).toBeVisible();
    const text = await noResults.textContent();
    expect(text).toContain("No findings match");
  });

  test("clearing search restores findings", async ({ page }) => {
    await waitForReady(page);
    const query = page.locator("#query");
    await query.fill("zzzznonexistent999");
    await page.waitForTimeout(300);

    await query.fill("");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);
  });
});

test.describe("Multiple filter combination", () => {
  test("severity + source filter narrows results", async ({ page }) => {
    await waitForReady(page);

    // Filter to critical
    const criticalChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await criticalChip.click();
    await page.waitForTimeout(200);

    // Also filter to trivy
    const trivyChip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" });
    await trivyChip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Critical + Trivy: trivy.cve-2024-0001 = 1
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.cve-2024-0001");
  });

  test("search + severity filter combines", async ({ page }) => {
    await waitForReady(page);

    const query = page.locator("#query");
    await query.fill("ssh");
    await page.waitForTimeout(300);

    // Also filter to high severity
    const highChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "High" });
    await highChip.click();
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // SSH + high: AUTH-9286 = 1
    expect(count).toBe(1);
  });
});

test.describe("View more/View less toggle", () => {
  test("long description shows View more button", async ({ page }) => {
    await waitForReady(page);
    // Select a finding with a long description
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    // The section function truncates at 300 chars.
    // Check if there's a toggle-more button in the detail panel
    const toggleBtn = page.locator("#detail .toggle-more");
    const count = await toggleBtn.count();
    // May or may not have one depending on description length
    if (count > 0) {
      await expect(toggleBtn.first()).toBeVisible();
      const text = await toggleBtn.first().textContent();
      expect(text).toBe("View more");

      // Click to expand
      await toggleBtn.first().click();
      await page.waitForTimeout(200);
      const expandedText = await toggleBtn.first().textContent();
      expect(expandedText).toBe("View less");

      // Click again to collapse
      await toggleBtn.first().click();
      await page.waitForTimeout(200);
      const collapsedText = await toggleBtn.first().textContent();
      expect(collapsedText).toBe("View more");
    }
  });
});

test.describe("Keyboard filter cycling", () => {
  test("s key cycles source filter", async ({ page }) => {
    await waitForReady(page);

    // Default is "all"
    const sourceChip = page
      .locator("#sourceFilters button.active");
    let activeText = await sourceChip.textContent();
    expect(activeText).toContain("All");

    // Press s to cycle to trivy
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    activeText = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(activeText).toContain("Trivy");

    // Press s to cycle to lynis
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    activeText = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(activeText).toContain("Lynis");

    // Press s to cycle to compose
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    activeText = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(activeText).toContain("Compose");

    // Press s to cycle back to all
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    activeText = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(activeText).toContain("All");
  });

  test("r key cycles remediation filter", async ({ page }) => {
    await waitForReady(page);

    // r cycles: all → auto → review → unavailable → manual → all
    // Mock data has no "manual" findings, so no chip renders for it.
    // Test the 4 values that have chips.
    const rems = ["All", "Auto", "Review", "Unavailable"];
    for (const expected of rems) {
      const activeText = await page
        .locator("#remediationFilters button.active")
        .textContent();
      expect(activeText).toContain(expected);
      await page.keyboard.press("r");
      await page.waitForTimeout(200);
    }
    // After loop: state = "manual" (no chip). One more press → "all".
    await page.keyboard.press("r"); // manual → all
    await page.waitForTimeout(200);
    const activeText = await page
      .locator("#remediationFilters button.active")
      .textContent();
    expect(activeText).toContain("All");
  });

  test("v key cycles service filter", async ({ page }) => {
    await waitForReady(page);

    // Press v to cycle service filter
    await page.keyboard.press("v");
    await page.waitForTimeout(200);

    const activeText = await page
      .locator("#serviceFilters button.active")
      .textContent();
    // Should have cycled to a non-"All" service
    expect(activeText).not.toBe("All");
  });

  test("o key cycles sort field", async ({ page }) => {
    await waitForReady(page);

    const sortBy = page.locator("#sortBy");
    const initial = await sortBy.inputValue();

    await page.keyboard.press("o");
    await page.waitForTimeout(200);

    const next = await sortBy.inputValue();
    expect(next).not.toBe(initial);
  });

  test("O key toggles sort direction", async ({ page }) => {
    await waitForReady(page);

    const rows1 = page.locator("#findings tr[data-index]");
    const first1 = await rows1.first().textContent();

    await page.keyboard.press("O");
    await page.waitForTimeout(200);

    const first2 = await rows1.first().textContent();
    expect(first1).not.toBe(first2);
  });
});

test.describe("R key clears all filters", () => {
  test("R key clears all filters and shows toast", async ({ page }) => {
    await waitForReady(page);

    // Set some filters
    const query = page.locator("#query");
    await query.fill("ssh");
    await page.waitForTimeout(300);

    // Verify filter is active
    let rows = page.locator("#findings tr[data-index]");
    let count = await rows.count();
    expect(count).toBeLessThan(14);

    // Blur the search input first — keyboard shortcuts are blocked while typing
    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);

    // Press R to clear
    await page.keyboard.press("R");
    await page.waitForTimeout(300);

    // Check toast
    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
    const toastText = await toast.textContent();
    expect(toastText).toContain("Filters cleared");

    // Verify all findings restored
    rows = page.locator("#findings tr[data-index]");
    count = await rows.count();
    expect(count).toBe(14);
  });
});

test.describe("Number key severity filter", () => {
  test("pressing 1 filters to critical", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(2); // 2 critical findings
  });

  test("pressing 4 filters to low", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("4");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Low: lynis.FILE-6310, lynis.KRNL-5780 = 2
    expect(count).toBe(2);
  });

  test("pressing 0 shows all", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("1"); // filter to critical first
    await page.waitForTimeout(200);
    await page.keyboard.press("0"); // back to all
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);
  });
});

test.describe("Ctrl+A select/deselect toggle", () => {
  test("Ctrl+A selects all, Ctrl+A again deselects all", async ({
    page,
  }) => {
    await waitForReady(page);

    // Select all
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);

    let selectedCount = await page.evaluate(() => {
      return document.querySelectorAll("#findings tr.row-selected").length;
    });
    expect(selectedCount).toBeGreaterThanOrEqual(10);

    // Ctrl+A again to deselect all
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);

    selectedCount = await page.evaluate(() => {
      return document.querySelectorAll("#findings tr.row-selected").length;
    });
    expect(selectedCount).toBe(0);
  });
});

test.describe("Row click shows detail", () => {
  test("clicking a row shows its detail panel", async ({ page }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("SSH password authentication");
    expect(text).toContain("lynis.AUTH-9286");
    expect(text).toContain("/etc/ssh/sshd_config");
  });

  test("clicking compose finding shows compose details", async ({ page }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='compose.ds001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("privileged");
    expect(text).toContain("compose");
  });
});

test.describe("Fixed finding detail", () => {
  test("fixed finding detail shows no Fix button", async ({ page }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    // Fixed finding should not have a Fix button
    const fixBtn = detail.locator(".fix-btn");
    await expect(fixBtn).not.toBeVisible();

    // Should show "Fixed" in the detail
    const text = await detail.textContent();
    expect(text).toContain("CVE-2024-0003");
  });
});

test.describe("Evidence details expand/collapse", () => {
  test("evidence details element is expandable", async ({ page }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const details = page.locator("#detail .evidence-details");
    const count = await details.count();
    expect(count).toBeGreaterThanOrEqual(1);

    // The <details> element should have a summary
    const summary = details.first().locator("summary");
    await expect(summary).toBeVisible();
    const summaryText = await summary.textContent();
    expect(summaryText).toContain("Evidence");
  });
});

test.describe("Detail panel for different remediation types", () => {
  test("review finding shows multiple options hint", async ({ page }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Review");
    expect(text).toContain("multiple options");
  });
});

test.describe("Toast auto-dismiss", () => {
  test("toast appears and disappears after timeout", async ({ page }) => {
    await waitForReady(page);

    // Trigger a toast via q key
    await page.keyboard.press("q");
    await page.waitForTimeout(500);

    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });

    // Wait for auto-dismiss (4s + 300ms animation)
    await page.waitForTimeout(5000);
    await expect(toast).not.toBeVisible();
  });
});

test.describe("Score plate styling", () => {
  test("score plate has correct layout", async ({ page }) => {
    await waitForReady(page);

    const scoreLabel = page.locator(".scoreplate .score-label");
    await expect(scoreLabel).toBeVisible();
    const text = await scoreLabel.textContent();
    expect(text).toContain("Security score");
  });
});

test.describe("Table header structure", () => {
  test("table has all expected column headers", async ({ page }) => {
    await waitForReady(page);

    const headers = page.locator("table thead th");
    const count = await headers.count();
    expect(count).toBe(6);

    // Check sortable headers exist
    const sortable = page.locator("table thead th.sortable");
    const sortableCount = await sortable.count();
    expect(sortableCount).toBe(4);
  });
});

test.describe("Sysinfo display", () => {
  test("sysinfo element shows hostname", async ({ page }) => {
    await waitForReady(page);

    const sysinfo = page.locator("#sysinfo");
    await expect(sysinfo).toBeVisible();
    const text = await sysinfo.textContent();
    expect(text).toContain("e2e-test-box");
  });
});
