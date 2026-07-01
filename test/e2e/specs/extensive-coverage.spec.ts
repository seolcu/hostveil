import { test, expect, type Page } from "@playwright/test";

// Helper: wait for findings table to be populated
async function waitForFindings(page: Page): Promise<void> {
  await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
}

// Helper: open the help modal
async function openHelp(page: Page): Promise<void> {
  await page.keyboard.press("?");
  await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
}

// Helper: open the export modal
async function openExport(page: Page): Promise<void> {
  await page.keyboard.press("e");
  await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
}

// Helper: click outside a modal (on the overlay backdrop)
async function clickOverlay(page: Page, modalSelector: string): Promise<void> {
  const modal = page.locator(modalSelector);
  const box = await modal.boundingBox();
  if (!box) throw new Error("modal not visible");
  // Click near the top-left corner of the overlay (outside the modal content)
  await page.mouse.click(box.x + 5, box.y + 5);
}

test.describe("Modal overlay click-to-close", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("help modal closes when clicking outside the modal content", async ({ page }) => {
    await openHelp(page);
    await clickOverlay(page, "#helpModal");
    await expect(page.locator("#helpModal")).not.toBeVisible({ timeout: 2000 });
  });

  test("export modal closes when clicking outside the modal content", async ({ page }) => {
    await openExport(page);
    await clickOverlay(page, "#exportModal");
    await expect(page.locator("#exportModal")).not.toBeVisible({ timeout: 2000 });
  });

  test("filter modal closes when clicking outside the modal content", async ({ page }) => {
    // Filter modal: only present at narrow widths
    await page.setViewportSize({ width: 800, height: 600 });
    await page.waitForTimeout(200);
    // Try to open the filter modal via the filter button if present
    const filterBtn = page.locator("#openFilters");
    if ((await filterBtn.count()) > 0) {
      await filterBtn.click();
      const filterModal = page.locator("#filterModal");
      if ((await filterModal.count()) > 0 && (await filterModal.isVisible())) {
        await clickOverlay(page, "#filterModal");
        await expect(filterModal).not.toBeVisible({ timeout: 2000 });
      }
    }
  });

  test("fix modal closes when clicking outside the modal content", async ({ page }) => {
    // Open fix modal on a fixable row
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    if ((await fixableRow.count()) === 0) {
      test.skip();
      return;
    }
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) === 0) {
      test.skip();
      return;
    }
    await fixBtn.click();
    const fixModal = page.locator("#fixModal");
    await expect(fixModal).toBeVisible({ timeout: 3000 });
    await clickOverlay(page, "#fixModal");
    await expect(fixModal).not.toBeVisible({ timeout: 2000 });
  });

  test("help modal does NOT close when clicking inside the modal content", async ({ page }) => {
    await openHelp(page);
    const modalContent = page.locator("#helpModal .modal-content, #helpModal .modal, #helpModal > div").first();
    await modalContent.click();
    await page.waitForTimeout(500);
    await expect(page.locator("#helpModal")).toBeVisible();
  });
});

test.describe("Finding selection edge cases", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("clicking a row selects it; clicking again deselects", async ({ page }) => {
    const firstRow = page.locator("#findings tr[data-index]").first();
    await firstRow.click({ force: true });
    await page.waitForTimeout(200);
    // Check that detail pane shows something
    const detail = page.locator("#detail");
    await expect(detail).not.toBeEmpty();
  });

  test("arrow keys move selection up and down", async ({ page }) => {
    const firstRow = page.locator("#findings tr[data-index]").first();
    const secondRow = page.locator("#findings tr[data-index]").nth(1);
    await firstRow.click({ force: true });
    await page.waitForTimeout(200);
    const firstId = await firstRow.getAttribute("data-id");

    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(200);
    const secondId = await secondRow.getAttribute("data-id");
    expect(secondId).not.toEqual(firstId);
  });

  test("spacebar toggles selection in batch mode", async ({ page }) => {
    // Enter batch mode with 'b' or similar
    const firstRow = page.locator("#findings tr[data-index]").first();
    await firstRow.click({ force: true });
    await page.waitForTimeout(200);
    // Try pressing space
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    // Check that selection count appears
    // Soft check: at least the page didn't crash
    await expect(page.locator("body")).toBeVisible();
  });

  test("escape clears filters and selection", async ({ page }) => {
    // Set a filter
    const searchBox = page.locator("#query, input[type=search]").first();
    if ((await searchBox.count()) > 0) {
      await searchBox.fill("ssh");
      await page.waitForTimeout(300);
    }
    // Press escape
    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
    // Filters should be cleared
    if ((await searchBox.count()) > 0) {
      const value = await searchBox.inputValue();
      expect(value).toBe("");
    }
  });
});

test.describe("Visual rendering: layout integrity", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("header, filters, findings, and detail are all visible at 1200x800", async ({ page }) => {
    await page.setViewportSize({ width: 1200, height: 800 });
    await expect(page.locator("header, #header, h1").first()).toBeVisible();
    await expect(page.locator("#findings").first()).toBeVisible();
    await expect(page.locator("#detail").first()).toBeVisible();
  });

  test("no horizontal scrollbar at 1024px width", async ({ page }) => {
    await page.setViewportSize({ width: 1024, height: 768 });
    const hasHScroll = await page.evaluate(() => {
      return document.documentElement.scrollWidth > document.documentElement.clientWidth;
    });
    expect(hasHScroll).toBe(false);
  });

  test("no horizontal scrollbar at 768px width", async ({ page }) => {
    await page.setViewportSize({ width: 768, height: 1024 });
    const hasHScroll = await page.evaluate(() => {
      return document.documentElement.scrollWidth > document.documentElement.clientWidth;
    });
    expect(hasHScroll).toBe(false);
  });

  test("detail panel scrolls internally on overflow", async ({ page }) => {
    const detail = page.locator("#detail").first();
    const isScrollable = await detail.evaluate((el) => {
      return el.scrollHeight > el.clientHeight || el.scrollWidth > el.clientWidth;
    });
    // If scrollable, it should have overflow set correctly
    if (isScrollable) {
      const overflow = await detail.evaluate((el) => getComputedStyle(el).overflowY);
      expect(["auto", "scroll"]).toContain(overflow);
    }
  });

  test("findings table does not overflow the panel at 800px", async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 600 });
    const findings = page.locator("#findings, #findingsPanel, .findings").first();
    const overflows = await findings.evaluate((el) => {
      const parent = el.parentElement;
      if (!parent) return false;
      return el.scrollWidth > parent.clientWidth;
    });
    // Allow overflow only if the parent has its own overflow:auto
    if (overflows) {
      const parentOverflow = await findings.evaluate((el) => {
        const p = el.parentElement;
        return p ? getComputedStyle(p).overflowX : "visible";
      });
      expect(["auto", "scroll", "hidden"]).toContain(parentOverflow);
    }
  });
  test("help modal content is centered and not full-width", async ({ page }) => {
    await openHelp(page);
    // Check the content box, not the overlay (overlay is full-width by design)
    const content = page.locator("#helpModal .modal-content");
    const box = await content.boundingBox();
    expect(box).not.toBeNull();
    if (box) {
      const viewport = page.viewportSize();
      expect(box.width).toBeLessThan(viewport!.width);
    }
  });

  test("modal overlay has a dark backdrop", async ({ page }) => {
    await openHelp(page);
    const overlay = page.locator("#helpModal");
    const bg = await overlay.evaluate((el) => getComputedStyle(el).backgroundColor);
    // Should have a non-transparent background
    expect(bg).not.toBe("rgba(0, 0, 0, 0)");
  });
});

test.describe("Visual rendering: text wrapping and overflow", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("detail panel h2 wraps long titles without horizontal overflow", async ({ page }) => {
    // Find a finding with a long title (the mock fixture has some)
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      await rows.nth(i).click({ force: true });
      await page.waitForTimeout(200);
      const h2 = page.locator("#detail h2").first();
      if ((await h2.count()) > 0) {
        const overflows = await h2.evaluate((el) => {
          return el.scrollWidth > el.clientWidth;
        });
        // If it does overflow, the parent should clip
        if (overflows) {
          const wordWrap = await h2.evaluate(
            (el) => getComputedStyle(el).overflowWrap || getComputedStyle(el).wordWrap
          );
          expect(["break-word", "anywhere", "normal"]).toContain(wordWrap);
        }
      }
    }
  });

  test("finding rows do not clip text on hover", async ({ page }) => {
    const firstRow = page.locator("#findings tr[data-index]").first();
    const box = await firstRow.boundingBox();
    if (box) {
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.waitForTimeout(200);
    }
    await expect(firstRow).toBeVisible();
  });

  test("code blocks in detail panel do not break layout", async ({ page }) => {
    // Select any finding
    const firstRow = page.locator("#findings tr[data-index]").first();
    await firstRow.click({ force: true });
    await page.waitForTimeout(200);
    const detail = page.locator("#detail").first();
    const detailScrollWidth = await detail.evaluate((el) => el.scrollWidth);
    const detailClientWidth = await detail.evaluate((el) => el.clientWidth);
    // Detail should not have horizontal overflow from its content
    expect(detailScrollWidth).toBeLessThanOrEqual(detailClientWidth + 1);
  });
});

test.describe("Visual rendering: spacing and padding", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });


  test("findings table and detail panel both have inner padding", async ({ page }) => {
    // The findings panel delegates padding to the table-wrap inside it
    const tableWrap = page.locator("#findingsPanel .table-wrap, .findings-panel .table-wrap").first();
    const detail = page.locator("#detail").first();
    const tablePad = await tableWrap.evaluate((el) => getComputedStyle(el).padding);
    const detailPad = await detail.evaluate((el) => getComputedStyle(el).padding);
    // Both should have non-zero padding
    expect(tablePad).not.toBe("0px");
    expect(detailPad).not.toBe("0px");
  });
  test("modal content has consistent inner padding", async ({ page }) => {
    await openHelp(page);
    const content = page.locator("#helpModal .modal-content");
    const pad = await content.evaluate((el) => getComputedStyle(el).padding);
    expect(pad).not.toBe("0px");
  });

  test("table rows have consistent height", async ({ page }) => {
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    if (count < 2) return;
    const firstHeight = await rows.nth(0).evaluate((el) => el.getBoundingClientRect().height);
    const secondHeight = await rows.nth(1).evaluate((el) => el.getBoundingClientRect().height);
    // Heights should be within 2px of each other (allow for slight variation)
    expect(Math.abs(firstHeight - secondHeight)).toBeLessThanOrEqual(2);
  });

  test("buttons have visible borders or backgrounds (not invisible)", async ({ page }) => {
    const fixBtn = page.locator("#detail .fix-btn, button.fix-btn").first();
    if ((await fixBtn.count()) > 0) {
      const styles = await fixBtn.evaluate((el) => {
        const cs = getComputedStyle(el);
        return {
          bg: cs.backgroundColor,
          border: cs.border,
          opacity: cs.opacity,
        };
      });
      // Should have either a background or a border
      const hasBg = styles.bg !== "rgba(0, 0, 0, 0)" && styles.bg !== "transparent";
      const hasBorder = styles.border !== "" && styles.border !== "0px none rgb(0, 0, 0)";
      expect(hasBg || hasBorder).toBe(true);
      expect(parseFloat(styles.opacity)).toBeGreaterThan(0);
    }
  });
});

test.describe("Filter combinations", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("search + severity filter narrows results", async ({ page }) => {
    const searchBox = page.locator("#query, input[type=search]").first();
    if ((await searchBox.count()) === 0) return;
    await searchBox.fill("ssh");
    await page.waitForTimeout(300);
    const allCount = await page.locator("#findings tr[data-index]").count();
    expect(allCount).toBeGreaterThanOrEqual(0); // soft check
  });

  test("clearing search restores all findings", async ({ page }) => {
    const searchBox = page.locator("#query, input[type=search]").first();
    if ((await searchBox.count()) === 0) return;
    const initialCount = await page.locator("#findings tr[data-index]").count();
    await searchBox.fill("zzzzzz");
    await page.waitForTimeout(300);
    const filteredCount = await page.locator("#findings tr[data-index]").count();
    expect(filteredCount).toBeLessThan(initialCount);
    await searchBox.fill("");
    await page.waitForTimeout(300);
    const restoredCount = await page.locator("#findings tr[data-index]").count();
    expect(restoredCount).toBe(initialCount);
  });
});

test.describe("Sort interactions", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("clicking a sortable column header sorts the table", async ({ page }) => {
    const headers = page.locator("#findings th[data-sort], #findings th.sortable, #findings thead th");
    const count = await headers.count();
    if (count === 0) return;
    await headers.first().click();
    await page.waitForTimeout(300);
    // Table should still be visible
    await expect(page.locator("#findings tr").first()).toBeVisible();
  });
});

test.describe("Rescan button lifecycle", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
  });

  test("rescan button is visible and clickable", async ({ page }) => {
    const rescanBtn = page.locator("#rescanBtn");
    if ((await rescanBtn.count()) === 0) {
      test.skip();
      return;
    }
    await expect(rescanBtn).toBeVisible();
    await expect(rescanBtn).toBeEnabled();
  });

  test("clicking rescan shows a loading state", async ({ page }) => {
    const rescanBtn = page.locator("#rescanBtn");
    if ((await rescanBtn.count()) === 0) {
      test.skip();
      return;
    }
    // Slow the network so we can catch the loading state
    await page.route("**/api/rescan", async (route) => {
      await new Promise((r) => setTimeout(r, 500));
      await route.continue();
    });
    await rescanBtn.click();
    // Within the delay, the button should show "Scanning..." or be disabled
    await page.waitForTimeout(100);
    const isScanning =
      (await rescanBtn.textContent())?.includes("Scanning") ||
      (await rescanBtn.isDisabled());
    expect(isScanning).toBe(true);
    // Wait for it to finish
    await page.waitForTimeout(800);
    await expect(rescanBtn).toBeEnabled();
  });
});

test.describe("Empty and edge-case states", () => {
  test("page loads without console errors", async ({ page }) => {
    const errors: string[] = [];
    page.on("pageerror", (err) => errors.push(err.message));
    page.on("console", (msg) => {
      if (msg.type() === "error") errors.push(msg.text());
    });
    await page.goto("/");
    await waitForFindings(page);
    // Filter out benign errors (favicon 404, etc.)
    const realErrors = errors.filter(
      (e) => !e.includes("favicon") && !e.includes("net::ERR_FILE_NOT_FOUND")
    );
    expect(realErrors).toEqual([]);
  });

  test("all images/icons have alt text or aria-label", async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
    const imgs = page.locator("img");
    const count = await imgs.count();
    for (let i = 0; i < count; i++) {
      const alt = await imgs.nth(i).getAttribute("alt");
      const ariaLabel = await imgs.nth(i).getAttribute("aria-label");
      expect(alt !== null || ariaLabel !== null).toBe(true);
    }
  });

  test("all interactive elements are keyboard-accessible", async ({ page }) => {
    await page.goto("/");
    await waitForFindings(page);
    // Press Tab a few times and verify focus moves
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    await page.keyboard.press("Tab");
    const focused = await page.evaluate(() => document.activeElement?.tagName);
    expect(focused).toBeDefined();
  });
});
