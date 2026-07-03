import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("CSV export download", () => {
  test("CSV export button triggers download", async ({ page }) => {
    await waitForReady(page);
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportCsv").click(),
    ]);

    const suggestedFilename = download.suggestedFilename();
    expect(suggestedFilename).toMatch(/\.csv$/);
  });
});

test.describe("AI brief export download", () => {
  test("AI brief export button triggers download", async ({ page }) => {
    await waitForReady(page);
    await page.locator("#exportBtn").click();
    await expect(page.locator("#exportModal")).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      page.locator("#exportAi").click(),
    ]);

    const suggestedFilename = download.suggestedFilename();
    expect(suggestedFilename).toMatch(/\.(md|txt)$/);
  });
});

test.describe("Column header sort by clicking", () => {
  test.beforeEach(async ({ page }) => {
    await waitForReady(page);
  });

  test("clicking source column sorts by source", async ({ page }) => {
    const srcHeader = page.locator("th.sortable[data-col='2']");
    await srcHeader.click();
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("source");
  });

  test("clicking title column sorts by title", async ({ page }) => {
    const titleHeader = page.locator("th.sortable[data-col='4']");
    await titleHeader.click();
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("title");
  });

  test("clicking fix column sorts by remediation", async ({ page }) => {
    const fixHeader = page.locator("th.sortable[data-col='5']");
    await fixHeader.click();
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("remediation");
  });
});

test.describe("Sort dropdown syncs with keyboard sort", () => {
  test("o key updates the sort dropdown value", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    const initial = await sortBy.inputValue();

    await page.keyboard.press("o");
    await page.waitForTimeout(200);

    const next = await sortBy.inputValue();
    expect(next).not.toBe(initial);
  });

  test("sort dropdown value matches keyboard state after multiple presses", async ({
    page,
  }) => {
    await waitForReady(page);
    await page.keyboard.press("o");
    await page.keyboard.press("o");
    await page.waitForTimeout(200);

    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    // After 2 presses from severity, should be on "title"
    expect(value).toBe("title");
  });
});

test.describe("Tab key navigation", () => {
  test("Tab moves focus through interactive elements", async ({ page }) => {
    await waitForReady(page);

    // Tab from body should focus the search input
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);

    const focused = await page.evaluate(() => {
      return document.activeElement?.id || "";
    });
    // Should focus on query, selectAllCheck, or another interactive element
    expect(focused).toBeTruthy();
  });
});

test.describe("Detail panel for findings with different evidence sizes", () => {
  test("finding with many evidence keys shows count", async ({ page }) => {
    await waitForReady(page);
    // trivy.cve-2024-0001 has 3 evidence keys
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const evidence = page.locator("#detail .evidence-details summary").first();
    await expect(evidence).toBeVisible();
    const text = await evidence.textContent();
    expect(text).toContain("3");
  });

  test("finding with fewer evidence keys shows correct count", async ({
    page,
  }) => {
    await waitForReady(page);
    // lynis.KRNL-5780 has 3 evidence keys
    const row = page.locator(
      "#findings tr[data-id='lynis.KRNL-5780']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const evidence = page.locator("#detail .evidence-details summary");
    await expect(evidence).toBeVisible();
    const text = await evidence.textContent();
    expect(text).toContain("3");
  });
});

test.describe("Score breakdown penalty display", () => {
  test("each axis shows penalty ratio text", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();

    for (let i = 0; i < count; i++) {
      const meta = axes.nth(i).locator(".score-axis-meta span").first();
      const text = await meta.textContent();
      // Should match pattern like "X/Y penalty cap used"
      expect(text).toMatch(/\d+\/\d+ penalty cap used/);
    }
  });

  test("each axis shows severity count summary", async ({ page }) => {
    await waitForReady(page);
    const counts = page.locator(
      "#scoreBreakdown .score-axis-counts"
    );
    const count = await counts.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const text = await counts.nth(i).textContent();
      // Should contain at least one severity letter (C, H, M, L) or "No active"
      expect(text).toMatch(/\d[CHML]|No active/);
    }
  });
});

test.describe("Score plate class reflects score", () => {
  test("score element has severity class matching score value", async ({
    page,
  }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    const text = await score.textContent();
    const match = text?.match(/^(\d+)\//);
    expect(match).toBeTruthy();
    if (match) {
      const scoreVal = parseInt(match[1]);
      const className = await score.getAttribute("class");
      // Score class should be low/medium/high/critical based on value
      if (scoreVal >= 85) {
        expect(className).toBe("low");
      } else if (scoreVal >= 65) {
        expect(className).toBe("medium");
      } else if (scoreVal >= 40) {
        expect(className).toBe("high");
      } else {
        expect(className).toBe("critical");
      }
    }
  });
});

test.describe("Row double-click toggles selection", () => {
  test("double-click on a selectable row toggles its selection", async ({
    page,
  }) => {
    await waitForReady(page);

    // Find a selectable row
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.dblclick({ force: true });
    await page.waitForTimeout(300);

    // Should be selected now
    const isSelected = await row.evaluate((el) =>
      el.classList.contains("row-selected")
    );
    expect(isSelected).toBe(true);

    // Double-click again to deselect
    await row.dblclick({ force: true });
    await page.waitForTimeout(300);

    const isDeselected = await row.evaluate((el) =>
      !el.classList.contains("row-selected")
    );
    expect(isDeselected).toBe(true);
  });
});

test.describe("Checkbox click on individual row", () => {
  test("clicking row checkbox toggles selection independently", async ({
    page,
  }) => {
    await waitForReady(page);

    const checkbox = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001'] .row-check"
    );
    await checkbox.click({ force: true });
    await page.waitForTimeout(300);

    const isChecked = await checkbox.isChecked();
    expect(isChecked).toBe(true);

    // Click again to uncheck
    await checkbox.click({ force: true });
    await page.waitForTimeout(300);

    const isUnchecked = await checkbox.isChecked();
    expect(isUnchecked).toBe(false);
  });
});

test.describe("Unfixed finding Fix button behavior", () => {
  test("auto finding shows Fix button in detail panel", async ({ page }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible();
    const text = await fixBtn.textContent();
    expect(text).toBe("Fix");
  });

  test("review finding shows Fix button in detail panel", async ({ page }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible();
    const text = await fixBtn.textContent();
    expect(text).toBe("Fix");
  });
});

test.describe("Filtering updates finding count", () => {
  test("finding count text updates when source filter applied", async ({
    page,
  }) => {
    await waitForReady(page);

    const countEl = page.locator("#findingCount");
    let text = await countEl.textContent();
    expect(text).toContain("14");

    // Apply source filter
    const trivyChip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" });
    await trivyChip.click();
    await page.waitForTimeout(200);

    text = await countEl.textContent();
    expect(text).not.toContain("14");
    expect(text).toContain("visible");
  });

  test("finding count updates when service filter applied", async ({
    page,
  }) => {
    await waitForReady(page);

    // Use keyboard to cycle service filter
    await page.keyboard.press("v");
    await page.waitForTimeout(200);

    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    expect(text).toContain("visible");
    // Should have fewer than 14
    expect(text).not.toBe("14 visible");
  });
});

test.describe("Sort by severity ordering", () => {
  test("default sort puts critical findings first", async ({ page }) => {
    await waitForReady(page);

    // Default sort is severity asc — check first few rows
    const rows = page.locator("#findings tr[data-index]");
    const firstBadge = rows.first().locator(".badge");
    const text = await firstBadge.textContent();
    expect(text).toContain("critical");
  });

  test("reversed severity sort puts low findings first", async ({ page }) => {
    await waitForReady(page);

    // Toggle sort direction
    await page.keyboard.press("O");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const firstBadge = rows.first().locator(".badge");
    const text = await firstBadge.textContent();
    expect(text).toContain("low");
  });
});

test.describe("Sort by title ordering", () => {
  test("title sort orders findings alphabetically", async ({ page }) => {
    await waitForReady(page);

    // Switch to title sort
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("title");
    await page.waitForTimeout(200);

    // Collect first few titles
    const rows = page.locator("#findings tr[data-index] .title");
    const titles: string[] = [];
    const count = Math.min(5, await rows.count());
    for (let i = 0; i < count; i++) {
      titles.push((await rows.nth(i).textContent()) ?? "");
    }

    // Should be in alphabetical order
    for (let i = 1; i < titles.length; i++) {
      expect(titles[i].localeCompare(titles[i - 1])).toBeGreaterThanOrEqual(0);
    }
  });
});

test.describe("Sort by source ordering", () => {
  test("source sort groups findings by source", async ({ page }) => {
    await waitForReady(page);

    // Switch to source sort
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("source");
    await page.waitForTimeout(200);

    // All compose findings should be grouped together
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    let foundCompose = false;
    let composeEnded = false;
    for (let i = 0; i < count; i++) {
      const id = await rows.nth(i).getAttribute("data-id");
      if (id?.startsWith("compose.")) {
        foundCompose = true;
      } else if (foundCompose && !id?.startsWith("compose.")) {
        composeEnded = true;
      }
    }
    // If we found compose findings, they should be contiguous
    if (foundCompose && composeEnded) {
      // Check all compose findings are together
      let inComposeGroup = false;
      let leftGroup = false;
      for (let i = 0; i < count; i++) {
        const id = await rows.nth(i).getAttribute("data-id");
        const isCompose = id?.startsWith("compose.");
        if (isCompose) {
          inComposeGroup = true;
          expect(leftGroup).toBe(false);
        } else if (inComposeGroup) {
          leftGroup = true;
        }
      }
    }
  });
});

test.describe("Evidence key ordering", () => {
  test("evidence keys are displayed in alphabetical order", async ({
    page,
  }) => {
    await waitForReady(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    // Evidence has keys: cve_url, fixed_version, pkg_name (alphabetical)
    // Scope to first evidence-details section (second is metadata)
    const evidenceSection = page.locator("#detail .evidence-details").first();
    const evidencePre = evidenceSection.locator("pre strong");
    const count = await evidencePre.count();
    expect(count).toBe(3);

    const keys: string[] = [];
    for (let i = 0; i < count; i++) {
      keys.push((await evidencePre.nth(i).textContent()) ?? "");
    }

    // Should be alphabetical
    for (let i = 1; i < keys.length; i++) {
      expect(keys[i].localeCompare(keys[i - 1])).toBeGreaterThanOrEqual(0);
    }
  });
});

test.describe("Score breakdown axis labels", () => {
  test("all four axes have correct labels", async ({ page }) => {
    await waitForReady(page);

    const axes = page.locator("#scoreBreakdown .score-axis");
    const labels = page.locator("#scoreBreakdown .score-axis-top span");
    const count = await labels.count();
    expect(count).toBe(4);

    const labelTexts: string[] = [];
    for (let i = 0; i < count; i++) {
      labelTexts.push((await labels.nth(i).textContent()) ?? "");
    }

    expect(labelTexts).toContain("Vulnerabilities");
    expect(labelTexts).toContain("Container exposure");
    expect(labelTexts).toContain("Host hardening");
    expect(labelTexts).toContain("Secrets");
  });
});
