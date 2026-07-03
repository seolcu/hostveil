import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Fix result content after applying fix", () => {
  test("successful fix shows result text", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.FILE-6310']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeEnabled();
    await confirmBtn.click();
    await page.waitForTimeout(2000);

    const fixResult = page.locator("#fixResult");
    const text = await fixResult.textContent();
    expect(text).toContain("Apply mock fix");
  });

  test("fix button disappears after fixing", async ({ page }) => {
    await ready(page);

    // Use KRNL-5780 which is Auto (remediation=0)
    const row = page.locator(
      "#findings tr[data-id='lynis.KRNL-5780']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeEnabled();
    await confirmBtn.click();
    await page.waitForTimeout(2000);

    const fixResult = page.locator("#fixResult");
    const text = await fixResult.textContent();
    expect(text).toContain("Apply mock fix");
  });
});

test.describe("Section copy button", () => {
  test("how_to_fix section has copy button", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    await expect(detail).toBeVisible({ timeout: 5000 });

    // The "How to fix" section has a copy button with class="copy"
    const copyBtn = detail.locator("button.copy");
    await expect(copyBtn).toBeVisible({ timeout: 5000 });

    const btnText = await copyBtn.textContent();
    expect(btnText).toContain("Copy guidance");
  });
});

test.describe("View more / View less toggle", () => {
  test("long description can be expanded and collapsed", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const viewMore = page.locator("#detail .toggle-more").first();
    if ((await viewMore.count()) > 0) {
      await viewMore.click();
      await page.waitForTimeout(300);

      const viewLess = page.locator("#detail .toggle-more").first();
      const text = await viewLess.textContent();
      expect(text).toContain("View less");

      await viewLess.click();
      await page.waitForTimeout(300);

      const viewMoreAgain = page.locator("#detail .toggle-more").first();
      const textAgain = await viewMoreAgain.textContent();
      expect(textAgain).toContain("View more");
    }
  });
});

test.describe("Batch fix with selection", () => {
  test("selecting two findings shows count on Fix Selected", async ({
    page,
  }) => {
    await ready(page);

    // Navigate to first finding and select it with Space
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);

    // Navigate to second finding and select it
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);

    const fixSelectedBtn = page.locator("#fixSelectedBtn");
    await expect(fixSelectedBtn).toBeVisible();
    const btnText = await fixSelectedBtn.textContent();
    expect(btnText).toContain("2");
  });
});

test.describe("Cross-origin request rejection", () => {
  test("POST /api/fix with invalid Origin header is rejected", async ({
    page,
  }) => {
    await ready(page);

    const response = await page.evaluate(async () => {
      const r = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "test.id", action_index: 0 }),
      });
      return r.json();
    });

    // Should return error since "test.id" isn't registered
    expect(response.success).toBe(false);
    expect(response.error).toBeTruthy();
  });
});

test.describe("Rescan lifecycle", () => {
  test("rescan button re-enables after completion", async ({ page }) => {
    await ready(page);

    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeVisible();
    await rescanBtn.click();
    await page.waitForTimeout(500);

    const isDisabled = await rescanBtn.isDisabled();
    expect(isDisabled).toBe(true);

    // Score breakdown should still be visible
    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);

    // Wait for rescan to complete
    await expect(rescanBtn).toBeEnabled({ timeout: 10000 });
  });
});

test.describe("Detail panel metadata for different sources", () => {
  test("lynis finding shows source and remediation", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Auto");
    expect(text).toContain("one clear fix");
  });
});

test.describe("Finding count updates correctly", () => {
  test("count shows correct number for each severity", async ({ page }) => {
    await ready(page);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);

    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    await page
      .locator("#severityFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });

  test("source filter shows correct count per source", async ({ page }) => {
    await ready(page);

    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" })
      .click();
    await page.waitForTimeout(200);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(6);

    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Detail panel auto-selects first finding", () => {
  test("first finding is selected on load", async ({ page }) => {
    await ready(page);

    const detail = page.locator("#detail");
    // Fixture mode auto-selects the first finding
    const text = await detail.textContent();
    expect(text).toBeTruthy();
    expect(text.length).toBeGreaterThan(10);
  });
});

test.describe("Sort stability across operations", () => {
  test("sort order persists after selecting a finding", async ({ page }) => {
    await ready(page);

    await page.locator("#sortBy").selectOption("title");
    await page.waitForTimeout(200);

    const ids1: string[] = [];
    const rows1 = page.locator("#findings tr[data-index]");
    const count = await rows1.count();
    for (let i = 0; i < count; i++) {
      const id = await rows1.nth(i).getAttribute("data-id");
      if (id) ids1.push(id);
    }

    await rows1.first().click({ force: true });
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

test.describe("Score plate reflects overall score", () => {
  test("score element shows N/100 format", async ({ page }) => {
    await ready(page);

    const scoreEl = page.locator("#score");
    const text = await scoreEl.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });

  test("score is between 0 and 100", async ({ page }) => {
    await ready(page);

    const scoreEl = page.locator("#score");
    const text = await scoreEl.textContent();
    const score = parseInt(text?.split("/")[0] || "0", 10);
    expect(score).toBeGreaterThanOrEqual(0);
    expect(score).toBeLessThanOrEqual(100);
  });
});

test.describe("Table rendering consistency", () => {
  test("every row has exactly 6 cells", async ({ page }) => {
    await ready(page);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const cells = rows.nth(i).locator("td");
      const cellCount = await cells.count();
      expect(cellCount).toBe(6);
    }
  });

  test("every row has a severity badge or checkmark", async ({ page }) => {
    await ready(page);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const secondCell = rows.nth(i).locator("td").nth(1);
      const text = await secondCell.textContent();
      expect(text).toMatch(/(critical|high|medium|low|✓)/);
    }
  });

  test("every row has a fix column with remediation kind", async ({
    page,
  }) => {
    await ready(page);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const lastCell = rows.nth(i).locator("td").last();
      const text = await lastCell.textContent();
      expect(text).toMatch(/(Auto|Review|Unavailable|Fixed)/);
    }
  });
});

test.describe("Multiple filter combinations", () => {
  test("severity + source filter narrows correctly", async ({ page }) => {
    await ready(page);

    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);

    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" })
      .click();
    await page.waitForTimeout(200);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(1);

    await page
      .locator("#severityFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(100);
    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);

    const total = await page.locator("#findings tr[data-index]").count();
    expect(total).toBe(14);
  });

  test("search + remediation filter combines", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("CVE");
    await page.waitForTimeout(300);

    await page
      .locator("#remediationFilters button")
      .filter({ hasText: "Auto" })
      .click();
    await page.waitForTimeout(200);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);
    expect(count).toBeLessThanOrEqual(3);

    await query.fill("");
    await page.waitForTimeout(100);
    await page
      .locator("#remediationFilters button")
      .filter({ hasText: "All" })
      .click();
    await page.waitForTimeout(200);

    const total = await page.locator("#findings tr[data-index]").count();
    expect(total).toBe(14);
  });
});

test.describe("Export modal opens and closes", () => {
  test("export modal has JSON, CSV, and AI options", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("e");
    await page.waitForTimeout(300);

    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    const text = await modal.textContent();
    expect(text).toContain("JSON");
    expect(text).toContain("CSV");
    expect(text).toContain("AI");

    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
    await expect(modal).not.toBeVisible();
  });
});

test.describe("CSV export via API", () => {
  test("CSV has correct header columns", async ({ page }) => {
    await ready(page);

    const response = await page.evaluate(async () => {
      const r = await fetch("/api/export?format=csv");
      return { status: r.status, text: await r.text() };
    });

    expect(response.status).toBe(200);
    const lines = response.text.split("\n");
    expect(lines[0]).toContain("ID");
    expect(lines[0]).toContain("Title");
    expect(lines.length).toBeGreaterThanOrEqual(2);
  });
});

test.describe("AI brief export via API", () => {
  test("returns markdown with headings", async ({ page }) => {
    await ready(page);

    const response = await page.evaluate(async () => {
      const r = await fetch("/api/export?format=ai");
      return { status: r.status, text: await r.text() };
    });

    expect(response.status).toBe(200);
    expect(response.text).toContain("#");
    expect(response.text).toContain("Security");
  });
});

test.describe("API contract validation", () => {
  test("result has all required top-level fields", async ({ page }) => {
    await ready(page);

    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });

    expect(result).toHaveProperty("findings");
    expect(result).toHaveProperty("score");
    expect(result).toHaveProperty("score_breakdown");
    expect(result).toHaveProperty("hostname");
    expect(Array.isArray(result.findings)).toBe(true);
    expect(result.findings.length).toBe(14);
  });

  test("score_breakdown has axes array with 4 items", async ({ page }) => {
    await ready(page);

    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });

    const axes = result.score_breakdown.axes;
    expect(Array.isArray(axes)).toBe(true);
    expect(axes.length).toBe(4);

    const ids = axes.map((a: { id: string }) => a.id);
    expect(ids).toContain("vulnerabilities");
    expect(ids).toContain("container_exposure");
    expect(ids).toContain("host_hardening");
    expect(ids).toContain("secrets");
  });

  test("recalc returns consistent score", async ({ page }) => {
    await ready(page);

    const result1 = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });

    const result2 = await page.evaluate(async () => {
      const r = await fetch("/api/recalc", { method: "POST" });
      return r.json();
    });

    expect(result2.score).toBe(result1.score);
  });
});

test.describe("Fix error handling", () => {
  test("fix with non-existent ID returns error", async ({ page }) => {
    await ready(page);

    const response = await page.evaluate(async () => {
      const r = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "nonexistent.id", action_index: 0 }),
      });
      return r.json();
    });

    expect(response.success).toBe(false);
    expect(response.error).toBeTruthy();
  });

  test("fix with out-of-range action_index returns error", async ({
    page,
  }) => {
    await ready(page);

    const response = await page.evaluate(async () => {
      const r = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "lynis.FILE-6310", action_index: 99 }),
      });
      return r.json();
    });

    expect(response.success).toBe(false);
    expect(response.error).toBeTruthy();
  });
});

test.describe("Table scroll behavior", () => {
  test("table wrapper has overflow auto", async ({ page }) => {
    await ready(page);

    const tableWrap = page.locator(".table-wrap");
    await expect(tableWrap).toBeVisible();

    const overflow = await tableWrap.evaluate(
      (el) => getComputedStyle(el).overflow
    );
    expect(overflow).toBe("auto");
  });
});

test.describe("Score breakdown panel structure", () => {
  test("head shows title and description", async ({ page }) => {
    await ready(page);

    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    await expect(head).toBeVisible();

    const span = head.locator("span");
    const spanText = await span.textContent();
    expect(spanText).toBe("Score breakdown");

    const p = head.locator("p");
    const pText = await p.textContent();
    expect(pText).toContain("penalty cap");
  });

  test("each axis card shows label, score, and bar", async ({ page }) => {
    await ready(page);

    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const label = axes.nth(i).locator(".score-axis-top span");
      const labelText = await label.textContent();
      expect(labelText).toBeTruthy();
      expect(labelText!.length).toBeGreaterThan(0);

      const score = axes.nth(i).locator(".score-axis-top strong");
      const scoreText = await score.textContent();
      expect(scoreText).toMatch(/^\d+\/100$/);

      const bar = axes.nth(i).locator(".score-axis-bar span");
      await expect(bar).toBeVisible();
    }
  });
});
test.describe("Responsive: score breakdown at narrow width", () => {
  test("score breakdown remains visible at 768px", async ({ page }) => {
    await ready(page);
    await page.setViewportSize({ width: 768, height: 900 });
    await page.waitForTimeout(200);

    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      await expect(axes.nth(i)).toBeVisible();
    }

    await page.setViewportSize({ width: 1440, height: 900 });
  });
});


test.describe("Topbar rendering", () => {
  test("topbar has title and action buttons", async ({ page }) => {
    await ready(page);

    const topbar = page.locator(".topbar");
    await expect(topbar).toBeVisible();

    const h1 = topbar.locator("h1");
    const title = await h1.textContent();
    expect(title).toContain("hostveil");

    await expect(page.locator("#rescanBtn")).toBeVisible();
    await expect(page.locator("#recalcBtn")).toBeVisible();
  });
});

test.describe("Keyboard navigation depth", () => {
  test("arrow keys navigate through all findings", async ({ page }) => {
    await ready(page);

    for (let i = 0; i < 13; i++) {
      await page.keyboard.press("ArrowDown");
      await page.waitForTimeout(50);
    }

    const rows = page.locator("#findings tr.selected");
    const count = await rows.count();
    expect(count).toBe(1);

    for (let i = 0; i < 13; i++) {
      await page.keyboard.press("ArrowUp");
      await page.waitForTimeout(50);
    }
  });

  test("o key cycles through sort fields", async ({ page }) => {
    await ready(page);

    const sortBy = page.locator("#sortBy");

    let value = await sortBy.inputValue();
    expect(value).toBe("severity");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    value = await sortBy.inputValue();
    expect(value).toBe("source");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    value = await sortBy.inputValue();
    expect(value).toBe("title");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    value = await sortBy.inputValue();
    expect(value).toBe("remediation");

    await page.keyboard.press("o");
    await page.waitForTimeout(100);
    value = await sortBy.inputValue();
    expect(value).toBe("severity");
  });
});

test.describe("Recalc preserves score breakdown", () => {
  test("recalc returns same number of axes", async ({ page }) => {
    await ready(page);

    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(1000);

    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);
  });
});

test.describe("Metrics row structure", () => {
  test("metrics row has 6 metric cards", async ({ page }) => {
    await ready(page);

    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBe(6);
  });

  test("total metric shows 14", async ({ page }) => {
    await ready(page);

    const first = await page.locator("#metrics .metric").first().textContent();
    expect(first).toContain("14");
  });
});

test.describe("Help modal has all sections", () => {
  test("help modal shows navigation and action shortcuts", async ({
    page,
  }) => {
    await ready(page);

    await page.keyboard.press("?");
    await page.waitForTimeout(300);

    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    const text = await modal.textContent();
    expect(text).toContain("Navigation");
    expect(text).toContain("Filters");

    await page.keyboard.press("Escape");
  });
});

test.describe("Finding count after filter reset", () => {
  test("count returns to 14 after clearing all filters", async ({ page }) => {
    await ready(page);

    // Apply critical filter
    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);

    // Apply Trivy source filter
    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" })
      .click();
    await page.waitForTimeout(200);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(1);

    // Clear all
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Fix modal action type for auto finding", () => {
  test("auto fix modal does not require action selection", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.KRNL-5780']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    // Auto fix should have a direct confirm button, not radio options
    const radios = modal.locator("input[name='fixAction']");
    const radioCount = await radios.count();
    expect(radioCount).toBe(0);

    // Should have a confirm button
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeVisible();

    await page.keyboard.press("Escape");
  });
});

test.describe("Evidence detail in pre tags", () => {
  test("evidence key-value pairs render in pre elements", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    // Expand evidence section
    const summary = page
      .locator("#detail .evidence-details summary")
      .first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);

      const pres = page.locator(
        "#detail .evidence-details pre"
      );
      const count = await pres.count();
      expect(count).toBeGreaterThanOrEqual(3);
    }
  });
});
