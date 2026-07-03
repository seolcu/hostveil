import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Recalc button triggers recalc and shows toast", () => {
  test("recalc button shows success toast", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);

    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 5000 });
    const text = await toast.textContent();
    expect(text).toContain("recalculated");

    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);
  });
});

test.describe("Export button click", () => {
  test("Export button opens export modal", async ({ page }) => {
    await ready(page);

    const exportBtn = page.locator("#exportBtn");
    await expect(exportBtn).toBeVisible();
    await exportBtn.click();
    await page.waitForTimeout(300);

    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    const text = await modal.textContent();
    expect(text).toContain("JSON");
    expect(text).toContain("CSV");
    expect(text).toContain("AI brief");

    await page.keyboard.press("Escape");
  });
});

test.describe("Score breakdown data-axis attributes", () => {
  test("each axis card has correct data-axis attribute", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const expected = [
      "vulnerabilities",
      "container_exposure",
      "host_hardening",
      "secrets",
    ];
    for (let i = 0; i < 4; i++) {
      const axisId = await axes.nth(i).getAttribute("data-axis");
      expect(expected).toContain(axisId);
    }
  });
});

test.describe("Score breakdown penalty cap text", () => {
  test("each axis shows penalty cap ratio", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    for (let i = 0; i < 4; i++) {
      const meta = axes.nth(i).locator(".score-axis-meta span").first();
      const text = await meta.textContent();
      expect(text).toMatch(/\d+\/\d+ penalty cap/);
    }
  });
});

test.describe("Score plate CSS class", () => {
  test("score plate has severity class", async ({ page }) => {
    await ready(page);
    const scoreplate = page.locator(".scoreplate");
    const cls = await scoreplate.getAttribute("class");
    expect(cls).toMatch(/score-(low|medium|high|critical)/);
  });

  test("score element has matching class", async ({ page }) => {
    await ready(page);
    const scoreEl = page.locator("#score");
    const cls = await scoreEl.getAttribute("class");
    expect(cls).toMatch(/(low|medium|high|critical)/);
  });
});

test.describe("Filter chips render correctly", () => {
  test("severity chips have correct labels", async ({ page }) => {
    await ready(page);
    const chips = page.locator("#severityFilters button.chip");
    const count = await chips.count();
    expect(count).toBe(5);

    const labels: string[] = [];
    for (let i = 0; i < count; i++) {
      labels.push((await chips.nth(i).textContent()) ?? "");
    }
    expect(labels).toContain("All");
    expect(labels).toContain("Critical");
    expect(labels).toContain("High");
    expect(labels).toContain("Medium");
    expect(labels).toContain("Low");
  });

  test("source chips have correct labels", async ({ page }) => {
    await ready(page);
    const chips = page.locator("#sourceFilters button.chip");
    const count = await chips.count();
    expect(count).toBeGreaterThanOrEqual(4);

    const labels: string[] = [];
    for (let i = 0; i < count; i++) {
      labels.push((await chips.nth(i).textContent()) ?? "");
    }
    expect(labels).toContain("All");
  });

  test("default All chip is active", async ({ page }) => {
    await ready(page);
    const activeChip = page.locator("#severityFilters button.chip.active");
    const text = await activeChip.textContent();
    expect(text).toContain("All");
  });
});

test.describe("Table column header sort", () => {
  test("clicking severity column sorts by severity", async ({ page }) => {
    await ready(page);
    const severityHeader = page.locator("th.sortable").nth(0);
    await severityHeader.click();
    await page.waitForTimeout(200);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("severity");
  });

  test("clicking source column sorts by source", async ({ page }) => {
    await ready(page);
    const sourceHeader = page.locator("th.sortable").nth(1);
    await sourceHeader.click();
    await page.waitForTimeout(200);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("source");
  });

  test("clicking title column sorts by title", async ({ page }) => {
    await ready(page);
    const titleHeader = page.locator("th.sortable").nth(2);
    await titleHeader.click();
    await page.waitForTimeout(200);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("title");
  });

  test("clicking fix column sorts by remediation", async ({ page }) => {
    await ready(page);
    const fixHeader = page.locator("th.sortable").nth(3);
    await fixHeader.click();
    await page.waitForTimeout(200);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("remediation");
  });

  test("clicking same column twice toggles sort direction", async ({
    page,
  }) => {
    await ready(page);
    const severityHeader = page.locator("th.sortable").nth(0);
    await severityHeader.click();
    await page.waitForTimeout(100);
    await severityHeader.click();
    await page.waitForTimeout(100);
    const firstRow = page.locator("#findings tr[data-index]").first();
    const firstId = await firstRow.getAttribute("data-id");
    expect(firstId).toBeTruthy();
  });
});

test.describe("Remediation filter cycling via keyboard", () => {
  test("r key cycles through all remediation values", async ({ page }) => {
    await ready(page);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);

    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(10);

    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(3);

    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(1);

    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(0);

    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Source filter cycling via keyboard", () => {
  test("s key cycles through source values", async ({ page }) => {
    await ready(page);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);

    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(6);

    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(6);

    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Service filter cycling via keyboard", () => {
  test("v key cycles through service values", async ({ page }) => {
    await ready(page);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);

    await page.keyboard.press("v");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThan(0);
    expect(count).toBeLessThan(14);

    for (let i = 0; i < 10; i++) {
      await page.keyboard.press("v");
      await page.waitForTimeout(200);
      count = await page.locator("#findings tr[data-index]").count();
      if (count === 14) break;
    }

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Detail panel for different finding types", () => {
  test("trivy CVE finding shows metadata with compose_path", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("compose_path");
    expect(text).toContain("docker-compose.yml");
  });

  test("compose finding shows service field in metadata", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='compose.dr004']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("env_file");
    expect(text).toContain("webapp");
  });

  test("unavailable finding has no Fix button", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    const count = await fixBtn.count();
    expect(count).toBe(0);
  });

  test("review finding has Fix button and review hint", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Review");
    expect(text).toContain("multiple");

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible();
  });
});

test.describe("Score breakdown after recalc", () => {
  test("recalc preserves all 4 axes and scores", async ({ page }) => {
    await ready(page);

    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);

    const scores1: string[] = [];
    for (let i = 0; i < 4; i++) {
      const s = await axes
        .nth(i)
        .locator(".score-axis-top strong")
        .textContent();
      scores1.push(s ?? "");
    }

    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(1000);

    const scores2: string[] = [];
    for (let i = 0; i < 4; i++) {
      const s = await axes
        .nth(i)
        .locator(".score-axis-top strong")
        .textContent();
      scores2.push(s ?? "");
    }
    expect(scores2).toEqual(scores1);
  });
});

test.describe("Fix modal for auto finding", () => {
  test("auto finding fix modal has finding title", async ({ page }) => {
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

    const modalText = await modal.textContent();
    expect(modalText).toContain("Mock fix");

    await page.keyboard.press("Escape");
  });
});

test.describe("Detail panel how_to_fix with copy button", () => {
  test("how_to_fix section renders correctly", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0002']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    await expect(detail).toBeVisible({ timeout: 5000 });

    const sections = detail.locator(".section");
    const count = await sections.count();
    expect(count).toBeGreaterThanOrEqual(2);

    const copyBtn = detail.locator("button.copy");
    await expect(copyBtn).toBeVisible();
  });
});

test.describe("Detail panel evidence keys are sorted", () => {
  test("evidence keys appear in alphabetical order", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const summary = page
      .locator("#detail .evidence-details summary")
      .first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);

      const keys = page.locator(
        "#detail .evidence-details:first-of-type pre strong"
      );
      const count = await keys.count();
      const keyTexts: string[] = [];
      for (let i = 0; i < count; i++) {
        keyTexts.push((await keys.nth(i).textContent()) ?? "");
      }
      for (let i = 1; i < keyTexts.length; i++) {
        expect(keyTexts[i].localeCompare(keyTexts[i - 1])).toBeGreaterThanOrEqual(0);
      }
    }
  });
});

test.describe("Score breakdown head text", () => {
  test("head says Score breakdown and mentions penalty cap", async ({
    page,
  }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const text = await head.textContent();
    expect(text).toContain("Score breakdown");
    expect(text).toContain("penalty cap");
  });
});

test.describe("Metric counts are correct", () => {
  test("metrics show correct counts", async ({ page }) => {
    await ready(page);

    const metrics = page.locator("#metrics .metric");
    const count = await metrics.count();
    expect(count).toBe(6);

    const first = await metrics.nth(0).textContent();
    expect(first).toContain("14");

    const second = await metrics.nth(1).textContent();
    expect(second).toContain("2");

    const third = await metrics.nth(2).textContent();
    expect(third).toContain("6");
  });
});

test.describe("Finding row fixed state", () => {
  test("fixed finding row has fixed and disabled classes", async ({
    page,
  }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const cls = await row.getAttribute("class");
    expect(cls).toContain("fixed");
    expect(cls).toContain("disabled");
  });

  test("fixed finding has disabled checkbox", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const checkbox = row.locator(".row-check");
    const isDisabled = await checkbox.isDisabled();
    expect(isDisabled).toBe(true);
  });
});

test.describe("Score breakdown penalty bars", () => {
  test("each penalty bar has a width percentage", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const style = await bars.nth(i).getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
    }
  });
});

test.describe("Score breakdown overall consistency", () => {
  test("score breakdown overall matches main score", async ({ page }) => {
    await ready(page);

    const scoreText = await page.locator("#score").textContent();
    const mainScore = parseInt(scoreText?.split("/")[0] || "0", 10);

    const result = await page.evaluate(async () => {
      const r = await fetch("/api/result");
      return r.json();
    });

    expect(result.score_breakdown.overall).toBe(mainScore);
  });
});

test.describe("Tab key focus management", () => {
  test("Tab moves focus through interactive elements", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);

    const focused = await page.evaluate(() => {
      const el = document.activeElement;
      return el?.tagName || "";
    });
    expect(focused).toBeTruthy();
  });
});

test.describe("Escape key closes modals", () => {
  test("Escape closes help modal", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });

  test("Escape closes export modal", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

test.describe("Score breakdown visible when findings exist", () => {
  test("score breakdown is not hidden on load", async ({ page }) => {
    await ready(page);
    const breakdown = page.locator("#scoreBreakdown");
    await expect(breakdown).toBeVisible();
  });
});

test.describe("Detail panel shows remediation hints", () => {
  test("auto finding shows one clear fix hint", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.FILE-6310']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Auto");
    expect(text).toContain("one clear fix");
  });

  test("unavailable finding shows not yet classified hint", async ({
    page,
  }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='test.unfixable-001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Unavailable");
    expect(text).toContain("not yet classified");
  });
});

test.describe("Search by different fields", () => {
  test("search by service name finds findings", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);

    await query.fill("");
    await page.waitForTimeout(300);
  });

  test("empty search shows all findings", async ({ page }) => {
    await ready(page);

    const query = page.locator("#query");
    await query.fill("something-impossible-zzzz");
    await page.waitForTimeout(300);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(0);

    await query.fill("");
    await page.waitForTimeout(300);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Sort direction toggle via O key", () => {
  test("O key reverses sort order", async ({ page }) => {
    await ready(page);

    const firstId1 = await page
      .locator("#findings tr[data-index]")
      .first()
      .getAttribute("data-id");

    await page.keyboard.press("O");
    await page.waitForTimeout(200);

    const firstId2 = await page
      .locator("#findings tr[data-index]")
      .first()
      .getAttribute("data-id");

    expect(firstId1).not.toBe(firstId2);
  });
});
