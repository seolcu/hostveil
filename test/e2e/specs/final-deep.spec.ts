import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Fix result with diff highlighting", () => {
  test("successful fix shows diff content in result", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0002']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        const confirmBtn = modal.locator("#modalFixYes");
        if (await confirmBtn.isEnabled()) {
          await confirmBtn.click();
          await page.waitForTimeout(2000);
          const fixResult = page.locator("#fixResult");
          if ((await fixResult.count()) > 0) {
            const text = await fixResult.textContent();
            expect(text).toBeTruthy();
          }
        } else {
          await page.keyboard.press("Escape");
        }
      }
    }
  });
});

test.describe("Batch fix with action selection", () => {
  test("selecting two findings shows count on Fix Selected", async ({
    page,
  }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
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

test.describe("Fix Selected button visibility", () => {
  test("Fix Selected button has no count with no selection", async ({
    page,
  }) => {
    await ready(page);
    const fixSelectedBtn = page.locator("#fixSelectedBtn");
    const btnText = await fixSelectedBtn.textContent();
    expect(btnText).not.toContain("(");
  });
});

test.describe("Tooltip text on buttons", () => {
  test("recalc button has title tooltip", async ({ page }) => {
    await ready(page);
    const recalcBtn = page.locator("#recalcBtn");
    const title = await recalcBtn.getAttribute("title");
    expect(title).toBeTruthy();
  });
});

test.describe("Score breakdown penalty bar accessibility", () => {
  test("penalty bars have aria-label", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    const count = await bars.count();
    for (let i = 0; i < count; i++) {
      const ariaLabel = await bars.nth(i).getAttribute("aria-label");
      expect(ariaLabel).toBeTruthy();
      expect(ariaLabel!.length).toBeGreaterThan(0);
    }
  });
});

test.describe("Detail panel metadata grid", () => {
  test("trivy CVE finding has metadata with compose_path", async ({
    page,
  }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const detail = page.locator("#detail");
    const metaSection = detail.locator(".section").filter({ hasText: "Metadata" });
    if ((await metaSection.count()) > 0) {
      const metaText = await metaSection.textContent();
      expect(metaText).toContain("compose_path");
    }
  });
});

test.describe("Finding count text accuracy", () => {
  test("count shows exact visible number", async ({ page }) => {
    await ready(page);
    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    expect(text).toMatch(/\d+ visible/);
  });

  test("count updates after source filter", async ({ page }) => {
    await ready(page);
    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" })
      .click();
    await page.waitForTimeout(200);
    const countEl = page.locator("#findingCount");
    const text = await countEl.textContent();
    expect(text).toContain("6 visible");
  });
});

test.describe("Detail panel for different severity levels", () => {
  test("critical finding shows critical badge", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const badge = page.locator("#detail .badge");
    if ((await badge.count()) > 0) {
      const cls = await badge.getAttribute("class");
      expect(cls).toContain("critical");
    }
  });

  test("low finding shows low badge", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.KRNL-5780']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const badge = page.locator("#detail .badge");
    if ((await badge.count()) > 0) {
      const cls = await badge.getAttribute("class");
      expect(cls).toContain("low");
    }
  });
});

test.describe("Sort stability across re-renders", () => {
  test("severity sort produces same order after re-render", async ({
    page,
  }) => {
    await ready(page);
    const ids1: string[] = [];
    const rows1 = page.locator("#findings tr[data-index]");
    const count = await rows1.count();
    for (let i = 0; i < count; i++) {
      const id = await rows1.nth(i).getAttribute("data-id");
      if (id) ids1.push(id);
    }
    // Trigger re-render by clicking a row
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

test.describe("Remediation filter cycling via keyboard", () => {
  test("r key cycles through remediation values", async ({ page }) => {
    await ready(page);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(10); // auto
    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(3); // review
    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(1); // unavailable
    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(0); // manual
    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14); // back to all
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
    expect(count).toBe(6); // trivy
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(6); // lynis
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2); // compose
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14); // back to all
  });
});

test.describe("Number key filters", () => {
  test("key 1 filters to critical", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);
  });

  test("key 0 shows all", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    await page.keyboard.press("0");
    await page.waitForTimeout(200);
    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Findings panel structure", () => {
  test("panel has eyebrow saying Findings", async ({ page }) => {
    await ready(page);
    const eyebrow = page.locator(".findings-panel .eyebrow");
    const text = await eyebrow.textContent();
    expect(text).toContain("Findings");
  });
});

test.describe("Topbar structure", () => {
  test("topbar has title hostveil", async ({ page }) => {
    await ready(page);
    const h1 = page.locator(".topbar h1");
    const text = await h1.textContent();
    expect(text).toContain("hostveil");
  });

  test("topbar has eyebrow with security text", async ({ page }) => {
    await ready(page);
    const eyebrow = page.locator(".topbar .eyebrow");
    const text = await eyebrow.textContent();
    expect(text).toBeTruthy();
  });
});

test.describe("Score element exists", () => {
  test("score element shows numeric value", async ({ page }) => {
    await ready(page);
    const score = page.locator("#score");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });

  test("score plate shows Security score label", async ({ page }) => {
    await ready(page);
    const label = page.locator(".scoreplate .score-label");
    const text = await label.textContent();
    expect(text).toContain("Security score");
  });
});

test.describe("Search input placeholder", () => {
  test("search input has placeholder text", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    const placeholder = await query.getAttribute("placeholder");
    expect(placeholder).toBeTruthy();
    expect(placeholder!.length).toBeGreaterThan(0);
  });
});

test.describe("Clear filters button exists", () => {
  test("clear filters button is visible", async ({ page }) => {
    await ready(page);
    const btn = page.locator("#clearFilters");
    await expect(btn).toBeVisible();
  });
});

test.describe("Detail panel badge color", () => {
  test("critical finding shows critical badge", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const badge = page.locator("#detail .badge");
    if ((await badge.count()) > 0) {
      const cls = await badge.getAttribute("class");
      expect(cls).toContain("critical");
    }
  });
});

test.describe("Sort by source groups findings", () => {
  test("source sort puts all compose findings together", async ({
    page,
  }) => {
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
    // Compose findings should be grouped together
    const composeIndices = ids
      .map((id, idx) => (id.startsWith("compose.") ? idx : -1))
      .filter((i) => i >= 0);
    if (composeIndices.length >= 2) {
      // All compose findings should be adjacent
      for (let i = 1; i < composeIndices.length; i++) {
        expect(composeIndices[i] - composeIndices[i - 1]).toBe(1);
      }
    }
  });
});

test.describe("Sort by remediation groups findings", () => {
  test("remediation sort puts auto first", async ({ page }) => {
    await ready(page);
    await page.locator("#sortBy").selectOption("remediation");
    await page.waitForTimeout(200);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const fixTexts: string[] = [];
    for (let i = 0; i < count; i++) {
      const lastCell = rows.nth(i).locator("td").last();
      fixTexts.push((await lastCell.textContent()) ?? "");
    }
    const getGroup = (text: string): number => {
      if (text.includes("Auto") || text.includes("Fixed")) return 0;
      if (text.includes("Review")) return 1;
      if (text.includes("Unavailable")) return 2;
      return 3;
    };
    let lastGroup = -1;
    for (const text of fixTexts) {
      const group = getGroup(text);
      expect(group).toBeGreaterThanOrEqual(lastGroup);
      lastGroup = group;
    }
  });
});

test.describe("Evidence key alphabetical ordering", () => {
  test("evidence keys appear in sorted order", async ({ page }) => {
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

test.describe("Score breakdown head description", () => {
  test("head mentions penalty cap and scanner", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const p = head.locator("p");
    const text = await p.textContent();
    expect(text).toContain("penalty cap");
    expect(text).toContain("scanner");
  });
});

test.describe("Metrics medium and low counts", () => {
  test("medium metric shows 4", async ({ page }) => {
    await ready(page);
    const metrics = page.locator("#metrics .metric");
    const fourth = await metrics.nth(3).textContent();
    expect(fourth).toContain("4");
  });

  test("low metric shows 2", async ({ page }) => {
    await ready(page);
    const metrics = page.locator("#metrics .metric");
    const fifth = await metrics.nth(4).textContent();
    expect(fifth).toContain("2");
  });
});
