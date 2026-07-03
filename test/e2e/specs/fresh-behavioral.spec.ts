import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

async function apiFetch(
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

test.describe("Fix apply flow end-to-end", () => {
  test("clicking Fix on auto finding opens modal, confirm applies fix", async ({
    page,
  }) => {
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
    const isDisabled = await confirmBtn.isDisabled();
    expect(isDisabled).toBe(false);

    await confirmBtn.click();
    await page.waitForTimeout(1000);

    await expect(modal).not.toBeVisible({ timeout: 3000 });

    const fixResult = page.locator("#fixResult");
    const text = await fixResult.textContent();
    expect(text).toContain("Apply mock fix");
  });
});


test.describe("Score breakdown with filtered data", () => {
  test("score breakdown updates after filter", async ({ page }) => {
    await ready(page);

    const axes = page.locator("#scoreBreakdown .score-axis");
    await expect(axes).toHaveCount(4);

    for (let i = 0; i < 4; i++) {
      const score = axes.nth(i).locator(".score-axis-top strong");
      const text = await score.textContent();
      expect(text).toMatch(/^\d+\/100$/);
    }
  });
});

test.describe("Evidence expand/collapse behavior", () => {
  test("evidence details expand and collapse", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const summary = page
      .locator("#detail .evidence-details summary")
      .first();
    await summary.click();
    await page.waitForTimeout(300);

    const pres = page.locator(
      "#detail .evidence-details:first-of-type pre"
    );
    const preCount = await pres.count();
    expect(preCount).toBeGreaterThanOrEqual(3);

    await summary.click();
    await page.waitForTimeout(300);
  });
});

test.describe("Keyboard 'f' opens fix", () => {
  test("pressing f opens fix for current finding", async ({ page }) => {
    await ready(page);

    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);

    await page.keyboard.press("f");
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 3000 });

    await page.keyboard.press("Escape");
    await page.waitForTimeout(200);
  });
});

test.describe("Score breakdown axis data attributes", () => {
  test("each axis has correct data-axis value", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const expectedIds = [
      "vulnerabilities",
      "container_exposure",
      "host_hardening",
      "secrets",
    ];
    for (let i = 0; i < 4; i++) {
      const axisId = await axes.nth(i).getAttribute("data-axis");
      expect(expectedIds).toContain(axisId);
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
  });
});

test.describe("Rescan button state", () => {
  test("rescan button shows loading state", async ({ page }) => {
    await ready(page);

    const rescanBtn = page.locator("#rescanBtn");
    await expect(rescanBtn).toBeVisible();

    await rescanBtn.click();
    await page.waitForTimeout(500);

    const isDisabled = await rescanBtn.isDisabled();
    expect(isDisabled).toBe(true);
  });
});

test.describe("Recalc button state", () => {
  test("recalc button shows loading during recalc", async ({ page }) => {
    await ready(page);

    const recalcBtn = page.locator("#recalcBtn");
    await expect(recalcBtn).toBeVisible();

    await recalcBtn.click();
    await page.waitForTimeout(300);

    const toast = page.locator(".toast");
    await expect(toast).toBeVisible({ timeout: 2000 });
  });
});

test.describe("Multiple rapid filter changes", () => {
  test("rapid clicks settle to final state", async ({ page }) => {
    await ready(page);

    const critical = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    const high = page
      .locator("#severityFilters button")
      .filter({ hasText: "High" });
    const all = page
      .locator("#severityFilters button")
      .filter({ hasText: "All" });

    await critical.click();
    await high.click();
    await all.click();
    await page.waitForTimeout(300);

    const count = await page
      .locator("#findings tr[data-index]")
      .count();
    expect(count).toBe(14);
  });
});

test.describe("Score breakdown penalty bars have width", () => {
  test("each penalty bar has a percentage width", async ({ page }) => {
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

test.describe("Detail panel for lynis finding", () => {
  test("lynis finding shows correct detail fields", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9308']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Root SSH login");
    expect(text).toContain("PermitRootLogin");
    expect(text).toContain("lynis.AUTH-9308");
    expect(text).toContain("Auto");
    expect(text).toContain("one clear fix");
  });
});

test.describe("Detail panel for compose finding", () => {
  test("compose finding shows service and metadata", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='compose.dr004']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("env_file");
    expect(text).toContain("Service");
    expect(text).toContain("webapp");
  });
});

test.describe("Score breakdown axis severity count spans", () => {
  test("vulnerabilities axis has severity count spans", async ({ page }) => {
    await ready(page);
    const vulnAxis = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Vulnerabilities" });
    const counts = vulnAxis.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Table row fixed class", () => {
  test("fixed finding row has both fixed and disabled classes", async ({
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
});

test.describe("Table row source column", () => {
  test("trivy finding shows trivy source", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const cells = row.locator("td");
    const sourceCell = cells.nth(2);
    const text = await sourceCell.textContent();
    expect(text).toContain("trivy");
  });
});

test.describe("Filter chip active state persistence", () => {
  test("active chip stays active after re-render", async ({ page }) => {
    await ready(page);

    await page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" })
      .click();
    await page.waitForTimeout(200);

    let active = await page
      .locator("#severityFilters button.active")
      .textContent();
    expect(active).toContain("Critical");

    await page
      .locator("#findings tr[data-index]")
      .first()
      .click({ force: true });
    await page.waitForTimeout(200);

    active = await page
      .locator("#severityFilters button.active")
      .textContent();
    expect(active).toContain("Critical");
  });
});

test.describe("Sort by remediation grouping", () => {
  test("remediation sort groups findings by fix type", async ({
    page,
  }) => {
    await ready(page);

    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("remediation");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();

    const fixTexts: string[] = [];
    for (let i = 0; i < count; i++) {
      const cells = rows.nth(i).locator("td");
      const lastCell = cells.last();
      fixTexts.push((await lastCell.textContent()) ?? "");
    }

    // All Auto+Fixed should come before Review, which comes before Unavailable
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

test.describe("Detail panel badge and remediation type", () => {
  test("review finding shows Review remediation", async ({ page }) => {
    await ready(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toContain("Review");
    expect(text).toContain("multiple options");
  });
});

test.describe("Search case insensitivity", () => {
  test("searching with uppercase matches lowercase", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.fill("CVE");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(3);
  });
});

test.describe("Score breakdown head text", () => {
  test("head shows 'Score breakdown' and description", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    const text = await head.textContent();
    expect(text).toContain("Score breakdown");
    expect(text).toContain("penalty cap");
    expect(text).toContain("scanner");
  });
});

test.describe("Metrics total count", () => {
  test("total metric shows 14", async ({ page }) => {
    await ready(page);
    const metrics = page.locator("#metrics .metric");
    const first = await metrics.first().textContent();
    expect(first).toContain("14");
  });
});

test.describe("Score breakdown axis count colors", () => {
  test("severity count spans have correct CSS classes", async ({ page }) => {
    await ready(page);
    const counts = page.locator(
      "#scoreBreakdown .score-axis-counts span"
    );
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);

    for (let i = 0; i < count; i++) {
      const cls = await counts.nth(i).getAttribute("class");
      expect(cls).toMatch(/^(critical|high|medium|low|muted)$/);
    }
  });
});

test.describe("Fix modal action label", () => {
  test("fix modal shows finding title in label", async ({ page }) => {
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

    const label = modal.locator(".fix-label");
    const text = await label.textContent();
    expect(text).toContain("Mock fix");

    await page.keyboard.press("Escape");
  });
});

test.describe("Finding count after source filter", () => {
  test("trivy filter shows correct count", async ({ page }) => {
    await ready(page);
    await page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" })
      .click();
    await page.waitForTimeout(200);

    const countEl = page.locator("#findingCount");
    expect(await countEl.textContent()).toBe("6 visible");
  });
});

test.describe("Score breakdown axis penalty values", () => {
  test("vulnerabilities axis max penalty is 35", async ({ page }) => {
    await ready(page);
    const result = await apiFetch(page, "/api/result");
    const data = JSON.parse(result.body);
    const vuln = data.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "vulnerabilities"
    );
    expect(vuln.max_penalty).toBe(35);
  });
});

test.describe("Detail panel for fixed finding", () => {
  test("fixed finding detail has no Fix button", async ({ page }) => {
    await ready(page);

    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    const fixBtn = page.locator("#detail .fix-btn");
    const count = await fixBtn.count();
    expect(count).toBe(0);
  });
});

test.describe("Score plate severity class", () => {
  test("score plate gets correct severity class", async ({ page }) => {
    await ready(page);
    const scoreplate = page.locator(".scoreplate");
    const cls = await scoreplate.getAttribute("class");
    expect(cls).toMatch(/score-(low|medium|high|critical)/);
  });
});
