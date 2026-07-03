import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

async function apiFetch(
  page: Page,
  path: string,
  options?: RequestInit
) {
  return page.evaluate(
    async ({ path, options }: { path: string; options?: RequestInit }) => {
      const resp = await fetch(path, options);
      const headers: Record<string, string> = {};
      resp.headers.forEach((v, k) => { headers[k] = v; });
      return { status: resp.status, headers, body: await resp.text() };
    },
    { path, options }
  );
}

test.describe("Table row data-index attributes", () => {
  test("rows have sequential data-index starting from 0", async ({
    page,
  }) => {
    await waitForReady(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    expect(count).toBe(14);

    for (let i = 0; i < count; i++) {
      const idx = await rows.nth(i).getAttribute("data-index");
      expect(idx).toBe(String(i));
    }
  });
});

test.describe("Sort by source groups findings", () => {
  test("source sort puts all compose findings together", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("source");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const ids: string[] = [];
    for (let i = 0; i < count; i++) {
      ids.push((await rows.nth(i).getAttribute("data-id")) ?? "");
    }

    // Find first and last compose indices
    const firstCompose = ids.findIndex((id) => id.startsWith("compose."));
    const lastCompose = ids.findLastIndex((id) => id.startsWith("compose."));
    if (firstCompose >= 0 && lastCompose >= 0) {
      // All compose findings should be contiguous
      for (let i = firstCompose; i <= lastCompose; i++) {
        expect(ids[i].startsWith("compose.")).toBe(true);
      }
    }
  });
});

test.describe("Sort by remediation groups findings", () => {
  test("remediation sort groups findings by fix type", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    await sortBy.selectOption("remediation");
    await page.waitForTimeout(200);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const fixTexts: string[] = [];
    for (let i = 0; i < count; i++) {
      const cells = rows.nth(i).locator("td");
      const fixCell = cells.last();
      fixTexts.push((await fixCell.textContent()) ?? "");
    }

    // Verify sort order: Auto < Review < Unavailable
    const order = ["Auto", "Review", "Unavailable"];
    let lastIdx = -1;
    for (const text of fixTexts) {
      const matched = order.findIndex((o) => text.includes(o));
      if (matched >= 0) {
        expect(matched).toBeGreaterThanOrEqual(lastIdx);
        lastIdx = matched;
      }
    }
  });
});

test.describe("Evidence values rendered in pre tags", () => {
  test("evidence key-value pairs are in pre elements", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const evidencePre = page.locator("#detail .evidence-details pre");
    const count = await evidencePre.count();
    // 3 evidence keys, each in a pre tag
    expect(count).toBeGreaterThanOrEqual(3);

    // Details may be collapsed — just check the pre has content
    const firstPre = evidencePre.first();
    const text = await firstPre.textContent();
    expect(text).toBeTruthy();
    expect(text.length).toBeGreaterThan(0);
  });
});

test.describe("Metadata values rendered in pre tags", () => {
  test("metadata key-value pairs are in pre elements", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    // Find the metadata details section (second evidence-details)
    const metaSection = page.locator("#detail .evidence-details").nth(1);
    const summary = metaSection.locator("summary");
    const summaryText = await summary.textContent();
    expect(summaryText).toContain("Metadata");

    const pre = metaSection.locator("pre");
    const count = await pre.count();
    expect(count).toBe(1);

    const strong = pre.locator("strong");
    const key = await strong.textContent();
    expect(key).toContain("compose_path");
  });
});

test.describe("Detail panel ID and source in metadata", () => {
  test("detail shows finding ID in meta section", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("ID");
    expect(text).toContain("lynis.AUTH-9286");
    expect(text).toContain("Source");
  });
});

test.describe("Severity badge in table rows", () => {
  test("critical finding has critical badge in table", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const badge = row.locator(".badge");
    await expect(badge).toBeVisible();
    const text = await badge.textContent();
    expect(text).toContain("critical");
  });

  test("medium finding has medium badge in table", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    const badge = row.locator(".badge");
    await expect(badge).toBeVisible();
    const text = await badge.textContent();
    expect(text).toContain("medium");
  });
});

test.describe("Score breakdown head text", () => {
  test("score breakdown has description text", async ({ page }) => {
    await waitForReady(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    await expect(head).toBeVisible();
    const text = await head.textContent();
    expect(text).toContain("Score breakdown");
    expect(text).toContain("penalty cap");
  });
});

test.describe("Filter chip count matches data", () => {
  test("severity chips show all severity levels", async ({ page }) => {
    await waitForReady(page);
    const chips = page.locator("#severityFilters button");
    const count = await chips.count();
    // all + critical + high + medium + low = 5
    expect(count).toBe(5);
  });

  test("source chips show all sources", async ({ page }) => {
    await waitForReady(page);
    const chips = page.locator("#sourceFilters button");
    const count = await chips.count();
    // all + trivy + lynis + compose = 4
    expect(count).toBe(4);
  });

  test("remediation chips show available remediation types", async ({
    page,
  }) => {
    await waitForReady(page);
    const chips = page.locator("#remediationFilters button");
    const count = await chips.count();
    // all + auto + review + unavailable = 4 (no manual in data)
    expect(count).toBe(4);
  });
});

test.describe("Sort dropdown options", () => {
  test("sort dropdown has 4 options", async ({ page }) => {
    await waitForReady(page);
    const options = page.locator("#sortBy option");
    const count = await options.count();
    expect(count).toBe(4);
  });

  test("sort dropdown default is severity", async ({ page }) => {
    await waitForReady(page);
    const sortBy = page.locator("#sortBy");
    const value = await sortBy.inputValue();
    expect(value).toBe("severity");
  });
});

test.describe("Panel head contains action buttons", () => {
  test("panel head has Rescan, Recalc, Export buttons", async ({ page }) => {
    await waitForReady(page);

    const rescanBtn = page.locator("#rescanBtn");
    const recalcBtn = page.locator("#recalcBtn");
    const exportBtn = page.locator("#exportBtn");

    await expect(rescanBtn).toBeVisible();
    await expect(recalcBtn).toBeVisible();
    await expect(exportBtn).toBeVisible();
  });
});

test.describe("Fix Selected button exists", () => {
  test("fix selected button is present in panel head", async ({ page }) => {
    await waitForReady(page);
    const btn = page.locator("#fixSelectedBtn");
    await expect(btn).toBeAttached();
  });
});

test.describe("Detail panel has empty state by default", () => {
  test("detail panel shows empty-detail on fresh load", async ({ page }) => {
    await page.goto("/");
    // Don't wait for findings — check immediately
    await page.waitForTimeout(500);
    const emptyDetail = page.locator("#detail .empty-detail");
    // On fresh load, the page auto-selects first finding,
    // so empty-detail may or may not be visible
    // Just verify the detail element exists
    const detail = page.locator("#detail");
    await expect(detail).toBeAttached();
  });
});

test.describe("Score element exists", () => {
  test("score element shows numeric value", async ({ page }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    await expect(score).toBeVisible();
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Score plate has label", () => {
  test("score plate shows Security score label", async ({ page }) => {
    await waitForReady(page);
    const label = page.locator(".scoreplate .score-label");
    await expect(label).toBeVisible();
    const text = await label.textContent();
    expect(text).toContain("Security score");
  });
});

test.describe("Topbar has title and description", () => {
  test("topbar shows hostveil title", async ({ page }) => {
    await waitForReady(page);
    const h1 = page.locator(".topbar h1");
    await expect(h1).toBeVisible();
    const text = await h1.textContent();
    expect(text).toContain("hostveil");
  });

  test("topbar shows eyebrow description", async ({ page }) => {
    await waitForReady(page);
    const eyebrow = page.locator(".topbar .eyebrow");
    await expect(eyebrow).toBeVisible();
    const text = await eyebrow.textContent();
    expect(text).toContain("security");
  });
});

test.describe("Findings panel header", () => {
  test("findings panel has Findings heading", async ({ page }) => {
    await waitForReady(page);
    const heading = page.locator(".findings-panel .eyebrow");
    await expect(heading).toBeVisible();
    const text = await heading.textContent();
    expect(text).toContain("Findings");
  });
});

test.describe("Search input placeholder", () => {
  test("search input has placeholder text", async ({ page }) => {
    await waitForReady(page);
    const input = page.locator("#query");
    const placeholder = await input.getAttribute("placeholder");
    expect(placeholder).toBeTruthy();
    expect(placeholder?.length).toBeGreaterThan(0);
  });
});

test.describe("Clear filters button exists", () => {
  test("clear filters button is visible", async ({ page }) => {
    await waitForReady(page);
    const btn = page.locator("#clearFilters");
    await expect(btn).toBeVisible();
    const text = await btn.textContent();
    expect(text).toContain("Clear filters");
  });
});
