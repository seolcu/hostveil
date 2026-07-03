import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Table row severity badge in correct column", () => {
  test("severity badge is in the second td", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const secondTd = row.locator("td").nth(1);
    const badge = secondTd.locator(".badge");
    await expect(badge).toBeVisible();
    const text = await badge.textContent();
    expect(text).toContain("critical");
  });
});

test.describe("Table row ID in correct column", () => {
  test("short ID is in the fourth td", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9286']"
    );
    const fourthTd = row.locator("td").nth(3);
    const text = await fourthTd.textContent();
    expect(text).toContain("AUTH-9286");
  });
});

test.describe("Table row title in correct column", () => {
  test("title is in the fifth td", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const fifthTd = row.locator("td").nth(4);
    const text = await fifthTd.textContent();
    expect(text).toContain("CVE-2024-0001");
  });
});

test.describe("Table row fix column", () => {
  test("fix text is in the sixth td", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const sixthTd = row.locator("td").nth(5);
    const text = await sixthTd.textContent();
    expect(text).toContain("Auto");
  });
});

test.describe("Fixed finding row check mark", () => {
  test("fixed finding shows check mark in severity column", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const secondTd = row.locator("td").nth(1);
    const text = await secondTd.textContent();
    expect(text).toContain("✓");
  });
});

test.describe("Fixed finding strikethrough title", () => {
  test("fixed finding title has strikethrough style", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const titleCell = row.locator(".title");
    const hasStrikethrough = await titleCell.evaluate((el) => {
      const span = el.querySelector("span");
      return span?.style.textDecoration === "line-through";
    });
    expect(hasStrikethrough).toBe(true);
  });
});

test.describe("Fixed finding shows Fixed text", () => {
  test("fixed finding shows Fixed in fix column", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const sixthTd = row.locator("td").nth(5);
    const text = await sixthTd.textContent();
    expect(text).toContain("Fixed");
  });
});

test.describe("Finding count after source filter", () => {
  test("trivy filter shows 6, then all shows 14", async ({ page }) => {
    await waitForReady(page);

    // Apply trivy filter
    const chip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Trivy" });
    await chip.click();
    await page.waitForTimeout(200);

    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(6);

    // Apply all
    const allChip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "All" });
    await allChip.click();
    await page.waitForTimeout(200);

    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});

test.describe("Score breakdown axes severity counts", () => {
  test("vulnerabilities axis has severity counts", async ({ page }) => {
    await waitForReady(page);
    const vulnAxis = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Vulnerabilities" });
    const counts = vulnAxis.locator(".score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Detail panel for different severity levels", () => {
  test("critical finding shows critical badge in detail", async ({
    page,
  }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    const text = await badge.textContent();
    expect(text).toContain("critical");
  });

  test("medium finding shows medium badge in detail", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const badge = page.locator("#detail .badge");
    const text = await badge.textContent();
    expect(text).toContain("medium");
  });
});

test.describe("Sort stability across re-renders", () => {
  test("severity sort produces same order after re-render", async ({
    page,
  }) => {
    await waitForReady(page);

    // Collect initial order
    const getIds = async () => {
      const rows = page.locator("#findings tr[data-index]");
      const count = await rows.count();
      const ids: string[] = [];
      for (let i = 0; i < count; i++) {
        ids.push((await rows.nth(i).getAttribute("data-id")) ?? "");
      }
      return ids;
    };

    const ids1 = await getIds();

    // Trigger a re-render by pressing o and then back
    await page.keyboard.press("o");
    await page.waitForTimeout(200);
    await page.keyboard.press("o");
    await page.keyboard.press("o");
    await page.keyboard.press("o");
    await page.waitForTimeout(200);

    const ids2 = await getIds();
    // After cycling back to severity, order should be same
    expect(ids1).toEqual(ids2);
  });
});

test.describe("Remediation filter cycling via keyboard", () => {
  test("r key cycles through remediation values", async ({ page }) => {
    await waitForReady(page);

    // Start at all
    let active = await page
      .locator("#remediationFilters button.active")
      .textContent();
    expect(active).toContain("All");

    // Press r → auto
    await page.keyboard.press("r");
    await page.waitForTimeout(200);
    active = await page
      .locator("#remediationFilters button.active")
      .textContent();
    expect(active).toContain("Auto");
  });
});

test.describe("Source filter cycling via keyboard", () => {
  test("s key cycles through source values", async ({ page }) => {
    await waitForReady(page);

    // Start at all
    let active = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(active).toContain("All");

    // Press s → trivy
    await page.keyboard.press("s");
    await page.waitForTimeout(200);
    active = await page
      .locator("#sourceFilters button.active")
      .textContent();
    expect(active).toContain("Trivy");
  });
});

test.describe("Number key filters", () => {
  test("key 0 shows all findings", async ({ page }) => {
    await waitForReady(page);

    // Apply a filter first
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(2);

    // Press 0 to show all
    await page.keyboard.press("0");
    await page.waitForTimeout(200);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });
});
