import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Score breakdown severity count styling", () => {
  test("severity counts have correct CSS classes", async ({ page }) => {
    await waitForReady(page);
    const counts = page.locator("#scoreBreakdown .score-axis-counts span");
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);

    // Each severity count span should have a CSS class (critical, high, etc.)
    for (let i = 0; i < count; i++) {
      const className = await counts.nth(i).getAttribute("class");
      expect(className).toMatch(/^(critical|high|medium|low|muted)$/);
    }
  });
});

test.describe("Fix modal for review finding shows multiple actions", () => {
  test("review finding info_only returns multiple actions", async ({
    page,
  }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            id: "trivy.dr001",
            title: "Container uses host network mode",
            severity: 2,
            source: 0,
            remediation: 1,
            service: "webapp",
            metadata: { compose_path: "/home/test/docker-compose.yml" },
          },
          action_index: 0,
          info_only: true,
        }),
      });
      return resp.json();
    });
    expect(result.success).toBe(true);
    expect(result.actions.length).toBeGreaterThanOrEqual(2);
  });
});

test.describe("Auto finding info_only returns single action", () => {
  test("auto finding info_only returns one action", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            id: "lynis.FILE-6310",
            title: "/etc/shadow has insecure permissions",
            severity: 3,
            source: 1,
            remediation: 0,
            service: "",
          },
          action_index: 0,
          info_only: true,
        }),
      });
      return resp.json();
    });
    expect(result.success).toBe(true);
    expect(result.actions.length).toBe(1);
    expect(result.actions[0].type).toBeTruthy();
    expect(result.actions[0].label).toBeTruthy();
  });
});

test.describe("Fix action types", () => {
  test("exec action has type and label fields", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            id: "lynis.FILE-6310",
            title: "test",
            severity: 3,
            source: 1,
            remediation: 0,
            service: "",
          },
          action_index: 0,
          info_only: true,
        }),
      });
      return resp.json();
    });
    expect(result.success).toBe(true);
    const action = result.actions[0];
    expect(action.type).toBe("exec");
    expect(action.label).toBeTruthy();
    expect(typeof action.index).toBe("number");
  });
});

test.describe("Batch fix with unregistered findings", () => {
  test("batch returns per-finding errors for unregistered IDs", async ({
    page,
  }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [
            {
              id: "nonexistent.finding-001",
              title: "test",
              severity: 0,
              source: 0,
              remediation: 0,
              service: "",
            },
          ],
          action_index: 0,
        }),
      });
      return resp.json();
    });
    expect(result.results.length).toBe(1);
    expect(result.results[0].success).toBe(false);
    expect(result.results[0].error).toContain("no fix registered");
  });
});

test.describe("Score breakdown axes have severity counts", () => {
  test("vulnerabilities axis has severity count spans", async ({ page }) => {
    await waitForReady(page);
    const vulnAxis = page
      .locator("#scoreBreakdown .score-axis")
      .filter({ hasText: "Vulnerabilities" });
    await expect(vulnAxis).toBeVisible();

    const counts = vulnAxis.locator(".score-axis-counts span");
    const count = await counts.count();
    // Should have at least one severity count
    expect(count).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Detail panel service field presence", () => {
  test("compose finding shows service in detail", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='compose.ds001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail .detail-meta");
    const text = await detail.textContent();
    expect(text).toContain("Service");
    expect(text).toContain("webapp");
  });
});

test.describe("Finding row has all expected cells", () => {
  test("each row has 6 cells", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const cells = row.locator("td");
    const count = await cells.count();
    expect(count).toBe(6);
  });
});

test.describe("Score breakdown penalty bar width", () => {
  test("penalty bar has width style", async ({ page }) => {
    await waitForReady(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    const count = await bars.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const style = await bars.nth(i).getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
    }
  });
});

test.describe("Export modal has three format options", () => {
  test("export modal shows JSON, CSV, and AI options", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const options = page.locator("#exportModal .export-option");
    const count = await options.count();
    expect(count).toBe(3);

    await page.keyboard.press("Escape");
  });
});

test.describe("Help modal close button", () => {
  test("help modal has close button that dismisses it", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const closeBtn = page.locator("#modalHelpClose");
    await expect(closeBtn).toBeVisible();
    await closeBtn.click();
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });
});

test.describe("Filter chip active state", () => {
  test("default severity filter shows All as active", async ({ page }) => {
    await waitForReady(page);
    const activeChip = page
      .locator("#severityFilters button.active");
    const text = await activeChip.textContent();
    expect(text).toContain("All");
  });

  test("clicking chip makes it active", async ({ page }) => {
    await waitForReady(page);
    const criticalChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "Critical" });
    await criticalChip.click();
    await page.waitForTimeout(200);

    const activeChip = page
      .locator("#severityFilters button.active");
    const text = await activeChip.textContent();
    expect(text).toContain("Critical");
  });
});

test.describe("Score breakdown axis penalty text", () => {
  test("each axis shows penalty ratio", async ({ page }) => {
    await waitForReady(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const count = await axes.count();

    for (let i = 0; i < count; i++) {
      const meta = axes.nth(i).locator(".score-axis-meta span").first();
      const text = await meta.textContent();
      expect(text).toMatch(/\d+\/\d+ penalty/);
    }
  });
});

test.describe("Finding title in table row", () => {
  test("trivy finding shows truncated title", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const titleCell = row.locator(".title");
    const text = await titleCell.textContent();
    expect(text).toContain("CVE-2024-0001");
  });
});

test.describe("Severity badge class in table", () => {
  test("critical finding badge has critical class", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    const badge = row.locator(".badge");
    const className = await badge.getAttribute("class");
    expect(className).toContain("critical");
  });
});
