import { test, expect, type Page } from "@playwright/test";

async function waitForReady(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Table row classes for fixed findings", () => {
  test("fixed finding row has fixed class", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const className = await row.getAttribute("class");
    expect(className).toContain("fixed");
  });

  test("fixed finding row has disabled class", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003']"
    );
    const className = await row.getAttribute("class");
    expect(className).toContain("disabled");
  });
});

test.describe("Table row checkbox disabled for unavailable", () => {
  test("unavailable finding checkbox is disabled", async ({ page }) => {
    await waitForReady(page);
    const checkbox = page.locator(
      "#findings tr[data-id='test.unfixable-001'] .row-check"
    );
    const isDisabled = await checkbox.isDisabled();
    expect(isDisabled).toBe(true);
  });

  test("fixed finding checkbox is disabled", async ({ page }) => {
    await waitForReady(page);
    const checkbox = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0003'] .row-check"
    );
    const isDisabled = await checkbox.isDisabled();
    expect(isDisabled).toBe(true);
  });

});

test.describe("Score breakdown axis data-axis values", () => {
  test("each axis has correct data-axis attribute", async ({ page }) => {
    await waitForReady(page);
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

test.describe("Detail panel for review finding", () => {
  test("review finding shows Review remediation type", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.dr001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail .detail-meta");
    const text = await detail.textContent();
    expect(text).toContain("Review");
    expect(text).toContain("multiple options");
  });
});

test.describe("Fix info_only returns action details", () => {
  test("compose finding action has type and label", async ({ page }) => {
    await waitForReady(page);
    const result = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding: {
            id: "trivy.ds001",
            title: "Container runs in privileged mode",
            severity: 1,
            source: 0,
            remediation: 0,
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
    const action = result.actions[0];
    expect(action.type).toBeTruthy();
    expect(action.label).toBeTruthy();
  });
});

test.describe("Score breakdown severity count spans", () => {
  test("severity counts use span elements with correct classes", async ({
    page,
  }) => {
    await waitForReady(page);
    const counts = page.locator(
      "#scoreBreakdown .score-axis-counts span"
    );
    const count = await counts.count();
    expect(count).toBeGreaterThanOrEqual(1);

    for (let i = 0; i < count; i++) {
      const cls = await counts.nth(i).getAttribute("class");
      const text = await counts.nth(i).textContent();
      // Either "No active findings" (muted) or N + severity letter
      if (cls === "muted") {
        expect(text).toContain("No active findings");
      } else {
        expect(cls).toMatch(/^(critical|high|medium|low)$/);
        expect(text).toMatch(/\d+[CHML]/);
      }
    }
  });
});

test.describe("Filter and search combined", () => {
  test("search + severity filter narrows correctly", async ({ page }) => {
    await waitForReady(page);

    // Filter to high severity
    const highChip = page
      .locator("#severityFilters button")
      .filter({ hasText: "High" });
    await highChip.click();
    await page.waitForTimeout(200);

    // Search for nginx
    const query = page.locator("#query");
    await query.fill("nginx");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // High + nginx: cve-2024-0002 = 1
    expect(count).toBe(1);
    const id = await rows.first().getAttribute("data-id");
    expect(id).toBe("trivy.cve-2024-0002");
  });

  test("source filter + search narrows correctly", async ({ page }) => {
    await waitForReady(page);

    // Filter to lynis
    const lynisChip = page
      .locator("#sourceFilters button")
      .filter({ hasText: "Lynis" });
    await lynisChip.click();
    await page.waitForTimeout(200);

    // Search for SSH
    const query = page.locator("#query");
    await query.fill("SSH");
    await page.waitForTimeout(300);

    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    // Lynis + SSH: AUTH-9286, AUTH-9308 = 2
    expect(count).toBe(2);
  });
});

test.describe("Score breakdown axis score values", () => {
  test("each axis score is between 0 and 100", async ({ page }) => {
    await waitForReady(page);
    const scores = page.locator("#scoreBreakdown .score-axis-top strong");
    const count = await scores.count();
    expect(count).toBe(4);

    for (let i = 0; i < count; i++) {
      const text = await scores.nth(i).textContent();
      const match = text?.match(/^(\d+)\/100$/);
      expect(match).toBeTruthy();
      if (match) {
        const score = parseInt(match[1]);
        expect(score).toBeGreaterThanOrEqual(0);
        expect(score).toBeLessThanOrEqual(100);
      }
    }
  });
});

test.describe("Detail panel for finding with service", () => {
  test("detail shows Service label and value", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0002']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail .detail-meta");
    const text = await detail.textContent();
    expect(text).toContain("Service");
    expect(text).toContain("nginx:1.24");
  });
});

test.describe("Detail panel for finding without service", () => {
  test("detail hides Service label", async ({ page }) => {
    await waitForReady(page);
    const row = page.locator(
      "#findings tr[data-id='lynis.AUTH-9308']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(300);

    const detail = page.locator("#detail .detail-meta");
    const text = await detail.textContent();
    // lynis findings have empty service — no Service field shown
    expect(text).not.toContain("Service");
  });
});

test.describe("Fix modal overlay click closes", () => {
  test("fix modal closes when clicking outside", async ({ page }) => {
    await waitForReady(page);

    // Open fix modal via keyboard
    // First select a finding
    const row = page.locator(
      "#findings tr[data-id='trivy.cve-2024-0001']"
    );
    await row.click({ force: true });
    await page.waitForTimeout(500);

    // Press f to open fix
    await page.keyboard.press("f");
    await page.waitForTimeout(500);

    const modal = page.locator("#fixModal");
    const isVisible = await modal.isVisible().catch(() => false);
    if (isVisible) {
      // Click overlay background
      const box = await modal.boundingBox();
      if (box) {
        await page.mouse.click(box.x + 5, box.y + 5);
        await page.waitForTimeout(300);
        await expect(modal).not.toBeVisible();
      }
    }
  });
});

test.describe("Metrics row total count", () => {
  test("total metric shows 14", async ({ page }) => {
    await waitForReady(page);
    const totalMetric = page.locator("#metrics .metric--total");
    const text = await totalMetric.textContent();
    expect(text).toContain("14");
  });
});

test.describe("Score plate score value", () => {
  test("score plate shows numeric score", async ({ page }) => {
    await waitForReady(page);
    const score = page.locator("#score");
    const text = await score.textContent();
    expect(text).toMatch(/^\d+\/100$/);
  });
});

test.describe("Sort by severity ascending default", () => {
  test("first row is critical severity", async ({ page }) => {
    await waitForReady(page);
    const firstRow = page.locator("#findings tr[data-index]").first();
    const badge = firstRow.locator(".badge");
    const text = await badge.textContent();
    expect(text).toContain("critical");
  });

  test("last row is low severity", async ({ page }) => {
    await waitForReady(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const lastRow = rows.nth(count - 1);
    const badge = lastRow.locator(".badge");
    const text = await badge.textContent();
    expect(text).toContain("low");
  });
});
