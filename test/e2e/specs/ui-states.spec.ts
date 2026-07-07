import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Clean state when no findings", () => {
  test("score shows Clean when findings array is empty", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "clean-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await expect(page.locator("#score")).toHaveText("Clean");
    await expect(page.locator("#score")).toHaveClass(/low/);
  });

  test("metrics show 0 total when no findings", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "clean-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    const metrics = page.locator("#metrics .metric");
    await expect(metrics).toHaveCount(6);
    await expect(metrics.first()).toContainText("0");
  });

  test("finding count shows 0 visible", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "clean-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await expect(page.locator("#findingCount")).toContainText("0 visible");
  });

  test("table shows no-match message", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "clean-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await expect(page.locator("#findings .muted")).toContainText(
      "No findings match"
    );
  });

  test("detail panel shows empty state", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "clean-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    const empty = page.locator("#detail .empty-detail");
    await expect(empty).toHaveCount(1);
    await expect(empty).toContainText("Select a finding");
  });

  test("score breakdown hidden when no axes", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "clean-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await expect(page.locator("#scoreBreakdown")).toBeHidden();
  });
});

test.describe("Score breakdown no active findings", () => {
  test("axis with zero counts shows No active findings", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "test-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 100,
          score_breakdown: {
            overall: 100,
            axes: [
              {
                id: "vulnerabilities",
                label: "Vulnerabilities",
                score: 100,
                penalty: 0,
                max_penalty: 35,
                critical: 0,
                high: 0,
                medium: 0,
                low: 0,
              },
            ],
          },
        }),
      })
    );
    await page.goto("/");
    await expect(page.locator("#scoreBreakdown .score-axis-counts").first()).toContainText(
      "No active findings"
    );
  });
});

test.describe("Visibility pause", () => {
  test("polling stops when tab is hidden and resumes when visible", async ({
    page,
  }) => {
    let fetchCount = 0;
    await page.route("**/api/result", (route) => {
      fetchCount++;
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          phase: "loading",
          tools: {},
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      });
    });
    await page.goto("/");
    await page.waitForTimeout(1000);
    const countBeforeHide = fetchCount;
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { value: true, writable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.waitForTimeout(3000);
    expect(fetchCount).toBe(countBeforeHide);
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { value: false, writable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.waitForTimeout(3000);
    expect(fetchCount).toBeGreaterThan(countBeforeHide);
  });
});

test.describe("Connection lost handling", () => {
  test("page survives consecutive fetch failures", async ({ page }) => {
    let callCount = 0;
    await page.route("**/api/result", (route) => {
      callCount++;
      if (callCount <= 5) {
        route.abort("connectionrefused");
      } else {
        route.fulfill({
          status: 200,
          contentType: "application/json",
          body: JSON.stringify({
            hostname: "test-box",
            local_ip: "10.0.0.1",
            findings: [],
            score: 100,
            score_breakdown: { overall: 100, axes: [] },
          }),
        });
      }
    });
    await page.goto("/");
    await page.waitForTimeout(8000);
    await expect(page.locator("body")).not.toBeEmpty();
  });
});

test.describe("Loading phase screen", () => {
  test("shows scanning UI when phase is loading", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          phase: "loading",
          tools: {
            trivy: { status: 1, message: "Scanning images..." },
            lynis: { status: 0, message: "Queued" },
            compose: { status: 2, message: "Done" },
          },
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await expect(page.locator(".loading-state h2")).toHaveText("Scanning...");
    await expect(page.locator("#score")).toHaveText("--/100");
    await expect(page.locator("#findingCount")).toHaveText("Scanning...");
    await expect(page.locator(".shell")).toHaveClass(/loading/);
  });
});

test.describe("Recalc failure toast", () => {
  test("shows error toast when recalc fails", async ({ page }) => {
    await ready(page);
    await page.route("**/api/recalc", (route) => route.abort("connectionrefused"));
    await page.locator("#recalcBtn").click();
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 5000 });
    await expect(toast).toContainText("Recalculation failed");
  });
});
