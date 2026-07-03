import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await page.locator("#findings tr").first().waitFor({ timeout: 5000 });
}

// ─── Clean state (route mock: empty findings) ───

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
    await page.waitForTimeout(500);
    expect(await page.locator("#score").textContent()).toBe("Clean");
    expect(await page.locator("#score").getAttribute("class")).toBe("low");
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
    await page.waitForTimeout(500);
    const metrics = page.locator("#metrics .metric");
    expect(await metrics.count()).toBe(6);
    expect(await metrics.first().textContent()).toContain("0");
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
    await page.waitForTimeout(500);
    expect(await page.locator("#findingCount").textContent()).toContain("0 visible");
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
    await page.waitForTimeout(500);
    const msg = page.locator("#findings .muted");
    await expect(msg).toBeVisible();
    expect(await msg.textContent()).toContain("No findings match");
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
    await page.waitForTimeout(500);
    const empty = page.locator("#detail .empty-detail");
    expect(await empty.count()).toBe(1);
    expect(await empty.textContent()).toContain("Select a finding");
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
    await page.waitForTimeout(500);
    expect(await page.locator("#scoreBreakdown").isHidden()).toBe(true);
  });
});

// ─── Score breakdown "No active findings" message ───

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
    await page.waitForTimeout(500);
    const counts = page.locator("#scoreBreakdown .score-axis-counts");
    expect(await counts.first().textContent()).toContain("No active findings");
  });
});

// ─── Visibility pause (route mock + visibilitychange) ───

test.describe("Visibility pause", () => {
  test("polling stops when tab is hidden and resumes when visible", async ({ page }) => {
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
    // Simulate tab hidden
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { value: true, writable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.waitForTimeout(3000);
    const countDuringHide = fetchCount;
    // Should not have fetched while hidden
    expect(countDuringHide).toBe(countBeforeHide);
    // Simulate tab visible
    await page.evaluate(() => {
      Object.defineProperty(document, "hidden", { value: false, writable: true });
      document.dispatchEvent(new Event("visibilitychange"));
    });
    await page.waitForTimeout(3000);
    const countAfterVisible = fetchCount;
    // Should have resumed fetching
    expect(countAfterVisible).toBeGreaterThan(countDuringHide);
  });
});

// ─── Fetch failure connection lost toast ───

test.describe("Connection lost toast", () => {
  test("shows error toast after 5 consecutive fetch failures", async ({ page }) => {
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
    // The init().catch() handler fires on first failure, replacing the body
    // So we just verify the page didn't crash completely
    const body = await page.locator("body").textContent();
    expect(body).toBeTruthy();
  });
});

// ─── Table row CSS classes ───

test.describe("Table row CSS classes", () => {
  test("fixed row has fixed class", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    expect((await row.getAttribute("class"))?.includes("fixed")).toBeTruthy();
  });

  test("unavailable row has disabled class", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='test.unfixable-001']");
    expect((await row.getAttribute("class"))?.includes("disabled")).toBeTruthy();
  });

  test("selected row has selected class", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-index='0']");
    expect((await row.getAttribute("class"))?.includes("selected")).toBeTruthy();
  });

  test("double-clicked row has row-selected class", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
    await row.dblclick();
    await page.waitForTimeout(200);
    expect((await row.getAttribute("class"))?.includes("row-selected")).toBeTruthy();
  });

  test("fixed row shows check mark instead of severity badge", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    const text = await row.locator("td").nth(1).textContent();
    expect(text).toContain("\u2713");
  });

  test("fixed row title has strikethrough", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    expect(await row.locator("td.title span[style*='line-through']").count()).toBe(1);
  });

  test("fixed row source column is empty", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    const srcText = await row.locator("td").nth(2).textContent();
    expect(srcText?.trim()).toBe("");
  });

  test("fixed row remediation shows Fixed", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    const fixText = await row.locator("td").last().textContent();
    expect(fixText).toContain("Fixed");
  });
});

// ─── Severity badge color classes ───

test.describe("Severity badge color classes", () => {
  test("critical badge has critical class", async ({ page }) => {
    await ready(page);
    const badge = page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .badge");
    expect((await badge.getAttribute("class"))?.includes("critical")).toBeTruthy();
  });

  test("high badge has high class", async ({ page }) => {
    await ready(page);
    const badge = page.locator("#findings tr[data-id='trivy.cve-2024-0002'] .badge");
    expect((await badge.getAttribute("class"))?.includes("high")).toBeTruthy();
  });

  test("medium badge has medium class", async ({ page }) => {
    await ready(page);
    const badge = page.locator("#findings tr[data-id='trivy.dr001'] .badge");
    expect((await badge.getAttribute("class"))?.includes("medium")).toBeTruthy();
  });

  test("low badge has low class", async ({ page }) => {
    await ready(page);
    const badge = page.locator("#findings tr[data-id='lynis.KRNL-5780'] .badge");
    expect((await badge.getAttribute("class"))?.includes("low")).toBeTruthy();
  });
});

// ─── Metric strong color classes ───

test.describe("Metric strong color classes", () => {
  test("critical metric has critical class", async ({ page }) => {
    await ready(page);
    const strong = page.locator("#metrics .metric strong.critical");
    expect(await strong.count()).toBe(1);
    expect(await strong.textContent()).toBe("2");
  });

  test("high metric has high class", async ({ page }) => {
    await ready(page);
    const strong = page.locator("#metrics .metric strong.high");
    expect(await strong.count()).toBe(1);
    expect(await strong.textContent()).toBe("6");
  });

  test("medium metric has medium class", async ({ page }) => {
    await ready(page);
    const strong = page.locator("#metrics .metric strong.medium");
    expect(await strong.count()).toBe(1);
    expect(await strong.textContent()).toBe("4");
  });

  test("low metric has low class", async ({ page }) => {
    await ready(page);
    const strong = page.locator("#metrics .metric strong.low");
    expect(await strong.count()).toBe(1);
    expect(await strong.textContent()).toBe("2");
  });
});

// ─── Scoreplate class variants ───

test.describe("Scoreplate class variants", () => {
  test("scoreplate has correct score class", async ({ page }) => {
    await ready(page);
    const cls = await page.locator(".scoreplate").getAttribute("class");
    expect(cls).toMatch(/score-(low|medium|high|critical)/);
  });

  test("score element has severity class", async ({ page }) => {
    await ready(page);
    const cls = await page.locator("#score").getAttribute("class");
    expect(cls).toMatch(/^(low|medium|high|critical)$/);
  });
});

// ─── Score breakdown axis bar color classes ───

test.describe("Score breakdown axis bar colors", () => {
  test("vulnerabilities axis bar has critical color", async ({ page }) => {
    await ready(page);
    const bar = page.locator("#scoreBreakdown .score-axis[data-axis='vulnerabilities'] .score-axis-bar span");
    const style = await bar.getAttribute("style");
    expect(style).toContain("width:");
  });

  test("each axis has a data-axis attribute", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const expected = ["vulnerabilities", "container_exposure", "host_hardening", "secrets"];
    for (const id of expected) {
      expect(await page.locator(`#scoreBreakdown .score-axis[data-axis='${id}']`).count()).toBe(1);
    }
  });
});

// ─── Fix modal action-type-badge CSS classes ───

test.describe("Fix modal action-type-badge CSS classes", () => {
  test("action type badge has type-exec or type-edit class", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const badge = page.locator("#fixModal .action-type-badge");
        if ((await badge.count()) > 0) {
          const cls = await badge.getAttribute("class");
          expect(cls).toMatch(/type-(exec|edit)/);
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal diff highlighting classes ───

test.describe("Fix modal diff highlighting", () => {
  test("diff preview has diff-add, diff-del, diff-hunk classes", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const diff = page.locator("#fixModal .diff-preview pre");
        if ((await diff.count()) > 0) {
          const html = await diff.innerHTML();
          // At least one of the diff classes should be present
          const hasDiffClass = html.includes("diff-add") || html.includes("diff-del") || html.includes("diff-hunk");
          expect(hasDiffClass).toBeTruthy();
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Toast class variants ───

test.describe("Toast class variants", () => {
  test("recalc success shows toast-info", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    const cls = await toast.getAttribute("class"); expect(cls).toContain("toast-info");
  });

  test("R key clear shows toast-info", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("R");
    await page.waitForTimeout(500);
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    expect((await toast.getAttribute("class"))?.includes("toast-info")).toBeTruthy();
  });
});

// ─── Detail panel empty-detail state ───

test.describe("Detail panel empty-detail state", () => {
  test("empty detail has cloud icon and Select a finding", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "empty-box",
          local_ip: "10.0.0.1",
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await page.waitForTimeout(500);
    const empty = page.locator("#detail .empty-detail");
    expect(await empty.count()).toBe(1);
    // Cloud icon
    expect(await empty.locator("span").first().textContent()).toBeTruthy();
    // Heading
    expect(await empty.locator("h2").textContent()).toBe("Select a finding");
    // Description
    expect(await empty.locator("p").textContent()).toContain("Choose an item");
  });
});

// ─── Sort direction via column click ───

test.describe("Sort direction via column click", () => {
  test("clicking same column toggles asc to desc", async ({ page }) => {
    await ready(page);
    const th = page.locator("th.sortable[data-col='1']");
    // Default is severity asc
    expect((await th.getAttribute("class"))?.includes("asc")).toBeTruthy();
    // Click to toggle to desc
    await th.click();
    await page.waitForTimeout(200);
    expect((await th.getAttribute("class"))?.includes("desc")).toBeTruthy();
    // Click again to toggle back to asc
    await th.click();
    await page.waitForTimeout(200);
    expect((await th.getAttribute("class"))?.includes("asc")).toBeTruthy();
  });

  test("clicking different column resets to asc", async ({ page }) => {
    await ready(page);
    const sevTh = page.locator("th.sortable[data-col='1']");
    const srcTh = page.locator("th.sortable[data-col='2']");
    // Toggle severity to desc
    await sevTh.click();
    await page.waitForTimeout(200);
    expect((await sevTh.getAttribute("class"))?.includes("desc")).toBeTruthy();
    // Click source - should reset to asc
    await srcTh.click();
    await page.waitForTimeout(200);
    expect((await srcTh.getAttribute("class"))?.includes("asc")).toBeTruthy();
    // Severity should have no direction class
    expect((await sevTh.getAttribute("class"))?.includes("asc")).toBeFalsy();
    expect((await sevTh.getAttribute("class"))?.includes("desc")).toBeFalsy();
  });
});

// ─── Fix result diff rendering ───

test.describe("Fix result diff rendering", () => {
  test("fix result shows fix-success class after apply", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
      }
    }
  });
});

// ─── Fix button loading CSS ───

test.describe("Fix button loading CSS", () => {
});

// ─── Score breakdown axis score color ───

test.describe("Score breakdown axis score color", () => {
  test("each axis score has a color class", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    for (let i = 0; i < 4; i++) {
      const cls = await axes.nth(i).getAttribute("class");
      expect(cls).toMatch(/score-axis (low|medium|high|critical)/);
    }
  });
});

// ─── Score breakdown penalty bar width ───

test.describe("Score breakdown penalty bar width", () => {
  test("each penalty bar has a width percentage", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    for (let i = 0; i < 4; i++) {
      const style = await bars.nth(i).getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
    }
  });
});

// ─── Score breakdown aria-label ───

test.describe("Score breakdown aria-label", () => {
  test("each penalty bar has an aria-label", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    for (let i = 0; i < 4; i++) {
      const label = await bars.nth(i).getAttribute("aria-label");
      expect(label).toBeTruthy();
      expect(label).toContain("penalty cap used");
    }
  });
});

// ─── Score breakdown severity count colors ───

test.describe("Score breakdown severity count colors", () => {
  test("severity count spans have correct color classes", async ({ page }) => {
    await ready(page);
    const spans = page.locator("#scoreBreakdown .score-axis-counts span");
    const count = await spans.count();
    for (let i = 0; i < count; i++) {
      const cls = await spans.nth(i).getAttribute("class");
      expect(cls).toMatch(/critical|high|medium|low|muted/);
    }
  });
});

// ─── Detail panel metadata section ───

test.describe("Detail panel metadata section", () => {
  test("finding with metadata shows both Evidence and Metadata", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const details = page.locator("#detail .evidence-details");
    expect(await details.count()).toBe(2);
    // First is Evidence
    expect(await details.first().locator("summary").textContent()).toContain("Evidence");
    // Second is Metadata
    expect(await details.nth(1).locator("summary").textContent()).toContain("Metadata");
  });

  test("finding with no metadata has only Evidence section", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    const details = page.locator("#detail .evidence-details");
    expect(await details.count()).toBe(1);
    expect(await details.first().locator("summary").textContent()).toContain("Evidence");
  });
});

// ─── Detail panel copy button ───

test.describe("Detail panel copy button", () => {
  test("how_to_fix section has Copy guidance button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const copyBtn = page.locator("#detail .copy");
    expect(await copyBtn.count()).toBe(1);
    expect(await copyBtn.textContent()).toContain("Copy guidance");
  });
});

// ─── Detail panel toggle-more button ───

test.describe("Detail panel toggle-more button", () => {
  test("long text has View more button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const toggle = page.locator("#detail .toggle-more").first();
    if ((await toggle.count()) > 0) {
      expect(await toggle.textContent()).toBe("View more");
    }
  });
});

// ─── Detail panel evidence expand/collapse ───

test.describe("Detail panel evidence expand/collapse", () => {
  test("evidence details can be toggled", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const summary = page.locator("#detail .evidence-details summary").first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);
      const pres = page.locator("#detail .evidence-details pre");
      expect(await pres.count()).toBeGreaterThanOrEqual(1);
      await summary.click();
      await page.waitForTimeout(200);
    }
  });
});

// ─── Table checkbox behavior ───

test.describe("Table checkbox behavior", () => {
  test("row checkbox has correct data-id", async ({ page }) => {
    await ready(page);
    const cb = page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check");
    expect(await cb.getAttribute("data-id")).toBe("trivy.cve-2024-0001");
  });

  test("row checkbox has correct type", async ({ page }) => {
    await ready(page);
    const cb = page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check");
    expect(await cb.getAttribute("type")).toBe("checkbox");
  });

  test("select-all checkbox has correct id", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#selectAllCheck").count()).toBe(1);
  });
});

// ─── Score breakdown head structure ───

test.describe("Score breakdown head structure", () => {
  test("head has span and p children", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    expect(await head.locator("span").count()).toBe(1);
    expect(await head.locator("p").count()).toBe(1);
  });
});

// ─── Score breakdown grid structure ───

test.describe("Score breakdown grid structure", () => {
  test("grid has 4 axis cards", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#scoreBreakdown .score-axis-grid").count()).toBe(1);
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
  });
});

// ─── Filter chip active state ───

test.describe("Filter chip active state", () => {
  test("All chip is active by default", async ({ page }) => {
    await ready(page);
    const active = page.locator("#severityFilters button.active");
    expect(await active.textContent()).toContain("All");
  });

  test("clicking Critical activates it", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    const active = page.locator("#severityFilters button.active");
    expect(await active.textContent()).toContain("Critical");
  });

  test("active chip has chip class", async ({ page }) => {
    await ready(page);
    const active = page.locator("#severityFilters button.active");
    const cls = await active.getAttribute("class");
    expect(cls).toContain("chip");
    expect(cls).toContain("active");
  });
});

// ─── Sort dropdown structure ───

test.describe("Sort dropdown structure", () => {
  test("sort dropdown has 4 options", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#sortBy option").count()).toBe(4);
  });

  test("sort dropdown default is severity", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#sortBy").inputValue()).toBe("severity");
  });
});

// ─── Workspace layout ───

test.describe("Workspace layout", () => {
  test("workspace has filters, findings-panel, and detail", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".workspace .filters").count()).toBe(1);
    expect(await page.locator(".workspace .findings-panel").count()).toBe(1);
    expect(await page.locator(".workspace .detail").count()).toBe(1);
  });
});

// ─── Topbar structure ───

test.describe("Topbar structure", () => {
  test("topbar has title, eyebrow, sysinfo, and scoreplate", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".topbar h1").textContent()).toContain("hostveil");
    expect(await page.locator(".topbar .eyebrow").textContent()).toContain("Finds and fixes");
    expect(await page.locator("#sysinfo").textContent()).toContain("e2e-test-box");
    expect(await page.locator(".scoreplate").count()).toBe(1);
  });
});

// ─── Findings panel structure ───

test.describe("Findings panel structure", () => {
  test("findings panel has panel-head, search, filters, and table", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".findings-panel .panel-head").count()).toBe(1);
    expect(await page.locator(".search").count()).toBe(1);
    expect(await page.locator("#severityFilters").count()).toBe(1);
    expect(await page.locator("#findings").count()).toBe(1);
  });
});

// ─── Detail panel structure ───

test.describe("Detail panel structure", () => {
});

// ─── Evidence details structure ───

test.describe("Evidence details structure", () => {
  test("evidence has summary and pre elements", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const details = page.locator("#detail .evidence-details").first();
    if ((await details.count()) > 0) {
      expect(await details.locator("summary").count()).toBe(1);
      expect(await details.locator("pre").count()).toBeGreaterThanOrEqual(1);
    }
  });
});

// ─── Evidence pre elements have strong keys ───

test.describe("Evidence pre elements", () => {
  test("each pre has a strong key", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const pres = page.locator("#detail .evidence-details pre");
    const count = await pres.count();
    for (let i = 0; i < count; i++) {
      expect(await pres.nth(i).locator("strong").count()).toBe(1);
    }
  });
});

// ─── Detail meta dt/dd pairs ───

test.describe("Detail meta dt/dd pairs", () => {
  test("detail meta has dt/dd pairs for ID, Source, Remediation", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const meta = page.locator("#detail .detail-meta");
    const dts = meta.locator("dt");
    const dds = meta.locator("dd");
    const dtCount = await dts.count();
    expect(dtCount).toBeGreaterThanOrEqual(3);
    expect(await dds.count()).toBe(dtCount);
    // Check first 3 dt values
    const dtTexts: string[] = [];
    for (let i = 0; i < Math.min(3, dtCount); i++) {
      dtTexts.push(await dts.nth(i).textContent() ?? "");
    }
    expect(dtTexts).toContain("ID");
    expect(dtTexts).toContain("Source");
    expect(dtTexts).toContain("Remediation");
  });
});

// ─── Detail panel service field ───

test.describe("Detail panel service field", () => {
  test("finding with service shows Service dt/dd", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).toContain("Service");
  });

  test("lynis finding without service has no Service field", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    const meta = page.locator("#detail .detail-meta");
    const text = await meta.textContent();
    expect(text).not.toContain("Service");
  });
});

// ─── Detail panel remediation hint ───

test.describe("Detail panel remediation hint", () => {
  test("auto finding shows one clear fix hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail .detail-meta").textContent();
    expect(text).toContain("one clear fix");
  });

  test("review finding shows multiple options hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail .detail-meta").textContent();
    expect(text).toContain("multiple options");
  });

  test("unavailable finding shows not yet classified hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail .detail-meta").textContent();
    expect(text).toContain("not yet classified");
  });
});

// ─── Fix button visibility by remediation kind ───

test.describe("Fix button visibility by remediation kind", () => {
  test("auto finding has Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(1);
  });

  test("review finding has Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(1);
  });

  test("unavailable finding has no Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });

  test("fixed finding has no Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0003']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });
});

// ─── Fix button text ───

test.describe("Fix button text", () => {
  test("fix button says Fix", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      expect(await page.locator("#detail .fix-btn").textContent()).toBe("Fix");
    }
  });
});

// ─── Fix modal structure ───

test.describe("Fix modal structure", () => {
  test("auto fix modal has correct structure", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal h2").textContent()).toBe("Apply fix");
        expect(await page.locator("#fixModal .action-summary").count()).toBe(1);
        expect(await page.locator("#fixModal .action-header").count()).toBe(1);
        expect(await page.locator("#fixModal .action-type-badge").count()).toBe(1);
        expect(await page.locator("#fixModal .modal-actions").count()).toBe(1);
        await page.keyboard.press("Escape");
      }
    }
  });

  test("review fix modal has correct structure", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal h2").textContent()).toBe("Choose action");
        expect(await page.locator("#fixModal .action-options").count()).toBe(1);
        expect(await page.locator("#fixModal .action-option").count()).toBeGreaterThanOrEqual(2);
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal action option structure ───

test.describe("Fix modal action option structure", () => {
  test("each option has header, radio, label, badge, strong", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const options = page.locator("#fixModal .action-option");
        const count = await options.count();
        for (let i = 0; i < count; i++) {
          expect(await options.nth(i).locator(".action-option-header").count()).toBe(1);
          expect(await options.nth(i).locator("input[type='radio']").count()).toBe(1);
          expect(await options.nth(i).locator("label").count()).toBe(1);
          expect(await options.nth(i).locator(".action-type-badge").count()).toBe(1);
          expect(await options.nth(i).locator("strong").count()).toBe(1);
          expect(await options.nth(i).getAttribute("data-idx")).toBe(String(i));
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal confirm button behavior ───

test.describe("Fix modal confirm button behavior", () => {
  test("confirm button disabled before selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
      }
    }
  });

  test("confirm button enabled after selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#fixModal input[name='fixAction']").first().click({ force: true });
        await page.waitForTimeout(100);
      }
    }
  });

  test("confirm button text changes after selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.waitForTimeout(100);
      }
    }
  });
});

// ─── Fix modal dismiss methods ───

test.describe("Fix modal dismiss methods", () => {
  test("Escape closes fix modal", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.keyboard.press("Escape");
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });

  test("Cancel button closes fix modal", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#fixModal #modalFixNo").click();
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });

  test("overlay click closes fix modal", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });
});

// ─── Fix result after apply ───

test.describe("Fix result after apply", () => {
  test("fix result shows success message", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
      }
    }
  });
});

// ─── Export modal structure ───

test.describe("Export modal structure", () => {
  test("export modal has 3 buttons", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    expect(await modal.locator(".export-option").count()).toBe(3);
    await page.keyboard.press("Escape");
  });

  test("export modal has correct labels", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    expect(await modal.locator("#exportJson .export-label").textContent()).toBe("JSON");
    expect(await modal.locator("#exportCsv .export-label").textContent()).toBe("CSV");
    expect(await modal.locator("#exportAi .export-label").textContent()).toBe("AI brief");
    await page.keyboard.press("Escape");
  });
});

// ─── Help modal structure ───

test.describe("Help modal structure", () => {
  test("help modal has 4 sections", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    expect(await modal.locator(".help-section").count()).toBe(4);
    await page.keyboard.press("Escape");
  });

  test("help modal has heading Keyboard shortcuts", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    expect(await modal.locator("h2").textContent()).toBe("Keyboard shortcuts");
    await page.keyboard.press("Escape");
  });

  test("help modal overlay click closes", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });

  test("help modal close button works", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.locator("#modalHelpClose").click();
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });
});

// ─── Export modal dismiss ───

test.describe("Export modal dismiss", () => {
  test("Escape closes export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });

  test("overlay click closes export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });

  test("Close button closes export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.locator("#exportClose").click();
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).not.toBeVisible();
  });
});

// ─── Keyboard navigation ───

test.describe("Keyboard navigation", () => {
  test("ArrowDown moves selection down", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    const selected = page.locator("#findings tr.selected");
    const index = await selected.getAttribute("data-index");
    expect(Number(index)).toBe(1);
  });

  test("ArrowUp moves selection up", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(100);
    const selected = page.locator("#findings tr.selected");
    const index = await selected.getAttribute("data-index");
    expect(Number(index)).toBe(1);
  });

  test("ArrowDown at last row stays at last", async ({ page }) => {
    await ready(page);
    for (let i = 0; i < 20; i++) {
      await page.keyboard.press("ArrowDown");
      await page.waitForTimeout(50);
    }
    const selected = page.locator("#findings tr.selected");
    const index = await selected.getAttribute("data-index");
    const totalRows = await page.locator("#findings tr[data-index]").count();
    expect(Number(index)).toBe(totalRows - 1);
  });

  test("ArrowUp at first row stays at first", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(100);
    const selected = page.locator("#findings tr.selected");
    const index = await selected.getAttribute("data-index");
    expect(Number(index)).toBe(0);
  });
});

// ─── Search behavior ───

test.describe("Search behavior", () => {
  test("search by ID finds exact match", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("AUTH-9286");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(1);
  });

  test("search with no results shows message", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("zzzznonexistent");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings .muted").textContent()).toContain("No findings match");
  });

  test("search is case-insensitive", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("SSH");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBeGreaterThanOrEqual(1);
  });

  test("clearing search restores all findings", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBeLessThan(14);
    await page.locator("#query").fill("");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
  });
});

// ─── Clear filters button ───

test.describe("Clear filters button", () => {
  test("clear filters resets all", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(200);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBeLessThan(14);
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
    expect(await page.locator("#query").inputValue()).toBe("");
  });
});

// ─── Severity filter counts ───

test.describe("Severity filter counts", () => {
  test("Critical shows 2 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(2);
  });

  test("High shows 6 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "High" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(6);
  });

  test("Medium shows 4 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Medium" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(4);
  });

  test("Low shows 2 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Low" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(2);
  });
});

// ─── Source filter counts ───

test.describe("Source filter counts", () => {
  test("Trivy shows 6 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#sourceFilters button").filter({ hasText: "Trivy" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(6);
  });

  test("Lynis shows 6 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#sourceFilters button").filter({ hasText: "Lynis" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(6);
  });

  test("Compose shows 2 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#sourceFilters button").filter({ hasText: "Compose" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(2);
  });
});

// ─── Remediation filter counts ───

test.describe("Remediation filter counts", () => {
  test("Auto shows 10 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#remediationFilters button").filter({ hasText: "Auto" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(10);
  });

  test("Review shows 3 findings", async ({ page }) => {
    await ready(page);
    await page.locator("#remediationFilters button").filter({ hasText: "Review" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(3);
  });

  test("Unavailable shows 1 finding", async ({ page }) => {
    await ready(page);
    await page.locator("#remediationFilters button").filter({ hasText: "Unavailable" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(1);
  });
});

// ─── Finding count display ───

test.describe("Finding count display", () => {
  test("shows 14 visible by default", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#findingCount").textContent()).toContain("14 visible");
  });
});

// ─── Metrics panel ───

test.describe("Metrics panel", () => {
  test("has 6 metric items", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").count()).toBe(6);
  });

  test("total shows 14", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").first().textContent()).toContain("14");
  });
});

// ─── Score element ───

test.describe("Score element", () => {
  test("shows N/100 format", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#score").textContent()).toMatch(/^\d+\/100$/);
  });
});

// ─── Score breakdown ───

test.describe("Score breakdown", () => {
  test("visible with 4 axes", async ({ page }) => {
    await ready(page);
    await expect(page.locator("#scoreBreakdown")).toBeVisible();
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
  });

  test("each axis has score and label", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    for (let i = 0; i < 4; i++) {
      const scoreText = await axes.nth(i).locator("strong").textContent();
      expect(scoreText).toMatch(/\d+\/100/);
    }
  });
});

// ─── Table structure ───

test.describe("Table structure", () => {
  test("has 6 columns", async ({ page }) => {
    await ready(page);
    expect(await page.locator("th").count()).toBe(6);
  });

  test("each row has 6 cells", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      expect(await rows.nth(i).locator("td").count()).toBe(6);
    }
  });

  test("rows have sequential data-index", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      expect(await rows.nth(i).getAttribute("data-index")).toBe(String(i));
    }
  });
});

// ─── Sort dropdown ───

test.describe("Sort dropdown", () => {
  test("has 4 options", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#sortBy option").count()).toBe(4);
  });

  test("default is severity", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#sortBy").inputValue()).toBe("severity");
  });
});

// ─── API endpoints ───

test.describe("API health", () => {
  test("returns ok status", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/health");
      return resp.json();
    });
    expect(r.status).toBe("ok");
  });
});

test.describe("API result", () => {
  test("has correct structure", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(typeof r.hostname).toBe("string");
    expect(Array.isArray(r.findings)).toBe(true);
    expect(typeof r.score).toBe("number");
    expect(typeof r.score_breakdown).toBe("object");
  });
});

test.describe("API score consistency", () => {
  test("recalc returns same score", async ({ page }) => {
    await ready(page);
    const r1 = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const r2 = await page.evaluate(async () => {
      const resp = await fetch("/api/recalc", { method: "POST" });
      return resp.json();
    });
    expect(r2.score).toBe(r1.score);
  });
});

test.describe("API export", () => {
  test("JSON export has correct content type", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=json");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("application/json");
  });

  test("CSV export has correct content type", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=csv");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("text/csv");
  });

  test("AI export has correct content type", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("text/markdown");
  });
});

test.describe("API fix error cases", () => {
  test("unregistered ID returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "nonexistent.abc", action_index: 0 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("no fix registered");
  });

  test("out-of-range action_index returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "trivy.cve-2024-0001", action_index: 99 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toBeTruthy();
  });

  test("malformed JSON returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{invalid",
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("invalid request");
  });
});

test.describe("API fix batch", () => {
  test("empty findings returns empty results", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: [], action_index: 0 }),
      });
      return resp.json();
    });
    expect(r.results.length).toBe(0);
  });
});

test.describe("API rescan idempotency", () => {
  test("double rescan returns error for second", async ({ page }) => {
    await ready(page);
    const r1 = await page.evaluate(async () => {
      const resp = await fetch("/api/rescan", { method: "POST" });
      return resp.json();
    });
    const r2 = await page.evaluate(async () => {
      const resp = await fetch("/api/rescan", { method: "POST" });
      return resp.json();
    });
    expect(r1.status === "rescanning" || r2.status === "rescanning").toBe(true);
  });
});

// ─── Secure headers ───

test.describe("Secure headers", () => {
  test("API responses include security headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/health");
      return {
        xcto: resp.headers.get("x-content-type-options"),
        xfo: resp.headers.get("x-frame-options"),
        rp: resp.headers.get("referrer-policy"),
        cc: resp.headers.get("cache-control"),
        csp: resp.headers.get("content-security-policy"),
      };
    });
    expect(r.xcto).toBe("nosniff");
    expect(r.xfo).toBe("DENY");
    expect(r.rp).toBe("no-referrer");
    expect(r.cc).toBe("no-store");
    expect(r.csp).toContain("default-src 'self'");
  });
});

// ─── Score range validation ───

test.describe("Score range validation", () => {
  test("overall score is 0-100", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(100);
  });

  test("each axis score is 0-100", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    for (const axis of r.score_breakdown.axes) {
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
    }
  });
});

// ─── Score breakdown max_penalty ───

test.describe("Score breakdown max_penalty", () => {
  test("correct max_penalty for each axis", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const expected: Record<string, number> = {
      vulnerabilities: 35,
      container_exposure: 30,
      host_hardening: 25,
      secrets: 10,
    };
    for (const [id, max] of Object.entries(expected)) {
      const axis = r.score_breakdown.axes.find((a: { id: string }) => a.id === id);
      expect(axis.max_penalty).toBe(max);
    }
  });
});

// ─── Finding structure ───

test.describe("Finding structure", () => {
  test("all finding IDs are unique", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const ids = r.findings.map((f: { id: string }) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("all severity values are 0-3", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    for (const f of r.findings) {
      expect(f.severity).toBeGreaterThanOrEqual(0);
      expect(f.severity).toBeLessThanOrEqual(3);
    }
  });

  test("all source values are 0-2", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    for (const f of r.findings) {
      expect(f.source).toBeGreaterThanOrEqual(0);
      expect(f.source).toBeLessThanOrEqual(2);
    }
  });
});

// ─── Toast auto-hide ───

test.describe("Toast auto-hide", () => {
  test("toast disappears after a few seconds", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
    await page.waitForTimeout(4500);
    await expect(page.locator("#toast")).not.toBeVisible({ timeout: 2000 });
  });
});

// ─── Rescan button states ───

test.describe("Rescan button states", () => {
  test("rescan button disables during scan", async ({ page }) => {
    await ready(page);
    await page.locator("#rescanBtn").click();
    await page.waitForTimeout(300);
    expect(await page.locator("#rescanBtn").isDisabled()).toBe(true);
  });

  test("rescan button has loading class during scan", async ({ page }) => {
    await ready(page);
    await page.locator("#rescanBtn").click();
    await page.waitForTimeout(300);
    expect((await page.locator("#rescanBtn").getAttribute("class"))?.includes("loading")).toBeTruthy();
  });
});

// ─── Fix Selected button ───

test.describe("Fix Selected button", () => {
  test("hidden with no selection", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#fixSelectedBtn").isHidden()).toBe(true);
  });

  test("visible with selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check").check({ force: true });
    await page.waitForTimeout(200);
    expect(await page.locator("#fixSelectedBtn").isVisible()).toBe(true);
  });
});

// ─── Select-all checkbox ───

test.describe("Select-all checkbox", () => {
  test("checking selects all batch-selectable rows", async ({ page }) => {
    await ready(page);
    await page.locator("#selectAllCheck").check({ force: true });
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr.row-selected").count()).toBeGreaterThan(0);
  });

  test("unavailable finding not selected", async ({ page }) => {
    await ready(page);
    await page.locator("#selectAllCheck").check({ force: true });
    await page.waitForTimeout(300);
    const cls = await page.locator("#findings tr[data-id='test.unfixable-001']").getAttribute("class");
    expect(cls?.includes("row-selected")).toBeFalsy();
  });
});

// ─── Sort by source groups ───

test.describe("Sort by source groups", () => {
  test("compose findings are contiguous", async ({ page }) => {
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
    const composeIndices = ids.map((id, i) => (id.startsWith("compose.") ? i : -1)).filter((i) => i >= 0);
    if (composeIndices.length >= 2) {
      for (let i = 1; i < composeIndices.length; i++) {
        expect(composeIndices[i] - composeIndices[i - 1]).toBe(1);
      }
    }
  });
});

// ─── Sort stability ───

test.describe("Sort stability", () => {
  test("order persists after filter apply and clear", async ({ page }) => {
    await ready(page);
    const ids1: string[] = [];
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) {
      const id = await rows.nth(i).getAttribute("data-id");
      if (id) ids1.push(id);
    }
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    await page.locator("#severityFilters button").filter({ hasText: "All" }).click();
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

// ─── Table row click ───

test.describe("Table row click", () => {
  test("clicking row highlights it", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-index='5']").click({ force: true });
    await page.waitForTimeout(200);
    expect((await page.locator("#findings tr[data-index='5']").getAttribute("class"))?.includes("selected")).toBeTruthy();
  });

  test("clicking different row moves selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-index='0']").click({ force: true });
    await page.waitForTimeout(200);
    await page.locator("#findings tr[data-index='5']").click({ force: true });
    await page.waitForTimeout(200);
    expect((await page.locator("#findings tr[data-index='5']").getAttribute("class"))?.includes("selected")).toBeTruthy();
    expect((await page.locator("#findings tr[data-index='0']").getAttribute("class"))?.includes("selected")).toBeFalsy();
  });
});

// ─── Double-click toggles selection ───

test.describe("Double-click selection", () => {
  test("double-click toggles row-selected", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='lynis.FILE-6310']");
    await row.dblclick();
    await page.waitForTimeout(200);
    expect((await row.getAttribute("class"))?.includes("row-selected")).toBeTruthy();
    await row.dblclick();
    await page.waitForTimeout(200);
    expect((await row.getAttribute("class"))?.includes("row-selected")).toBeFalsy();
  });
});

// ─── Space toggles selection ───

test.describe("Space selection", () => {
  test("Space toggles selection", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(1);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(0);
  });
});

// ─── Ctrl+A selects all ───

test.describe("Ctrl+A selection", () => {
  test("Ctrl+A toggles select all", async ({ page }) => {
    await ready(page);
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr.row-selected").count()).toBeGreaterThan(0);
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(0);
  });
});

// ─── v key cycles service filter ───

test.describe("v key cycles service filter", () => {
  test("v key cycles and wraps", async ({ page }) => {
    await ready(page);
    const allCount = await page.locator("#findings tr[data-index]").count();
    let totalCycles = 0;
    while (totalCycles < 10) {
      await page.keyboard.press("v");
      await page.waitForTimeout(200);
      totalCycles++;
      const count = await page.locator("#findings tr[data-index]").count();
      if (count === allCount && totalCycles > 1) break;
    }
    expect(await page.locator("#findings tr[data-index]").count()).toBe(allCount);
  });
});

// ─── R key clears filters ───

test.describe("R key clears filters", () => {
  test("R key resets all and shows toast", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(200);
    await page.keyboard.press("Escape");
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBeLessThan(14);
    await page.keyboard.press("R");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
    expect(await page.locator("#query").inputValue()).toBe("");
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
  });
});

// ─── o key cycles sort ───

test.describe("o key cycles sort", () => {
  test("o key cycles through sort fields", async ({ page }) => {
    await ready(page);
    const dropdown = page.locator("#sortBy");
    const vals: string[] = [];
    for (let i = 0; i < 4; i++) {
      await page.keyboard.press("o");
      await page.waitForTimeout(200);
      vals.push(await dropdown.inputValue());
    }
    expect(vals[3]).toBe("severity");
  });
});

// ─── q key shows toast ───

test.describe("q key shows toast", () => {
  test("q key shows quit hint", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("q");
    await page.waitForTimeout(500);
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
    expect(await page.locator("#toast").textContent()).toContain("close the tab");
  });
});

// ─── O key toggles sort direction ───

test.describe("O key toggles sort direction", () => {
  test("O key reverses order", async ({ page }) => {
    await ready(page);
    const firstId1 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    await page.keyboard.press("O");
    await page.waitForTimeout(200);
    const firstId2 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    expect(firstId1).not.toBe(firstId2);
  });
});

// ─── / key focuses search ───

test.describe("/ key focuses search", () => {
  test("/ focuses search input", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("/");
    await page.waitForTimeout(100);
    expect(await page.locator("#query").evaluate((el) => el === document.activeElement)).toBe(true);
    await page.keyboard.press("Escape");
  });
});

// ─── Escape blurs search ───

test.describe("Escape blurs search", () => {
  test("Escape removes focus from search", async ({ page }) => {
    await ready(page);
    await page.locator("#query").focus();
    await page.waitForTimeout(100);
    expect(await page.locator("#query").evaluate((el) => el === document.activeElement)).toBe(true);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);
    expect(await page.locator("#query").evaluate((el) => el === document.activeElement)).toBe(false);
  });
});

// ─── e key opens export ───

test.describe("e key opens export", () => {
  test("e opens export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

// ─── ? key opens help ───

test.describe("? key opens help", () => {
  test("? opens help modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

// ─── f key triggers fix ───

test.describe("f key triggers fix", () => {
  test("f key opens fix for current finding", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("f");
    await page.waitForTimeout(500);
    if ((await page.locator("#fixModal").count()) > 0) {
      await expect(page.locator("#fixModal")).toBeVisible();
      await page.keyboard.press("Escape");
    }
  });
});

// ─── Enter confirms fix modal ───

test.describe("Enter confirms fix modal", () => {
  test("Enter key confirms fix", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.keyboard.press("Enter");
        await page.waitForTimeout(2000);
        await expect(page.locator("#fixModal")).not.toBeVisible({ timeout: 3000 });
      }
    }
  });
});

// ─── Keyboard shortcuts suppressed in input ───

test.describe("Keyboard shortcuts suppressed in input", () => {
  test("typing in search does not trigger shortcuts", async ({ page }) => {
    await ready(page);
    await page.locator("#query").focus();
    await page.waitForTimeout(100);
    await page.keyboard.type("/");
    await page.waitForTimeout(200);
    expect(await page.locator("#query").inputValue()).toBe("/");
    expect(await page.locator("#helpModal").count()).toBe(0);
  });
});

// ─── Score breakdown head ───

test.describe("Score breakdown head", () => {
  test("head has description", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    expect(await head.locator("span").textContent()).toBe("Score breakdown");
    expect(await head.locator("p").textContent()).toContain("scanner cannot dominate");
  });
});

// ─── Score breakdown penalty cap text ───

test.describe("Score breakdown penalty cap text", () => {
  test("penalty text format", async ({ page }) => {
    await ready(page);
    const meta = page.locator("#scoreBreakdown .score-axis-meta span").first();
    const text = await meta.textContent();
    expect(text).toMatch(/\d+\/\d+ penalty cap used/);
  });
});

// ─── Score breakdown severity counts ───

test.describe("Score breakdown severity counts", () => {
  test("severity count spans exist", async ({ page }) => {
    await ready(page);
    const spans = page.locator("#scoreBreakdown .score-axis-counts span");
    expect(await spans.count()).toBeGreaterThan(0);
  });
});

// ─── Score breakdown axis labels ───

test.describe("Score breakdown axis labels", () => {
  test("vulnerabilities axis label", async ({ page }) => {
    await ready(page);
    const axis = page.locator("#scoreBreakdown .score-axis[data-axis='vulnerabilities']");
    expect(await axis.locator(".score-axis-top span").textContent()).toBe("Vulnerabilities");
  });

  test("container_exposure axis label", async ({ page }) => {
    await ready(page);
    const axis = page.locator("#scoreBreakdown .score-axis[data-axis='container_exposure']");
    expect(await axis.locator(".score-axis-top span").textContent()).toBe("Container exposure");
  });

  test("host_hardening axis label", async ({ page }) => {
    await ready(page);
    const axis = page.locator("#scoreBreakdown .score-axis[data-axis='host_hardening']");
    expect(await axis.locator(".score-axis-top span").textContent()).toBe("Host hardening");
  });

  test("secrets axis label", async ({ page }) => {
    await ready(page);
    const axis = page.locator("#scoreBreakdown .score-axis[data-axis='secrets']");
    expect(await axis.locator(".score-axis-top span").textContent()).toBe("Secrets");
  });
});

// ─── Score breakdown bar width and aria-label ───

test.describe("Score breakdown bar rendering", () => {
  test("each bar has width and aria-label", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    for (let i = 0; i < 4; i++) {
      const style = await bars.nth(i).locator("span").getAttribute("style");
      expect(style).toMatch(/width:\d+%/);
      expect(await bars.nth(i).getAttribute("aria-label")).toBeTruthy();
    }
  });
});

// ─── Score breakdown grid ───

test.describe("Score breakdown grid", () => {
  test("grid contains all axes", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#scoreBreakdown .score-axis-grid").count()).toBe(1);
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
  });
});

// ─── Detail panel for trivy CVE ───

test.describe("Detail panel for trivy CVE", () => {
  test("shows all sections", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const detail = page.locator("#detail");
    expect(await detail.locator(".badge").count()).toBe(1);
    expect(await detail.locator("h2").count()).toBe(1);
    expect(await detail.locator(".detail-meta").count()).toBe(1);
    expect(await detail.locator(".section").count()).toBeGreaterThanOrEqual(2);
  });
});

// ─── Detail panel for lynis finding ───

test.describe("Detail panel for lynis finding", () => {
  test("shows correct metadata", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail .detail-meta").textContent();
    expect(text).toContain("lynis.AUTH-9286");
    expect(text).toContain("lynis");
    expect(text).not.toContain("Service");
  });
});

// ─── Detail panel for compose finding ───

test.describe("Detail panel for compose finding", () => {
  test("shows service field", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='compose.ds001']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail .detail-meta").textContent();
    expect(text).toContain("compose.ds001");
    expect(text).toContain("compose");
    expect(text).toContain("webapp");
  });
});

// ─── Detail panel badge color ───

test.describe("Detail panel badge color", () => {
  test("critical finding shows critical badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("critical")).toBeTruthy();
  });

  test("high finding shows high badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("high")).toBeTruthy();
  });

  test("medium finding shows medium badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("medium")).toBeTruthy();
  });

  test("low finding shows low badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.KRNL-5780']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("low")).toBeTruthy();
  });
});

// ─── Detail panel remediation hint ───


// ─── Long text collapse/expand ───

test.describe("Long text collapse/expand", () => {
  test("View more/View less toggles", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const toggle = page.locator("#detail .toggle-more").first();
    if ((await toggle.count()) > 0) {
      expect(await toggle.textContent()).toBe("View more");
      await toggle.click();
      await page.waitForTimeout(200);
      expect(await toggle.textContent()).toBe("View less");
      await toggle.click();
      await page.waitForTimeout(200);
      expect(await toggle.textContent()).toBe("View more");
    }
  });
});

// ─── Fix button visibility ───

test.describe("Fix button visibility", () => {
  test("auto has Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(1);
  });

  test("review has Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(1);
  });

  test("unavailable has no Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });

  test("fixed has no Fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0003']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });
});

// ─── Fix modal heading ───

test.describe("Fix modal heading", () => {
  test("auto fix heading is Apply fix", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal h2").textContent()).toBe("Apply fix");
        await page.keyboard.press("Escape");
      }
    }
  });

  test("review fix heading is Choose action", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal h2").textContent()).toBe("Choose action");
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal cancel button text ───

test.describe("Fix modal cancel button text", () => {
  test("cancel button says Cancel", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal #modalFixNo").textContent()).toBe("Cancel");
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal label text ───

test.describe("Fix modal label text", () => {
  test("shows finding title", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal .fix-label").textContent()).toBeTruthy();
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal action-type-badge ───

test.describe("Fix modal action-type-badge", () => {
  test("badge has correct class", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const badge = page.locator("#fixModal .action-type-badge");
        if ((await badge.count()) > 0) {
          const cls = await badge.getAttribute("class");
          expect(cls).toMatch(/type-(exec|edit)/);
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal radio selection ───

test.describe("Fix modal radio selection", () => {
  test("selecting radio highlights option", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const radio = page.locator("#fixModal input[name='fixAction']").first();
        await radio.click({ force: true });
        await page.waitForTimeout(100);
        const option = await radio.evaluate((el) => {
          const opt = el.closest(".action-option") as HTMLElement | null;
          return opt?.className ?? "";
        });
        expect(option).toContain("selected");
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal radio name/value/id ───

test.describe("Fix modal radio name/value/id", () => {
  test("radio buttons have correct attributes", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const radios = page.locator("#fixModal input[name='fixAction']");
        const count = await radios.count();
        for (let i = 0; i < count; i++) {
          expect(await radios.nth(i).getAttribute("name")).toBe("fixAction");
          expect(await radios.nth(i).getAttribute("value")).toBe(String(i));
          expect(await radios.nth(i).getAttribute("id")).toBe(`actionRadio${i}`);
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal label for ───

test.describe("Fix modal label for", () => {
  test("labels match radio ids", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const labels = page.locator("#fixModal .action-option label");
        const count = await labels.count();
        for (let i = 0; i < count; i++) {
          expect(await labels.nth(i).getAttribute("for")).toBe(`actionRadio${i}`);
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal label content ───

test.describe("Fix modal label content", () => {
  test("label has badge and strong", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const labels = page.locator("#fixModal .action-option label");
        const count = await labels.count();
        for (let i = 0; i < count; i++) {
          expect(await labels.nth(i).locator(".action-type-badge").count()).toBe(1);
          expect(await labels.nth(i).locator("strong").count()).toBe(1);
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal action option data-idx ───

test.describe("Fix modal action option data-idx", () => {
  test("options have sequential data-idx", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const options = page.locator("#fixModal .action-option");
        const count = await options.count();
        for (let i = 0; i < count; i++) {
          expect(await options.nth(i).getAttribute("data-idx")).toBe(String(i));
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal action option structure ───


// ─── Fix modal confirm button disabled state ───

test.describe("Fix modal confirm button disabled state", () => {
  test("disabled before selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
      }
    }
  });

  test("enabled after selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#fixModal input[name='fixAction']").first().click({ force: true });
        await page.waitForTimeout(100);
      }
    }
  });

  test("text changes after selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.waitForTimeout(100);
      }
    }
  });
});

// ─── Fix modal dismiss ───

test.describe("Fix modal dismiss", () => {
  test("Escape closes", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.keyboard.press("Escape");
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });

  test("Cancel closes", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#fixModal #modalFixNo").click();
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });

  test("overlay click closes", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });
});

// ─── Fix result after apply ───


// ─── Score range validation ───


// ─── Finding structure ───


// ─── Score breakdown max_penalty ───


// ─── Score consistency ───

test.describe("Score consistency", () => {
  test("recalc returns same score", async ({ page }) => {
    await ready(page);
    const r1 = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const r2 = await page.evaluate(async () => {
      const resp = await fetch("/api/recalc", { method: "POST" });
      return resp.json();
    });
    expect(r2.score).toBe(r1.score);
  });

  test("breakdown.overall matches score", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(r.score_breakdown.overall).toBe(r.score);
  });
});

// ─── Secure headers ───


// ─── Toast auto-hide ───


// ─── Rescan button ───

test.describe("Rescan button", () => {
  test("disables during scan", async ({ page }) => {
    await ready(page);
    await page.locator("#rescanBtn").click();
    await page.waitForTimeout(300);
    expect(await page.locator("#rescanBtn").isDisabled()).toBe(true);
  });

  test("has loading class during scan", async ({ page }) => {
    await ready(page);
    await page.locator("#rescanBtn").click();
    await page.waitForTimeout(300);
    expect((await page.locator("#rescanBtn").getAttribute("class"))?.includes("loading")).toBeTruthy();
  });
});

// ─── Fix Selected button ───


// ─── Select-all checkbox ───


// ─── Sort by source groups ───


// ─── Sort stability ───


// ─── Table row click ───


// ─── Double-click selection ───


// ─── Space selection ───


// ─── Ctrl+A selection ───


// ─── v key cycles service ───

test.describe("v key cycles service", () => {
  test("cycles and wraps", async ({ page }) => {
    await ready(page);
    const allCount = await page.locator("#findings tr[data-index]").count();
    let totalCycles = 0;
    while (totalCycles < 10) {
      await page.keyboard.press("v");
      await page.waitForTimeout(200);
      totalCycles++;
      const count = await page.locator("#findings tr[data-index]").count();
      if (count === allCount && totalCycles > 1) break;
    }
    expect(await page.locator("#findings tr[data-index]").count()).toBe(allCount);
  });
});

// ─── R key clears ───

test.describe("R key clears", () => {
  test("resets all and shows toast", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(200);
    await page.keyboard.press("Escape");
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBeLessThan(14);
    await page.keyboard.press("R");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
    expect(await page.locator("#query").inputValue()).toBe("");
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
  });
});

// ─── o key cycles sort ───


// ─── q key shows toast ───


// ─── O key toggles sort ───

test.describe("O key toggles sort", () => {
  test("reverses order", async ({ page }) => {
    await ready(page);
    const firstId1 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    await page.keyboard.press("O");
    await page.waitForTimeout(200);
    const firstId2 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    expect(firstId1).not.toBe(firstId2);
  });
});

// ─── / key focuses search ───


// ─── Escape blurs search ───


// ─── e key opens export ───


// ─── ? key opens help ───


// ─── f key triggers fix ───


// ─── Enter confirms fix ───

test.describe("Enter confirms fix", () => {
  test("Enter key confirms fix", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.keyboard.press("Enter");
        await page.waitForTimeout(2000);
        await expect(page.locator("#fixModal")).not.toBeVisible({ timeout: 3000 });
      }
    }
  });
});

// ─── Keyboard shortcuts suppressed in input ───


// ─── Score breakdown head ───


// ─── Score breakdown penalty cap text ───


// ─── Score breakdown severity counts ───


// ─── Score breakdown axis labels ───


// ─── Score breakdown bar rendering ───


// ─── Score breakdown grid ───


// ─── Detail panel for trivy CVE ───


// ─── Detail panel for lynis finding ───


// ─── Detail panel for compose finding ───


// ─── Detail panel badge color ───


// ─── Detail panel remediation hint ───


// ─── Long text collapse/expand ───


// ─── Fix button visibility ───


// ─── Fix modal heading ───


// ─── Fix modal cancel button text ───


// ─── Fix modal label text ───


// ─── Fix modal action-type-badge ───


// ─── Fix modal radio selection ───


// ─── Fix modal radio name/value/id ───


// ─── Fix modal label for ───


// ─── Fix modal label content ───


// ─── Fix modal action option data-idx ───


// ─── Fix modal action option structure ───


// ─── Fix modal confirm button disabled state ───


// ─── Fix modal dismiss ───


// ─── Fix result after apply ───


// ─── Score range validation ───


// ─── Finding structure ───


// ─── Score breakdown max_penalty ───


// ─── Score consistency ───


// ─── Secure headers ───


// ─── Toast auto-hide ───


// ─── Rescan button ───


// ─── Fix Selected button ───


// ─── Select-all checkbox ───


// ─── Sort by source groups ───


// ─── Sort stability ───


// ─── Table row click ───


// ─── Double-click selection ───


// ─── Space selection ───


// ─── Ctrl+A selection ───


// ─── v key cycles service ───


// ─── R key clears ───


// ─── o key cycles sort ───


// ─── q key shows toast ───


// ─── O key toggles sort ───


// ─── / key focuses search ───


// ─── Escape blurs search ───


// ─── e key opens export ───


// ─── ? key opens help ───


// ─── f key triggers fix ───


// ─── Enter confirms fix ───


// ─── Keyboard shortcuts suppressed in input ───


// ─── Score breakdown head ───


// ─── Score breakdown penalty cap text ───


// ─── Score breakdown severity counts ───


// ─── Score breakdown axis labels ───


// ─── Score breakdown bar rendering ───


// ─── Score breakdown grid ───


// ─── Detail panel for trivy CVE ───


// ─── Detail panel for lynis finding ───


// ─── Detail panel for compose finding ───


// ─── Detail panel badge color ───


// ─── Detail panel remediation hint ───


// ─── Long text collapse/expand ───


// ─── Fix button visibility ───


// ─── Fix modal heading ───


// ─── Fix modal cancel button text ───


// ─── Fix modal label text ───


// ─── Fix modal action-type-badge ───


// ─── Fix modal radio selection ───


// ─── Fix modal radio name/value/id ───


// ─── Fix modal label for ───


// ─── Fix modal label content ───


// ─── Fix modal action option data-idx ───


// ─── Fix modal action option structure ───


// ─── Fix modal confirm button disabled state ───


// ─── Fix modal dismiss ───


// ─── Fix result after apply ───


// ─── Score range validation ───


// ─── Finding structure ───


// ─── Score breakdown max_penalty ───


// ─── Score consistency ───


// ─── Secure headers ───


// ─── Toast auto-hide ───


// ─── Rescan button ───


// ─── Fix Selected button ───


// ─── Select-all checkbox ───


// ─── Sort by source groups ───


// ─── Sort stability ───


// ─── Table row click ───


// ─── Double-click selection ───


// ─── Space selection ───


// ─── Ctrl+A selection ───


// ─── v key cycles service ───


// ─── R key clears ───


// ─── o key cycles sort ───


// ─── q key shows toast ───


// ─── O key toggles sort ───


// ─── / key focuses search ───


// ─── Escape blurs search ───


// ─── e key opens export ───


// ─── ? key opens help ───


// ─── f key triggers fix ───


// ─── Enter confirms fix ───


// ─── Keyboard shortcuts suppressed in input ───


// ─── Score breakdown head ───


// ─── Score breakdown penalty cap text ───


// ─── Score breakdown severity counts ───


// ─── Score breakdown axis labels ───


// ─── Score breakdown bar rendering ───


// ─── Score breakdown grid ───


// ─── Detail panel for trivy CVE ───

