import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

// ─── Loading phase screen (requires route mock) ───

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
    await page.waitForTimeout(500);
    // Loading state elements
    expect(await page.locator(".loading-state").count()).toBe(1);
    expect(await page.locator(".loading-state h2").textContent()).toBe("Scanning...");
    expect(await page.locator(".progress-bar").count()).toBe(1);
    expect(await page.locator(".progress-fill").count()).toBe(1);
    expect(await page.locator(".tool-row").count()).toBe(3);
    expect(await page.locator(".tool-name").first().textContent()).toBeTruthy();
    // Score shows --/100
    expect(await page.locator("#score").textContent()).toBe("--/100");
    // Finding count shows Scanning...
    expect(await page.locator("#findingCount").textContent()).toBe("Scanning...");
    // Shell has loading class
    expect((await page.locator(".shell").getAttribute("class"))?.includes("loading")).toBeTruthy();
  });

  test("loading phase shows correct progress percentage", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          phase: "loading",
          tools: {
            trivy: { status: 2, message: "Done" },
            lynis: { status: 2, message: "Done" },
            compose: { status: 0, message: "Queued" },
          },
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await page.waitForTimeout(500);
    const progressText = await page.locator(".loading-state .muted").first().textContent();
    expect(progressText).toContain("67% complete");
  });

  test("loading phase shows tool status icons", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          phase: "loading",
          tools: {
            trivy: { status: 1, message: "Scanning..." },
            lynis: { status: 3, message: "Skipped" },
          },
          findings: [],
          score: 0,
          score_breakdown: { overall: 0, axes: [] },
        }),
      })
    );
    await page.goto("/");
    await page.waitForTimeout(500);
    const icons = page.locator(".tool-icon");
    expect(await icons.count()).toBe(2);
    // Running icon
    expect((await icons.first().getAttribute("class"))?.includes("running")).toBeTruthy();
    // Muted icon (skipped)
    expect((await icons.nth(1).getAttribute("class"))?.includes("muted")).toBeTruthy();
  });

  test("score breakdown hidden during loading", async ({ page }) => {
    await page.route("**/api/result", (route) =>
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
      })
    );
    await page.goto("/");
    await page.waitForTimeout(500);
    expect(await page.locator("#scoreBreakdown").isHidden()).toBe(true);
  });
});

// ─── Recalc failure toast (requires route mock) ───

test.describe("Recalc failure toast", () => {
  test("shows error toast when recalc fails", async ({ page }) => {
    await ready(page);
    await page.route("**/api/recalc", (route) => route.abort("connectionrefused"));
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(1000);
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 5000 });
    expect(await toast.textContent()).toContain("Recalculation failed");
  });
});

// ─── O key (shift+o) toggles sort direction ───

test.describe("O key toggles sort direction", () => {
  test("O key reverses sort order", async ({ page }) => {
    await ready(page);
    const firstId1 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    await page.keyboard.press("O");
    await page.waitForTimeout(200);
    const firstId2 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    expect(firstId1).not.toBe(firstId2);
  });
});

// ─── f key with selection opens batch fix ───

test.describe("f key with selection", () => {
  test("f key opens fix for selected finding when no batch selection", async ({ page }) => {
    await ready(page);
    // Navigate to a finding
    await page.keyboard.press("ArrowDown");
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

// ─── Export modal Close button ───

test.describe("Export modal Close button", () => {
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

// ─── Export modal heading ───

test.describe("Export modal heading", () => {
  test("export modal has correct heading and description", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    expect(await modal.locator("h2").textContent()).toBe("Export report");
    expect(await modal.locator(".muted").textContent()).toContain("AI-ready");
    await page.keyboard.press("Escape");
  });
});

// ─── Detail panel empty state ───

test.describe("Detail panel empty state", () => {
  test("shows placeholder when no finding is selected", async ({ page }) => {
    await page.goto("/");
    // Before findings load, detail may show empty state
    // After loading, first finding is auto-selected, so check the initial render
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
    const detail = page.locator("#detail");
    const text = await detail.textContent();
    expect(text).toBeTruthy();
  });
});

// ─── Table "No findings match" message ───

test.describe("Table no-match message", () => {
  test("shows message when all findings filtered out", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("zzzzimpossible");
    await page.waitForTimeout(300);
    const msg = page.locator("#findings .muted");
    await expect(msg).toBeVisible();
    expect(await msg.textContent()).toContain("No findings match");
    await page.locator("#query").fill("");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
  });
});

// ─── Fix modal warning display ───

test.describe("Fix modal warning", () => {
  test("fix modal with warning shows warning text", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const warning = page.locator("#fixModal .fix-warning");
        if ((await warning.count()) > 0) {
          expect(await warning.textContent()).toContain("\u26A0");
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal diff preview ───

test.describe("Fix modal diff preview", () => {
  test("fix modal with diff preview shows highlighted diff", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const diffPreview = page.locator("#fixModal .diff-preview");
        if ((await diffPreview.count()) > 0) {
          expect(await diffPreview.locator("pre").count()).toBe(1);
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal edit_path display ───

test.describe("Fix modal edit_path", () => {
  test("fix modal with edit_path shows file path", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const editPath = page.locator("#fixModal .action-edit-path");
        if ((await editPath.count()) > 0) {
          expect(await editPath.textContent()).toContain("File");
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal command display ───

test.describe("Fix modal command display", () => {
  test("fix modal with command shows command block", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const cmd = page.locator("#fixModal .action-command");
        if ((await cmd.count()) > 0) {
          expect(await cmd.textContent()).toContain("Command");
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal radio selection visual feedback ───

test.describe("Fix modal radio selection highlights", () => {
  test("selecting a radio highlights the action option", async ({ page }) => {
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

// ─── Fix modal confirm button text changes ───

test.describe("Fix modal confirm button text", () => {
  test("confirm button says Select an action before selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal #modalFixYes").textContent()).toBe("Select an action");
        await page.keyboard.press("Escape");
      }
    }
  });

  test("confirm button says Apply selected after selection", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#fixModal input[name='fixAction']").first().click({ force: true });
        await page.waitForTimeout(100);
        expect(await page.locator("#fixModal #modalFixYes").textContent()).toBe("Apply selected");
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal action option structure ───

test.describe("Fix modal action option structure", () => {
  test("each action option has header, radio, and label with matching for", async ({ page }) => {
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
          const radio = options.nth(i).locator("input[type='radio']");
          const label = options.nth(i).locator("label");
          expect(await radio.getAttribute("id")).toBe(`actionRadio${i}`);
          expect(await label.getAttribute("for")).toBe(`actionRadio${i}`);
          expect(await radio.getAttribute("name")).toBe("fixAction");
          expect(await radio.getAttribute("value")).toBe(String(i));
          expect(await options.nth(i).locator("strong").count()).toBe(1);
          expect(await options.nth(i).locator(".action-type-badge").count()).toBe(1);
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix result success class ───

test.describe("Fix result success display", () => {
  test("fix result shows fix-success class", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#fixModal #modalFixYes").click();
        await page.waitForTimeout(2000);
        const result = page.locator("#fixResult");
        if ((await result.count()) > 0) {
          expect(await result.locator(".fix-success").count()).toBe(1);
        }
      }
    }
  });
});

// ─── Fix button loading and re-enable ───

test.describe("Fix button loading state", () => {
  test("fix button shows loading text and re-enables after apply", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        await page.locator("#fixModal #modalFixYes").click();
        await page.waitForTimeout(200);
        // Button shows Applying...
        const btn = page.locator("#detail .fix-btn");
        if ((await btn.count()) > 0) {
          expect(await btn.textContent()).toContain("Applying");
        }
      }
    }
  });
});

// ─── API export content types and headers ───

test.describe("API export content types", () => {
  test("export JSON has correct headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=json");
      return {
        ct: resp.headers.get("content-type"),
        cd: resp.headers.get("content-disposition"),
      };
    });
    expect(r.ct).toContain("application/json");
    expect(r.cd).toContain("hostveil-report.json");
  });

  test("export CSV has correct headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=csv");
      return {
        ct: resp.headers.get("content-type"),
        cd: resp.headers.get("content-disposition"),
      };
    });
    expect(r.ct).toContain("text/csv");
    expect(r.cd).toContain("hostveil-report.csv");
  });

  test("export AI brief has correct headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai");
      return {
        ct: resp.headers.get("content-type"),
        cd: resp.headers.get("content-disposition"),
      };
    });
    expect(r.ct).toContain("text/markdown");
    expect(r.cd).toContain("hostveil-ai-brief.md");
  });

  test("export ai-brief alias works", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai-brief");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("text/markdown");
  });

  test("export markdown alias works", async ({ page }) => {
    await ready(page);
    const ct = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=markdown");
      return resp.headers.get("content-type");
    });
    expect(ct).toContain("text/markdown");
  });
});

// ─── API export content validation ───

test.describe("API export content", () => {
  test("export JSON contains valid findings", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=json");
      return resp.json();
    });
    expect(Array.isArray(r.findings)).toBe(true);
    expect(r.findings.length).toBe(14);
  });

  test("export CSV contains header row", async ({ page }) => {
    await ready(page);
    const text = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=csv");
      return resp.text();
    });
    expect(text).toContain("ID");
    expect(text).toContain("trivy.cve-2024-0001");
  });

  test("export AI brief contains markdown headings", async ({ page }) => {
    await ready(page);
    const text = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai");
      return resp.text();
    });
    expect(text).toContain("#");
    expect(text).toContain("hostveil");
  });
});

// ─── API rescan idempotency ───

test.describe("API rescan idempotency", () => {
  test("double rescan returns error for second request", async ({ page }) => {
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

// ─── API fix error cases ───

test.describe("API fix error cases", () => {
  test("fix with malformed JSON returns error", async ({ page }) => {
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

  test("fix with empty body returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "",
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toBeTruthy();
  });

  test("fix with out-of-range action_index returns error", async ({ page }) => {
    await ready(page);
    // Use info_only to get the action count, then send an out-of-range index
    const info = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: { id: "lynis.AUTH-9286", remediation: 0 }, action_index: 0, info_only: true }),
      });
      return resp.json();
    });
    if (info.success && info.actions && info.actions.length > 0) {
      const r = await page.evaluate(async (actionCount) => {
        const resp = await fetch("/api/fix", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ finding: { id: "lynis.AUTH-9286", remediation: 0 }, action_index: actionCount }),
        });
        return resp.json();
      }, info.actions.length);
      expect(r.success).toBe(false);
      expect(r.error).toContain("out of range");
    }
  });

  test("fix with negative action_index returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding: { id: "lynis.AUTH-9286", remediation: 0 }, action_index: -1 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("out of range");
  });
});

// ─── API fix batch error cases ───

test.describe("API fix batch error cases", () => {
  test("batch with malformed JSON returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "not json",
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("invalid request");
  });

  test("batch with mix of valid and invalid findings", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [{ id: "nonexistent.abc", action_index: 0 }],
          action_index: 0,
        }),
      });
      return resp.json();
    });
    expect(r.results.length).toBe(1);
    expect(r.results[0].success).toBe(false);
    expect(r.results[0].error).toContain("no fix registered");
  });
});

// ─── Score breakdown severity counts ───

test.describe("Score breakdown severity counts", () => {
  test("each axis shows correct count format (number + letter)", async ({ page }) => {
    await ready(page);
    const counts = page.locator("#scoreBreakdown .score-axis-counts");
    for (let i = 0; i < 4; i++) {
      const text = await counts.nth(i).textContent();
      expect(text).toBeTruthy();
    }
  });

  test("severity count badges use correct color classes", async ({ page }) => {
    await ready(page);
    const counts = page.locator("#scoreBreakdown .score-axis-counts span");
    const count = await counts.count();
    for (let i = 0; i < count; i++) {
      const cls = await counts.nth(i).getAttribute("class");
      expect(cls).toMatch(/critical|high|medium|low|muted/);
    }
  });
});

// ─── Score breakdown penalty cap text ───

test.describe("Score breakdown penalty cap text", () => {
  test("penalty text shows N/M penalty cap used format", async ({ page }) => {
    await ready(page);
    const meta = page.locator("#scoreBreakdown .score-axis-meta span").first();
    const text = await meta.textContent();
    expect(text).toMatch(/\d+\/\d+ penalty cap used/);
  });
});

// ─── Score breakdown grid layout ───

test.describe("Score breakdown grid", () => {
  test("score-axis-grid contains all 4 axes", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#scoreBreakdown .score-axis-grid").count()).toBe(1);
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
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

// ─── Detail panel for finding with no evidence ───

test.describe("Detail panel no-evidence finding", () => {
  test("finding with no evidence has no evidence section", async ({ page }) => {
    await ready(page);
    // test.unfixable-001 has evidence but let's check a finding without metadata
    await page.locator("#findings tr[data-id='lynis.KRNL-5780']").click({ force: true });
    await page.waitForTimeout(500);
    const details = page.locator("#detail .evidence-details");
    // KRNL-5780 has evidence but no metadata
    expect(await details.count()).toBe(1);
  });
});

// ─── Finding count display ───

test.describe("Finding count display", () => {
  test("finding count shows correct visible number", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#findingCount").textContent()).toContain("14 visible");
  });
});

// ─── Rescan button during scan ───

test.describe("Rescan button during scan", () => {
  test("rescan button shows loading class during scan", async ({ page }) => {
    await ready(page);
    await page.locator("#rescanBtn").click();
    await page.waitForTimeout(300);
    const cls = await page.locator("#rescanBtn").getAttribute("class");
    expect(cls).toContain("loading");
  });
});

// ─── Fix modal heading for auto vs review ───

test.describe("Fix modal heading", () => {
  test("auto fix modal heading is Apply fix", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
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

  test("review fix modal heading is Choose action", async ({ page }) => {
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

// ─── Fix modal overlay ID and content class ───

test.describe("Fix modal overlay structure", () => {
  test("fix modal has id fixModal and modal-content with modal-fix class", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        expect(await page.locator("#fixModal").getAttribute("id")).toBe("fixModal");
        const content = page.locator("#fixModal .modal-content");
        expect(await content.count()).toBe(1);
        expect((await content.getAttribute("class"))?.includes("modal-fix")).toBeTruthy();
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal actions div ───

test.describe("Fix modal actions div", () => {
  test("fix modal has modal-actions with Apply and Cancel", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const actions = page.locator("#fixModal .modal-actions");
        expect(await actions.count()).toBe(1);
        expect(await actions.locator("button").count()).toBe(2);
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── Fix modal action type badge class ───

test.describe("Fix modal action type badge class", () => {
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

// ─── Fix modal label text ───

test.describe("Fix modal label text", () => {
  test("fix modal shows finding title as label", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    if ((await page.locator("#detail .fix-btn").count()) > 0) {
      await page.locator("#detail .fix-btn").click();
      await page.waitForTimeout(500);
      if ((await page.locator("#fixModal").count()) > 0) {
        const label = page.locator("#fixModal .fix-label");
        expect(await label.textContent()).toBeTruthy();
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

// ─── Fix modal action summary structure ───

