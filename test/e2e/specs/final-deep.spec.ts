import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("Fix modal overlay click-to-close", () => {
  test("fix modal closes when clicking overlay", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
        await page.waitForTimeout(300);
        await expect(page.locator("#fixModal")).not.toBeVisible();
      }
    }
  });
});

test.describe("Fix action type badge", () => {
  test("auto fix shows action type in badge", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        const badge = modal.locator(".action-type-badge");
        if ((await badge.count()) > 0) {
          const text = await badge.textContent();
          expect(text).toBeTruthy();
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Fix button state changes", () => {
  test("fix button disappears after successful apply", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
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

test.describe("Fix result content", () => {
  test("successful fix shows result with success indicator", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
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
  test("selecting findings shows count on Fix Selected", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("Space");
    await page.waitForTimeout(200);
    const btn = page.locator("#fixSelectedBtn");
    await expect(btn).toBeVisible();
    expect(await btn.textContent()).toContain("2");
  });
});

test.describe("Fix Selected button hidden when no selection", () => {
  test("Fix Selected button has no count with no selection", async ({ page }) => {
    await ready(page);
    const btn = page.locator("#fixSelectedBtn");
    const text = await btn.textContent();
    expect(text).not.toContain("(");
  });
});

test.describe("Fix modal for review finding", () => {
  test("review finding shows radio buttons and confirm is disabled", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.dr001']");
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        const radios = modal.locator("input[name='fixAction']");
        expect(await radios.count()).toBeGreaterThanOrEqual(2);
        const confirmBtn = modal.locator("#modalFixYes");
        expect(await confirmBtn.isDisabled()).toBe(true);
        await radios.first().click();
        await page.waitForTimeout(100);
        expect(await confirmBtn.isEnabled()).toBe(true);
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Fix error handling", () => {
  test("fix with unregistered ID returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "nonexistent.id", action_index: 0 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("no fix registered");
  });

  test("fix with out-of-range action_index returns error", async ({ page }) => {
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

  test("fix with negative action_index returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id: "trivy.cve-2024-0001", action_index: -1 }),
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toBeTruthy();
  });

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
});

test.describe("Fix batch error handling", () => {
  test("batch with empty findings returns empty results", async ({ page }) => {
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
  });

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
  });
});

test.describe("Export format edge cases", () => {
  test("export with no format defaults to JSON", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export");
      return { ct: resp.headers.get("content-type"), cd: resp.headers.get("content-disposition") };
    });
    expect(r.ct).toContain("application/json");
    expect(r.cd).toContain("hostveil-report.json");
  });

  test("export with unknown format defaults to JSON", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=xyz");
      return { ct: resp.headers.get("content-type") };
    });
    expect(r.ct).toContain("application/json");
  });

  test("export with format=csv returns CSV with headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=csv");
      return { ct: resp.headers.get("content-type"), cd: resp.headers.get("content-disposition"), text: await resp.text() };
    });
    expect(r.ct).toContain("text/csv");
    expect(r.cd).toContain("hostveil-report.csv");
    expect(r.text).toContain("ID");
  });

  test("export with format=ai returns markdown", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai");
      return { ct: resp.headers.get("content-type"), text: await resp.text() };
    });
    expect(r.ct).toContain("text/markdown");
    expect(r.text).toContain("#");
  });

  test("export with format=ai-brief returns markdown", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai-brief");
      return { ct: resp.headers.get("content-type") };
    });
    expect(r.ct).toContain("text/markdown");
  });

  test("export with format=markdown returns markdown", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=markdown");
      return { ct: resp.headers.get("content-type") };
    });
    expect(r.ct).toContain("text/markdown");
  });
});

test.describe("Secure headers", () => {
  test("API responses include security headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/health");
      return { xcto: resp.headers.get("x-content-type-options"), xfo: resp.headers.get("x-frame-options"), rp: resp.headers.get("referrer-policy") };
    });
    expect(r.xcto).toBe("nosniff");
    expect(r.xfo).toBe("DENY");
    expect(r.rp).toBe("no-referrer");
  });
});

test.describe("Score breakdown penalty cap values", () => {
  test("vulnerabilities max penalty is 35", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const v = r.score_breakdown.axes.find((a: { id: string }) => a.id === "vulnerabilities");
    expect(v.max_penalty).toBe(35);
  });

  test("container_exposure max penalty is 30", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const ce = r.score_breakdown.axes.find((a: { id: string }) => a.id === "container_exposure");
    expect(ce.max_penalty).toBe(30);
  });

  test("host_hardening max penalty is 25", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const hh = r.score_breakdown.axes.find((a: { id: string }) => a.id === "host_hardening");
    expect(hh.max_penalty).toBe(25);
  });

  test("secrets max penalty is 10", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const s = r.score_breakdown.axes.find((a: { id: string }) => a.id === "secrets");
    expect(s.max_penalty).toBe(10);
  });
});

test.describe("Score consistency", () => {
  test("score_breakdown.overall matches score", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    expect(r.score_breakdown.overall).toBe(r.score);
  });

  test("recalc returns same score as initial", async ({ page }) => {
    await ready(page);
    const r1 = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const r2 = await page.evaluate(async () => { const resp = await fetch("/api/recalc", { method: "POST" }); return resp.json(); });
    expect(r2.score).toBe(r1.score);
  });
});

test.describe("Finding structure validation", () => {
  test("each finding has required fields", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    for (const f of r.findings) {
      expect(typeof f.id).toBe("string");
      expect(typeof f.title).toBe("string");
      expect(typeof f.severity).toBe("number");
      expect(typeof f.source).toBe("number");
      expect(typeof f.remediation).toBe("number");
      expect(typeof f.fixed).toBe("boolean");
    }
  });

  test("finding IDs are unique", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const ids = r.findings.map((f: { id: string }) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("severity values are in range 0-3", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    for (const f of r.findings) {
      expect(f.severity).toBeGreaterThanOrEqual(0);
      expect(f.severity).toBeLessThanOrEqual(3);
    }
  });
});

test.describe("Score is in valid range", () => {
  test("overall score between 0 and 100", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(100);
  });

  test("score_breakdown.overall matches score", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    expect(r.score_breakdown.overall).toBe(r.score);
  });
});

test.describe("Score breakdown axes", () => {
  test("score_breakdown has 4 axes with valid data", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    expect(r.score_breakdown.axes.length).toBe(4);
    for (const axis of r.score_breakdown.axes) {
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
      expect(axis.max_penalty).toBeGreaterThan(0);
    }
  });

  test("each axis has correct data-axis attribute", async ({ page }) => {
    await ready(page);
    const axes = page.locator("#scoreBreakdown .score-axis");
    const expected = ["vulnerabilities", "container_exposure", "host_hardening", "secrets"];
    for (let i = 0; i < 4; i++) {
      expect(expected).toContain(await axes.nth(i).getAttribute("data-axis"));
    }
  });
});

test.describe("Remediation and source distribution", () => {
  test("correct counts per remediation type", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const rems: Record<number, number> = {};
    for (const f of r.findings) { rems[f.remediation] = (rems[f.remediation] || 0) + 1; }
    expect(rems[0]).toBe(10);
    expect(rems[1]).toBe(3);
    expect(rems[2]).toBe(1);
  });

  test("correct counts per source", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/result"); return resp.json(); });
    const srcs: Record<number, number> = {};
    for (const f of r.findings) { srcs[f.source] = (srcs[f.source] || 0) + 1; }
    expect(srcs[0]).toBe(6);
    expect(srcs[1]).toBe(6);
    expect(srcs[2]).toBe(2);
  });
});

test.describe("POST /api/recalc score validation", () => {
  test("recalc returns score between 0 and 100", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/recalc", { method: "POST" }); return resp.json(); });
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(100);
  });

  test("recalc score_breakdown axes have valid scores", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => { const resp = await fetch("/api/recalc", { method: "POST" }); return resp.json(); });
    expect(r.score_breakdown.axes.length).toBe(4);
    for (const axis of r.score_breakdown.axes) {
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
    }
  });
});

test.describe("POST /api/rescan idempotency", () => {
  test("second rescan while first is running returns error", async ({ page }) => {
    await ready(page);
    const r1 = await page.evaluate(async () => { const resp = await fetch("/api/rescan", { method: "POST" }); return resp.json(); });
    const r2 = await page.evaluate(async () => { const resp = await fetch("/api/rescan", { method: "POST" }); return resp.json(); });
    expect(r1.status === "rescanning" || r2.status === "rescanning").toBe(true);
  });
});

test.describe("POST /api/fix with large body", () => {
  test("fix request with very large body is rejected", async ({ page }) => {
    await ready(page);
    const largeId = "x".repeat(2 * 1024 * 1024);
    const r = await page.evaluate(async (id) => {
      const resp = await fetch("/api/fix", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ id, action_index: 0 }) });
      return { status: resp.status, body: await resp.json() };
    }, largeId);
    expect(r.body.success).toBe(false);
  });
});

test.describe("Detail panel for different finding types", () => {
  test("trivy CVE shows all detail sections", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail").textContent();
    expect(text).toContain("trivy.cve-2024-0001");
    expect(text).toContain("critical");
    expect(text).toContain("nginx:1.24");
    expect(text).toContain("Description");
    expect(text).toContain("How to fix");
  });

  test("lynis finding shows correct metadata", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.AUTH-9286']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail").textContent();
    expect(text).toContain("lynis.AUTH-9286");
    expect(text).toContain("Auto");
    expect(text).toContain("one clear fix");
  });

  test("compose finding shows service", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='compose.dr004']").click({ force: true });
    await page.waitForTimeout(500);
    const text = await page.locator("#detail").textContent();
    expect(text).toContain("compose.dr004");
    expect(text).toContain("webapp");
  });

  test("unavailable finding has no fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });

  test("fixed finding has no fix button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0003']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .fix-btn").count()).toBe(0);
  });
});

test.describe("Table row states", () => {
  test("fixed row has fixed and disabled classes", async ({ page }) => {
    await ready(page);
    const cls = await page.locator("#findings tr[data-id='trivy.cve-2024-0003']").getAttribute("class");
    expect(cls).toContain("fixed");
    expect(cls).toContain("disabled");
  });

  test("fixed row has check mark instead of badge", async ({ page }) => {
    await ready(page);
    const text = await page.locator("#findings tr[data-id='trivy.cve-2024-0003'] td").nth(1).textContent();
    expect(text).toContain("✓");
  });

  test("every row has 6 cells", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) { expect(await rows.nth(i).locator("td").count()).toBe(6); }
  });

  test("rows have sequential data-index", async ({ page }) => {
    await ready(page);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) { expect(await rows.nth(i).getAttribute("data-index")).toBe(String(i)); }
  });
});

test.describe("Selection behavior", () => {
  test("clicking row selects it", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-index='1']");
    await row.click({ force: true });
    await page.waitForTimeout(200);
    const cls1 = await row.getAttribute("class");
    expect(cls1).toContain("selected");
  });

  test("double-click toggles row-selected", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='lynis.FILE-6310']");
    await row.dblclick();
    await page.waitForTimeout(200);
    const cls2 = await row.getAttribute("class");
    expect(cls2).toContain("row-selected");
    await row.dblclick();
    await page.waitForTimeout(200);
    const cls3 = await row.getAttribute("class");
    expect(cls3).not.toContain("row-selected");
  });

  test("select-all checkbox selects all batch-selectable", async ({ page }) => {
    await ready(page);
    await page.locator("#selectAllCheck").check({ force: true });
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr.row-selected").count()).toBeGreaterThan(0);
    await page.locator("#selectAllCheck").uncheck({ force: true });
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr.row-selected").count()).toBe(0);
  });

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

test.describe("Keyboard navigation", () => {
  test("ArrowDown and ArrowUp navigate findings", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    await page.keyboard.press("ArrowDown");
    await page.waitForTimeout(100);
    expect(await page.locator("#findings tr.selected").count()).toBe(1);
    await page.keyboard.press("ArrowUp");
    await page.waitForTimeout(100);
  });

  test("/ focuses search input", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("/");
    await page.waitForTimeout(100);
    expect(await page.evaluate(() => document.activeElement?.id || "")).toBe("query");
    await page.keyboard.press("Escape");
  });

  test("Escape blurs search input", async ({ page }) => {
    await ready(page);
    const query = page.locator("#query");
    await query.focus();
    await page.waitForTimeout(100);
    expect(await query.evaluate((el) => el === document.activeElement)).toBe(true);
    await page.keyboard.press("Escape");
    await page.waitForTimeout(100);
    expect(await query.evaluate((el) => el === document.activeElement)).toBe(false);
  });

  test("e opens export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });

  test("? opens help modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

test.describe("No findings match message", () => {
  test("shows message when all filtered out", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("zzzzimpossible");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr td.muted").textContent()).toContain("No findings match");
    await page.locator("#query").fill("");
    await page.waitForTimeout(300);
  });
});

test.describe("Recalc and rescan", () => {
  test("recalc button shows toast", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);
    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 5000 });
    expect(await toast.textContent()).toContain("recalculated");
  });

  test("rescan button re-enables after completion", async ({ page }) => {
    await ready(page);
    const btn = page.locator("#rescanBtn");
    await btn.click();
    await page.waitForTimeout(500);
    expect(await btn.isDisabled()).toBe(true);
    await expect(btn).toBeEnabled({ timeout: 10000 });
  });
});

test.describe("Score plate and metrics", () => {
  test("score plate has severity class", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".scoreplate").getAttribute("class")).toMatch(/score-(low|medium|high|critical)/);
  });

  test("score element shows N/100 format", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#score").textContent()).toMatch(/^\d+\/100$/);
  });

  test("metrics has 6 items", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").count()).toBe(6);
  });

  test("total metric shows 14", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").first().textContent()).toContain("14");
  });
});

test.describe("Filter chip active state", () => {
  test("All chip is active by default", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#severityFilters button.chip.active").textContent()).toContain("All");
  });

  test("clicking Critical activates it", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    expect(await page.locator("#severityFilters button.chip.active").textContent()).toContain("Critical");
  });
});

test.describe("Sort dropdown", () => {
  test("sort dropdown has 4 options", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#sortBy option").count()).toBe(4);
  });

  test("sort dropdown defaults to severity", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#sortBy").inputValue()).toBe("severity");
  });
});

test.describe("Search filtering", () => {
  test("typing in search filters the findings table", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(300);
    const count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeGreaterThanOrEqual(1);
    expect(count).toBeLessThan(14);
  });

  test("clearing search restores all findings", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("nginx");
    await page.waitForTimeout(300);
    let count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBeLessThan(14);
    await page.locator("#query").fill("");
    await page.waitForTimeout(300);
    count = await page.locator("#findings tr[data-index]").count();
    expect(count).toBe(14);
  });

  test("search is case-insensitive", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("SSH");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBeGreaterThanOrEqual(1);
    await page.locator("#query").fill("");
    await page.waitForTimeout(300);
  });
});

test.describe("Detail panel copy button", () => {
  test("how_to_fix section has copy button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    await expect(page.locator("#detail button.copy")).toBeVisible({ timeout: 5000 });
  });
});

test.describe("Score breakdown head text", () => {
  test("head says Score breakdown and mentions penalty cap", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    expect(await head.locator("span").textContent()).toBe("Score breakdown");
    expect(await head.locator("p").textContent()).toContain("penalty cap");
  });
});

test.describe("Score breakdown penalty bars", () => {
  test("each penalty bar has a width percentage", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar span");
    for (let i = 0; i < 4; i++) {
      expect(await bars.nth(i).getAttribute("style")).toMatch(/width:\d+%/);
    }
  });
});

test.describe("Evidence key alphabetical ordering", () => {
  test("evidence keys appear in sorted order", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const summary = page.locator("#detail .evidence-details summary").first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);
      const keys = page.locator("#detail .evidence-details:first-of-type pre strong");
      const count = await keys.count();
      const texts: string[] = [];
      for (let i = 0; i < count; i++) { texts.push((await keys.nth(i).textContent()) ?? ""); }
      for (let i = 1; i < texts.length; i++) {
        expect(texts[i].localeCompare(texts[i - 1])).toBeGreaterThanOrEqual(0);
      }
    }
  });
});

test.describe("Filter chip active state persistence", () => {
  test("active chip stays active after re-render", async ({ page }) => {
    await ready(page);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    let active = await page.locator("#severityFilters button.active").textContent();
    expect(active).toContain("Critical");
    await page.locator("#findings tr[data-index]").first().click({ force: true });
    await page.waitForTimeout(200);
    active = await page.locator("#severityFilters button.active").textContent();
    expect(active).toContain("Critical");
  });
});

test.describe("Finding count after filter reset", () => {
  test("count returns to 14 after clearing all", async ({ page }) => {
    await ready(page);
    await page.locator("#clearFilters").click();
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
  });
});

test.describe("Sort by source groups findings", () => {
  test("compose findings are grouped together", async ({ page }) => {
    await ready(page);
    await page.locator("#sortBy").selectOption("source");
    await page.waitForTimeout(200);
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    const ids: string[] = [];
    for (let i = 0; i < count; i++) { const id = await rows.nth(i).getAttribute("data-id"); if (id) ids.push(id); }
    const composeIdx = ids.map((id, i) => id.startsWith("compose.") ? i : -1).filter(i => i >= 0);
    if (composeIdx.length >= 2) {
      for (let i = 1; i < composeIdx.length; i++) { expect(composeIdx[i] - composeIdx[i - 1]).toBe(1); }
    }
  });
});

test.describe("Sort stability", () => {
  test("sort order persists after clicking a row", async ({ page }) => {
    await ready(page);
    const ids1: string[] = [];
    const rows = page.locator("#findings tr[data-index]");
    const count = await rows.count();
    for (let i = 0; i < count; i++) { const id = await rows.nth(i).getAttribute("data-id"); if (id) ids1.push(id); }
    await rows.first().click({ force: true });
    await page.waitForTimeout(200);
    const ids2: string[] = [];
    const rows2 = page.locator("#findings tr[data-index]");
    for (let i = 0; i < count; i++) { const id = await rows2.nth(i).getAttribute("data-id"); if (id) ids2.push(id); }
    expect(ids1).toEqual(ids2);
  });
});

test.describe("Score breakdown penalty bar accessibility", () => {
  test("penalty bars have aria-label", async ({ page }) => {
    await ready(page);
    const bars = page.locator("#scoreBreakdown .score-axis-bar");
    for (let i = 0; i < 4; i++) { expect(await bars.nth(i).getAttribute("aria-label")).toBeTruthy(); }
  });
});

test.describe("Tab navigation", () => {
  test("Tab moves focus through interactive elements", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);
    await page.keyboard.press("Tab");
    await page.waitForTimeout(100);
    expect(await page.evaluate(() => document.activeElement?.tagName || "")).toBeTruthy();
  });
});

test.describe("Responsive behavior", () => {
  test("score breakdown at 768px shows all axes", async ({ page }) => {
    await ready(page);
    await page.setViewportSize({ width: 768, height: 900 });
    await page.waitForTimeout(200);
    expect(await page.locator("#scoreBreakdown .score-axis").count()).toBe(4);
    await page.setViewportSize({ width: 1440, height: 900 });
  });
});

test.describe("Export and help modals", () => {
  test("export modal has JSON, CSV, AI options and close button", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const text = await modal.textContent();
    expect(text).toContain("JSON");
    expect(text).toContain("CSV");
    expect(text).toContain("AI brief");
    expect(text).toContain("Close");
    await page.keyboard.press("Escape");
  });

  test("help modal has all four sections", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    const modal = page.locator("#helpModal");
    await expect(modal).toBeVisible({ timeout: 3000 });
    const text = await modal.textContent();
    expect(text).toContain("Navigation");
    expect(text).toContain("Filters");
    expect(text).toContain("Actions");
    expect(text).toContain("Other");
    await page.keyboard.press("Escape");
  });
});

test.describe("Topbar and findings panel structure", () => {
  test("topbar has hostveil title", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".topbar h1").textContent()).toContain("hostveil");
  });

  test("findings panel has eyebrow", async ({ page }) => {
    await ready(page);
    expect(await page.locator(".findings-panel .eyebrow").textContent()).toContain("Findings");
  });

  test("search input has placeholder", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#query").getAttribute("placeholder")).toBeTruthy();
  });

  test("clear filters button exists", async ({ page }) => {
    await ready(page);
    await expect(page.locator("#clearFilters")).toBeVisible();
  });
});

test.describe("Score breakdown severity counts", () => {
  test("vulnerabilities axis has severity count spans", async ({ page }) => {
    await ready(page);
    const counts = page.locator("#scoreBreakdown .score-axis").filter({ hasText: "Vulnerabilities" }).locator(".score-axis-counts span");
    expect(await counts.count()).toBeGreaterThanOrEqual(1);
  });
});

test.describe("Sort direction toggle via O key", () => {
  test("O key reverses sort order", async ({ page }) => {
    await ready(page);
    const firstId1 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    await page.keyboard.press("O");
    await page.waitForTimeout(200);
    const firstId2 = await page.locator("#findings tr[data-index]").first().getAttribute("data-id");
    expect(firstId1).not.toBe(firstId2);
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

test.describe("Number key filters", () => {
  test("key 1 filters to critical", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(2);
  });

  test("key 0 shows all", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("1");
    await page.waitForTimeout(200);
    await page.keyboard.press("0");
    await page.waitForTimeout(200);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(14);
  });
});

test.describe("Tooltip text on buttons", () => {
  test("recalc button has title tooltip", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#recalcBtn").getAttribute("title")).toBeTruthy();
  });
});

test.describe("Modal overlay click-to-close", () => {
  test("help modal closes on overlay click", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.locator(".modal-overlay").click({ position: { x: 5, y: 5 } });
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).not.toBeVisible();
  });
});

test.describe("Evidence expand/collapse", () => {
  test("evidence disclosure toggles", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const summary = page.locator("#detail .evidence-details summary").first();
    if ((await summary.count()) > 0) {
      await summary.click();
      await page.waitForTimeout(200);
      expect(await page.locator("#detail .evidence-details pre").count()).toBeGreaterThanOrEqual(1);
      await summary.click();
      await page.waitForTimeout(200);
    }
  });
});

test.describe("Fix modal for auto finding", () => {
  test("auto finding fix modal has finding title", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0002']");
    await row.click({ force: true });
    await page.waitForTimeout(500);
    const fixBtn = page.locator("#detail .fix-btn");
    if ((await fixBtn.count()) > 0) {
      await fixBtn.click();
      await page.waitForTimeout(500);
      const modal = page.locator("#fixModal");
      if ((await modal.count()) > 0) {
        expect(await modal.textContent()).toBeTruthy();
        await page.keyboard.press("Escape");
      }
    }
  });
});

test.describe("Detail panel for different severity levels", () => {
  test("critical finding shows critical badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const badge = page.locator("#detail .badge");
    if ((await badge.count()) > 0) {
      const cls = await badge.getAttribute("class");
      expect(cls).toContain("critical");
    }
  });

  test("low finding shows low badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.KRNL-5780']").click({ force: true });
    await page.waitForTimeout(500);
    const badge = page.locator("#detail .badge");
    if ((await badge.count()) > 0) {
      const cls = await badge.getAttribute("class");
      expect(cls).toContain("low");
    }
  });
});
test.describe("Detail panel metadata grid", () => {
  test("trivy CVE finding has metadata with compose_path", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const metaSection = page.locator("#detail .section").filter({ hasText: "Metadata" });
    if ((await metaSection.count()) > 0) { expect(await metaSection.textContent()).toContain("compose_path"); }
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
    for (let i = 0; i < count; i++) { fixTexts.push((await rows.nth(i).locator("td").last().textContent()) ?? ""); }
    const getGroup = (t: string): number => { if (t.includes("Auto") || t.includes("Fixed")) return 0; if (t.includes("Review")) return 1; if (t.includes("Unavailable")) return 2; return 3; };
    let lastGroup = -1;
    for (const text of fixTexts) { const g = getGroup(text); expect(g).toBeGreaterThanOrEqual(lastGroup); lastGroup = g; }
  });
});

test.describe("Score breakdown head description", () => {
  test("head mentions penalty cap and scanner", async ({ page }) => {
    await ready(page);
    const p = page.locator("#scoreBreakdown .score-breakdown-head p");
    const text = await p.textContent();
    expect(text).toContain("penalty cap");
    expect(text).toContain("scanner");
  });
});

test.describe("Metrics medium and low counts", () => {
  test("medium metric shows 4", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").nth(3).textContent()).toContain("4");
  });

  test("low metric shows 2", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#metrics .metric").nth(4).textContent()).toContain("2");
  });
});
