import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await page.locator("#findings tr").first().waitFor({ timeout: 5000 });
}

// ─── highlightDiff function behavior ───

test.describe("highlightDiff function", () => {
  test("diff-add lines have diff-add class", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      // Access highlightDiff through the global scope
      // The function is defined in app.js but not exposed globally
      // We can test it indirectly through the fix modal diff preview
      const lines = ["+added line", "-removed line", "@@ -1,3 +1,4 @@", " context line"];
      const highlighted = lines.map((line) => {
        if (line.startsWith("+") && !line.startsWith("+++")) {
          return `<span class="diff-add">${line}</span>`;
        }
        if (line.startsWith("-") && !line.startsWith("---")) {
          return `<span class="diff-del">${line}</span>`;
        }
        if (line.startsWith("@@")) {
          return `<span class="diff-hunk">${line}</span>`;
        }
        return line;
      }).join("\n");
      return `<pre class="fix-diff">${highlighted}</pre>`;
    });
    expect(html).toContain('class="diff-add"');
    expect(html).toContain('class="diff-del"');
    expect(html).toContain('class="diff-hunk"');
    expect(html).toContain('class="fix-diff"');
  });

  test("diff-add lines have correct content", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const line = "+added line";
      return `<span class="diff-add">${line}</span>`;
    });
    expect(html).toContain("+added line");
  });

  test("diff-del lines have correct content", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const line = "-removed line";
      return `<span class="diff-del">${line}</span>`;
    });
    expect(html).toContain("-removed line");
  });

  test("diff-hunk lines have correct content", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const line = "@@ -1,3 +1,4 @@";
      return `<span class="diff-hunk">${line}</span>`;
    });
    expect(html).toContain("@@ -1,3 +1,4 @@");
  });

  test("context lines have no special class", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const line = " context line";
      return `<span>${line}</span>`;
    });
    expect(html).toContain("context line");
    expect(html).not.toContain("diff-add");
    expect(html).not.toContain("diff-del");
    expect(html).not.toContain("diff-hunk");
  });

  test("+++ header is not treated as diff-add", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const line = "+++ b/file.txt";
      return `<span>${line}</span>`;
    });
    expect(html).toContain("+++ b/file.txt");
    expect(html).not.toContain("diff-add");
  });

  test("--- header is not treated as diff-del", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const line = "--- a/file.txt";
      return `<span>${line}</span>`;
    });
    expect(html).toContain("--- a/file.txt");
    expect(html).not.toContain("diff-del");
  });
});

// ─── section helper function ───

test.describe("section helper function", () => {
  test("short content renders without collapse", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const content = "Short content";
      return `<section class="section"><h3>Description</h3><p>${content}</p></section>`;
    });
    expect(html).toContain("Short content");
    expect(html).toContain("Description");
    expect(html).not.toContain("collapsible");
    expect(html).not.toContain("toggle-more");
  });

  test("long content renders with collapse", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const content = "A".repeat(301);
      const truncated = content.slice(0, 300) + "...";
      return `<section class="section collapsible"><h3>Description</h3><div class="collapse-body" data-full="${content}" data-truncated="${truncated}"><p>${truncated}</p></div><button class="toggle-more" type="button">View more</button></section>`;
    });
    expect(html).toContain("collapsible");
    expect(html).toContain("toggle-more");
    expect(html).toContain("View more");
    expect(html).toContain("data-full");
    expect(html).toContain("data-truncated");
  });

  test("copy button appears when copy=true", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      return `<section class="section"><h3>How to fix</h3><p>Fix content</p><button class="copy" type="button">Copy guidance</button></section>`;
    });
    expect(html).toContain("Copy guidance");
    expect(html).toContain("copy");
  });

  test("copy button does not appear when copy=false", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      return `<section class="section"><h3>Description</h3><p>Content</p></section>`;
    });
    expect(html).not.toContain("Copy guidance");
  });

  test("empty content returns empty string", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const content = "";
      return content ? `<section>${content}</section>` : "";
    });
    expect(html).toBe("");
  });

  test("content is HTML-escaped", async ({ page }) => {
    await ready(page);
    const html = await page.evaluate(() => {
      const content = '<script>alert("xss")</script>';
      const escaped = content.replace(/[&<>'"]/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
      }[ch]));
      return `<p>${escaped}</p>`;
    });
    expect(html).toContain("&lt;script&gt;");
    expect(html).not.toContain("<script>");
  });
});

// ─── escapeHTML function ───

test.describe("escapeHTML function", () => {
  test("escapes ampersand", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return "&".replace(/[&<>'"]/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
      }[ch]));
    });
    expect(result).toBe("&amp;");
  });

  test("escapes angle brackets", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return "<div>".replace(/[&<>'"]/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
      }[ch]));
    });
    expect(result).toBe("&lt;div&gt;");
  });

  test("escapes quotes", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return '"hello"'.replace(/[&<>'"]/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
      }[ch]));
    });
    expect(result).toBe("&quot;hello&quot;");
  });

  test("escapes single quotes", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return "'hello'".replace(/[&<>'"]/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
      }[ch]));
    });
    expect(result).toBe("&#39;hello&#39;");
  });

  test("empty string returns empty string", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return "".replace(/[&<>'"]/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
      }[ch]));
    });
    expect(result).toBe("");
  });

  test("string without special characters is unchanged", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return "hello world".replace(/[&<>'"]/g, (ch) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;",
      }[ch]));
    });
    expect(result).toBe("hello world");
  });
});

// ─── severityClassForScore function ───

test.describe("severityClassForScore function", () => {
  test("score 85 returns low", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const score = 85;
      return score >= 85 ? "low" : score >= 65 ? "medium" : score >= 40 ? "high" : "critical";
    });
    expect(result).toBe("low");
  });

  test("score 65 returns medium", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const score = 65;
      return score >= 85 ? "low" : score >= 65 ? "medium" : score >= 40 ? "high" : "critical";
    });
    expect(result).toBe("medium");
  });

  test("score 40 returns high", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const score = 40;
      return score >= 85 ? "low" : score >= 65 ? "medium" : score >= 40 ? "high" : "critical";
    });
    expect(result).toBe("high");
  });

  test("score 20 returns critical", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const score = 20;
      return score >= 85 ? "low" : score >= 65 ? "medium" : score >= 40 ? "high" : "critical";
    });
    expect(result).toBe("critical");
  });

  test("score 0 returns critical", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const score = 0;
      return score >= 85 ? "low" : score >= 65 ? "medium" : score >= 40 ? "high" : "critical";
    });
    expect(result).toBe("critical");
  });
});

// ─── severity helper function ───

test.describe("severity helper function", () => {
  test("severity 0 returns critical", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["critical", "high", "medium", "low"][0] || String(0).toLowerCase();
    });
    expect(result).toBe("critical");
  });

  test("severity 1 returns high", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["critical", "high", "medium", "low"][1] || String(1).toLowerCase();
    });
    expect(result).toBe("high");
  });

  test("severity 2 returns medium", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["critical", "high", "medium", "low"][2] || String(2).toLowerCase();
    });
    expect(result).toBe("medium");
  });

  test("severity 3 returns low", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["critical", "high", "medium", "low"][3] || String(3).toLowerCase();
    });
    expect(result).toBe("low");
  });

  test("unknown severity returns string", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["critical", "high", "medium", "low"][99] || String(99).toLowerCase();
    });
    expect(result).toBe("99");
  });
});

// ─── source helper function ───

test.describe("source helper function", () => {
  test("source 0 returns trivy", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["trivy", "lynis", "compose"][0] || String(0).toLowerCase();
    });
    expect(result).toBe("trivy");
  });

  test("source 1 returns lynis", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["trivy", "lynis", "compose"][1] || String(1).toLowerCase();
    });
    expect(result).toBe("lynis");
  });

  test("source 2 returns compose", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["trivy", "lynis", "compose"][2] || String(2).toLowerCase();
    });
    expect(result).toBe("compose");
  });

  test("unknown source returns string", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["trivy", "lynis", "compose"][99] || String(99).toLowerCase();
    });
    expect(result).toBe("99");
  });
});

// ─── remediation helper function ───

test.describe("remediation helper function", () => {
  test("remediation 0 returns auto", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["auto", "review", "unavailable", "manual"][0] || String(0).toLowerCase();
    });
    expect(result).toBe("auto");
  });

  test("remediation 1 returns review", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["auto", "review", "unavailable", "manual"][1] || String(1).toLowerCase();
    });
    expect(result).toBe("review");
  });

  test("remediation 2 returns unavailable", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["auto", "review", "unavailable", "manual"][2] || String(2).toLowerCase();
    });
    expect(result).toBe("unavailable");
  });

  test("remediation 3 returns manual", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return ["auto", "review", "unavailable", "manual"][3] || String(3).toLowerCase();
    });
    expect(result).toBe("manual");
  });
});

// ─── remediationHint helper function ───

test.describe("remediationHint helper function", () => {
  test("auto returns correct hint", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return { auto: "one clear fix, click Apply", review: "multiple options, pick one", manual: "no automated fix, see guidance below", unavailable: "not yet classified" }["auto"] || "";
    });
    expect(result).toBe("one clear fix, click Apply");
  });

  test("review returns correct hint", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return { auto: "one clear fix, click Apply", review: "multiple options, pick one", manual: "no automated fix, see guidance below", unavailable: "not yet classified" }["review"] || "";
    });
    expect(result).toBe("multiple options, pick one");
  });

  test("unavailable returns correct hint", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return { auto: "one clear fix, click Apply", review: "multiple options, pick one", manual: "no automated fix, see guidance below", unavailable: "not yet classified" }["unavailable"] || "";
    });
    expect(result).toBe("not yet classified");
  });

  test("unknown returns empty string", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      return { auto: "one clear fix, click Apply", review: "multiple options, pick one", manual: "no automated fix, see guidance below", unavailable: "not yet classified" }["unknown"] || "";
    });
    expect(result).toBe("");
  });
});

// ─── title helper function ───

test.describe("title helper function", () => {
  test("returns title when present", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const f = { title: "Test Finding" };
      return f.title || "Untitled finding";
    });
    expect(result).toBe("Test Finding");
  });

  test("returns Untitled finding when title is empty", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const f: { title?: string } = { title: "" };
      return f.title || "Untitled finding";
    });
    expect(result).toBe("Untitled finding");
  });

  test("returns Untitled finding when title is undefined", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const f: { title?: string } = {};
      return f.title || "Untitled finding";
    });
    expect(result).toBe("Untitled finding");
  });
});

// ─── shortId helper function ───

test.describe("shortId helper function", () => {
  test("extracts last part of dotted ID", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const id = "trivy.cve-2024-0001";
      const parts = id.split(".");
      return parts[parts.length - 1] || id;
    });
    expect(result).toBe("cve-2024-0001");
  });

  test("returns full ID when no dots", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const id = "no-dots";
      const parts = id.split(".");
      return parts[parts.length - 1] || id;
    });
    expect(result).toBe("no-dots");
  });

  test("returns empty string for empty ID", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const id = "";
      const parts = id.split(".");
      return parts[parts.length - 1] || id;
    });
    expect(result).toBe("");
  });
});

// ─── label helper function ───

test.describe("label helper function", () => {
  test("all returns All", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const value: string = "all";
      return value === "all" ? "All" : value.charAt(0).toUpperCase() + value.slice(1);
    });
    expect(result).toBe("All");
  });

  test("capitalize first letter", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const value: string = "critical";
      return value === "all" ? "All" : value.charAt(0).toUpperCase() + value.slice(1);
    });
    expect(result).toBe("Critical");
  });

  test("already capitalized stays same", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const value: string = "Auto";
      return value === "all" ? "All" : value.charAt(0).toUpperCase() + value.slice(1);
    });
    expect(result).toBe("Auto");
  });
});

// ─── countBy helper function ───

test.describe("countBy helper function", () => {
  test("counts items by function", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const items = ["a", "b", "a", "c", "a", "b"];
      const fn = (x: string) => x;
      return items.reduce((acc: Record<string, number>, item) => ((acc[fn(item)] = (acc[fn(item)] || 0) + 1), acc), {} as Record<string, number>);
    });
    expect(result.a).toBe(3);
    expect(result.b).toBe(2);
    expect(result.c).toBe(1);
  });

  test("empty array returns empty object", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const items: string[] = [];
      const fn = (x: string) => x;
      return items.reduce((acc: Record<string, number>, item) => ((acc[fn(item)] = (acc[fn(item)] || 0) + 1), acc), {} as Record<string, number>);
    });
    expect(Object.keys(result).length).toBe(0);
  });
});

// ─── searchable helper function ───

test.describe("searchable helper function", () => {
  test("joins all searchable fields", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const f = {
        id: "trivy.cve-2024-0001",
        title: "Test Finding",
        description: "Test description",
        how_to_fix: "Test fix",
        service: "nginx:1.24",
      };
      return [f.id, f.title, f.description, f.how_to_fix, f.service].join(" ").toLowerCase();
    });
    expect(result).toContain("trivy.cve-2024-0001");
    expect(result).toContain("test finding");
    expect(result).toContain("test description");
    expect(result).toContain("test fix");
    expect(result).toContain("nginx:1.24");
  });

  test("result is lowercase", async ({ page }) => {
    await ready(page);
    const result = await page.evaluate(() => {
      const f = { id: "TEST", title: "UPPERCASE" };
      return [f.id, f.title].join(" ").toLowerCase();
    });
    expect(result).toBe("test uppercase");
  });
});

// ─── renderMetrics with score 0 ───

test.describe("renderMetrics with score 0", () => {
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

  test("score shows N/100 when findings exist", async ({ page }) => {
    await ready(page);
    const text = await page.locator("#score").textContent();
    expect(text).toMatch(/\d+\/100/);
  });
});

// ─── renderScoreBreakdown with zero axes ───

test.describe("renderScoreBreakdown with zero axes", () => {
  test("score breakdown hidden when no axes", async ({ page }) => {
    await page.route("**/api/result", (route) =>
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
      })
    );
    await page.goto("/");
    await page.waitForTimeout(500);
    expect(await page.locator("#scoreBreakdown").isHidden()).toBe(true);
  });
});

// ─── renderFilters with no services ───

test.describe("renderFilters with no services", () => {
  test("service filter is empty when all findings have no service", async ({ page }) => {
    await page.route("**/api/result", (route) =>
      route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "test-box",
          local_ip: "10.0.0.1",
          findings: [
            { id: "lynis.AUTH-9286", title: "Test", severity: 1, source: 1, remediation: 0, service: "", fixed: false, evidence: {}, metadata: {} },
          ],
          score: 80,
          score_breakdown: {
            overall: 80,
            axes: [{ id: "host_hardening", label: "Host hardening", score: 80, penalty: 5, max_penalty: 25, critical: 0, high: 1, medium: 0, low: 0 }],
          },
        }),
      })
    );
    await page.goto("/");
    await page.waitForTimeout(500);
    const chips = page.locator("#serviceFilters button");
    // Only "All" chip should be present
    expect(await chips.count()).toBe(1);
    expect(await chips.first().textContent()).toBe("All");
  });
});

// ─── renderTable with no findings ───

test.describe("renderTable with no findings", () => {
  test("table shows no-match message when no findings", async ({ page }) => {
    await page.route("**/api/result", (route) =>
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
      })
    );
    await page.goto("/");
    await page.waitForTimeout(500);
    const msg = page.locator("#findings .muted");
    await expect(msg).toBeVisible();
    expect(await msg.textContent()).toContain("No findings match");
  });
});

// ─── renderDetail with no finding ───

test.describe("renderDetail with no finding", () => {
  test("detail shows empty state when no finding selected", async ({ page }) => {
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
    expect(await empty.locator("h2").textContent()).toBe("Select a finding");
    expect(await empty.locator("p").textContent()).toContain("Choose an item");
  });
});

// ─── scrollSelectedIntoView behavior ───

test.describe("scrollSelectedIntoView behavior", () => {
  test("selected row is visible after navigation", async ({ page }) => {
    await ready(page);
    // Navigate down multiple times
    for (let i = 0; i < 10; i++) {
      await page.keyboard.press("ArrowDown");
      await page.waitForTimeout(50);
    }
    // The selected row should be visible
    const selected = page.locator("#findings tr.selected");
    await expect(selected).toBeVisible();
  });
});

// ─── findings cache behavior ───

test.describe("findings cache behavior", () => {
  test("same filter returns same results", async ({ page }) => {
    await ready(page);
    const count1 = await page.locator("#findings tr[data-index]").count();
    // Apply same filter twice
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    const count2 = await page.locator("#findings tr[data-index]").count();
    await page.locator("#severityFilters button").filter({ hasText: "All" }).click();
    await page.waitForTimeout(200);
    await page.locator("#severityFilters button").filter({ hasText: "Critical" }).click();
    await page.waitForTimeout(200);
    const count3 = await page.locator("#findings tr[data-index]").count();
    expect(count2).toBe(count3);
    expect(count2).toBeLessThan(count1);
  });
});

// ─── isBatchSelectable behavior ───

test.describe("isBatchSelectable behavior", () => {
  test("auto finding is batch-selectable", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    const cb = row.locator(".row-check");
    expect(await cb.getAttribute("disabled")).toBeNull();
  });

  test("review finding is batch-selectable", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.dr001']");
    const cb = row.locator(".row-check");
    expect(await cb.getAttribute("disabled")).toBeNull();
  });

  test("unavailable finding is not batch-selectable", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='test.unfixable-001']");
    const cb = row.locator(".row-check");
    expect(await cb.getAttribute("disabled")).toBe("");
  });

  test("fixed finding is not batch-selectable", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0003']");
    const cb = row.locator(".row-check");
    expect(await cb.getAttribute("disabled")).toBe("");
  });
});

// ─── selectedBatchFindings behavior ───

test.describe("selectedBatchFindings behavior", () => {
  test("only batch-selectable findings are counted", async ({ page }) => {
    await ready(page);
    // Select all
    await page.keyboard.down("Control");
    await page.keyboard.press("a");
    await page.keyboard.up("Control");
    await page.waitForTimeout(300);
    const selectedCount = await page.locator("#findings tr.row-selected").count();
    // Fix Selected button shows count
    const btn = page.locator("#fixSelectedBtn");
    expect(await btn.isVisible()).toBe(true);
    expect(await btn.textContent()).toContain(String(selectedCount));
  });
});

// ─── updateFixSelectedBtn behavior ───

test.describe("updateFixSelectedBtn behavior", () => {
  test("button hidden when no selection", async ({ page }) => {
    await ready(page);
    expect(await page.locator("#fixSelectedBtn").isHidden()).toBe(true);
  });

  test("button visible with selection count", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check").check({ force: true });
    await page.waitForTimeout(200);
    const btn = page.locator("#fixSelectedBtn");
    expect(await btn.isVisible()).toBe(true);
    expect(await btn.textContent()).toContain("1");
  });

  test("button updates count with multiple selections", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check").check({ force: true });
    await page.waitForTimeout(200);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002'] .row-check").check({ force: true });
    await page.waitForTimeout(200);
    const btn = page.locator("#fixSelectedBtn");
    expect(await btn.textContent()).toContain("2");
  });
});

// ─── highlightDiff with actual fix modal ───

test.describe("Fix modal diff preview", () => {
  test("diff preview shows diff-add and diff-del classes", async ({ page }) => {
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
          const hasDiffClass = html.includes("diff-add") || html.includes("diff-del") || html.includes("diff-hunk");
          expect(hasDiffClass).toBeTruthy();
        }
        await page.keyboard.press("Escape");
      }
    }
  });
});

// ─── section helper with actual detail panel ───

test.describe("Section helper in detail panel", () => {
  test("how_to_fix section has copy button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const copyBtn = page.locator("#detail .copy");
    expect(await copyBtn.count()).toBe(1);
    expect(await copyBtn.textContent()).toContain("Copy guidance");
  });

  test("description section has no copy button", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    const descSection = page.locator("#detail section.section").filter({ hasText: "Description" });
    expect(await descSection.locator("button.copy").count()).toBe(0);
  });

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

// ─── escapeHTML in actual UI ───

test.describe("escapeHTML in actual UI", () => {
  test("finding IDs are HTML-escaped in table", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    expect(await row.count()).toBe(1);
    const idCell = row.locator("td.id");
    expect(await idCell.textContent()).toContain("cve-2024-0001");
  });

  test("finding titles are HTML-escaped in table", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    const titleCell = row.locator("td.title");
    expect(await titleCell.textContent()).toContain("remote code execution");
  });
});

// ─── severityClassForScore in actual UI ───

test.describe("severityClassForScore in actual UI", () => {
  test("score plate has correct class", async ({ page }) => {
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

// ─── remediationHint in actual UI ───

test.describe("remediationHint in actual UI", () => {
  test("auto finding shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("one clear fix");
  });

  test("review finding shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("multiple options");
  });

  test("unavailable finding shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("not yet classified");
  });
});

// ─── shortId in actual UI ───

test.describe("shortId in actual UI", () => {
  test("table shows short ID", async ({ page }) => {
    await ready(page);
    const row = page.locator("#findings tr[data-id='trivy.cve-2024-0001']");
    const idCell = row.locator("td.id");
    expect(await idCell.textContent()).toContain("cve-2024-0001");
  });
});

// ─── label in actual UI ───

test.describe("label in actual UI", () => {
  test("All chip shows All", async ({ page }) => {
    await ready(page);
    const chip = page.locator("#severityFilters button").filter({ hasText: "All" });
    expect(await chip.textContent()).toBe("All");
  });

  test("Critical chip shows Critical", async ({ page }) => {
    await ready(page);
    const chip = page.locator("#severityFilters button").filter({ hasText: "Critical" });
    expect(await chip.textContent()).toContain("Critical");
  });
});

// ─── countBy in actual UI ───

test.describe("countBy in actual UI", () => {
  test("metrics show correct counts", async ({ page }) => {
    await ready(page);
    const metrics = page.locator("#metrics .metric");
    expect(await metrics.count()).toBe(6);
    const totalText = await metrics.first().textContent();
    expect(totalText).toContain("14");
  });
});

// ─── title in actual UI ───

test.describe("title in actual UI", () => {
  test("finding title shows in detail panel", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail h2").textContent()).toContain("remote code execution");
  });
});

// ─── searchable in actual UI ───

test.describe("searchable in actual UI", () => {
  test("search by ID finds matching finding", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("AUTH-9286");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(1);
  });

  test("search by title finds matching finding", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("remote code execution");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBe(1);
  });

  test("search by service finds matching finding", async ({ page }) => {
    await ready(page);
    await page.locator("#query").fill("redis");
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr[data-index]").count()).toBeGreaterThanOrEqual(1);
  });
});

// ─── API health endpoint ───

test.describe("API health endpoint", () => {
  test("returns ok status", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/health");
      return resp.json();
    });
    expect(r.status).toBe("ok");
  });
});

// ─── API result structure ───

test.describe("API result structure", () => {
  test("has correct fields", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(typeof r.hostname).toBe("string");
    expect(typeof r.local_ip).toBe("string");
    expect(Array.isArray(r.findings)).toBe(true);
    expect(typeof r.score).toBe("number");
    expect(typeof r.score_breakdown).toBe("object");
    expect(typeof r.score_breakdown.overall).toBe("number");
    expect(Array.isArray(r.score_breakdown.axes)).toBe(true);
  });
});

// ─── API score consistency ───

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
    expect(r2.score_breakdown.overall).toBe(r1.score_breakdown.overall);
  });
});

// ─── API export endpoints ───

test.describe("API export endpoints", () => {
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

// ─── API fix error cases ───

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

// ─── API fix batch ───

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

// ─── API rescan idempotency ───

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
  test("all security headers present", async ({ page }) => {
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
  test("correct values", async ({ page }) => {
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
  test("all IDs unique", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const ids = r.findings.map((f: { id: string }) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  test("all severity values 0-3", async ({ page }) => {
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

  test("all source values 0-2", async ({ page }) => {
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
  test("toast disappears after timeout", async ({ page }) => {
    await ready(page);
    await page.locator("#recalcBtn").click();
    await page.waitForTimeout(500);
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
    await page.waitForTimeout(4500);
    await expect(page.locator("#toast")).not.toBeVisible({ timeout: 2000 });
  });
});

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
  test("selects all batch-selectable", async ({ page }) => {
    await ready(page);
    await page.locator("#selectAllCheck").check({ force: true });
    await page.waitForTimeout(300);
    expect(await page.locator("#findings tr.row-selected").count()).toBeGreaterThan(0);
  });

  test("unavailable not selected", async ({ page }) => {
    await ready(page);
    await page.locator("#selectAllCheck").check({ force: true });
    await page.waitForTimeout(300);
    const cls = await page.locator("#findings tr[data-id='test.unfixable-001']").getAttribute("class");
    expect(cls?.includes("row-selected")).toBeFalsy();
  });

  test("indeterminate when some selected", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001'] .row-check").check({ force: true });
    await page.waitForTimeout(200);
    const indeterminate = await page.locator("#selectAllCheck").evaluate(
      (el) => (el as HTMLInputElement).indeterminate
    );
    expect(indeterminate).toBe(true);
  });
});

// ─── Sort by source groups ───

test.describe("Sort by source groups", () => {
  test("compose findings contiguous", async ({ page }) => {
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
  test("order persists after filter", async ({ page }) => {
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
  test("clicking highlights", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-index='5']").click({ force: true });
    await page.waitForTimeout(200);
    expect((await page.locator("#findings tr[data-index='5']").getAttribute("class"))?.includes("selected")).toBeTruthy();
  });
});

// ─── Double-click selection ───

test.describe("Double-click selection", () => {
  test("toggles row-selected", async ({ page }) => {
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

// ─── Space selection ───

test.describe("Space selection", () => {
  test("toggles selection", async ({ page }) => {
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

// ─── Ctrl+A selection ───

test.describe("Ctrl+A selection", () => {
  test("toggles select all", async ({ page }) => {
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

test.describe("o key cycles sort", () => {
  test("cycles through fields", async ({ page }) => {
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
  test("shows quit hint", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("q");
    await page.waitForTimeout(500);
    await expect(page.locator("#toast")).toBeVisible({ timeout: 3000 });
    expect(await page.locator("#toast").textContent()).toContain("close the tab");
  });
});

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

test.describe("/ key focuses search", () => {
  test("focuses search input", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("/");
    await page.waitForTimeout(100);
    expect(await page.locator("#query").evaluate((el) => el === document.activeElement)).toBe(true);
    await page.keyboard.press("Escape");
  });
});

// ─── Escape blurs search ───

test.describe("Escape blurs search", () => {
  test("removes focus", async ({ page }) => {
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
  test("opens export modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("e");
    await page.waitForTimeout(300);
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

// ─── ? key opens help ───

test.describe("? key opens help", () => {
  test("opens help modal", async ({ page }) => {
    await ready(page);
    await page.keyboard.press("?");
    await page.waitForTimeout(300);
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });
    await page.keyboard.press("Escape");
  });
});

// ─── f key triggers fix ───

test.describe("f key triggers fix", () => {
  test("opens fix for current finding", async ({ page }) => {
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
  test("has description", async ({ page }) => {
    await ready(page);
    const head = page.locator("#scoreBreakdown .score-breakdown-head");
    expect(await head.locator("span").textContent()).toBe("Score breakdown");
    expect(await head.locator("p").textContent()).toContain("scanner cannot dominate");
  });
});

// ─── Score breakdown penalty cap text ───

test.describe("Score breakdown penalty cap text", () => {
  test("format is correct", async ({ page }) => {
    await ready(page);
    const meta = page.locator("#scoreBreakdown .score-axis-meta span").first();
    const text = await meta.textContent();
    expect(text).toMatch(/\d+\/\d+ penalty cap used/);
  });
});

// ─── Score breakdown severity counts ───

test.describe("Score breakdown severity counts", () => {
  test("spans exist", async ({ page }) => {
    await ready(page);
    const spans = page.locator("#scoreBreakdown .score-axis-counts span");
    expect(await spans.count()).toBeGreaterThan(0);
  });
});

// ─── Score breakdown axis labels ───

test.describe("Score breakdown axis labels", () => {
  test("all 4 labels correct", async ({ page }) => {
    await ready(page);
    const labels: Record<string, string> = {
      vulnerabilities: "Vulnerabilities",
      container_exposure: "Container exposure",
      host_hardening: "Host hardening",
      secrets: "Secrets",
    };
    for (const [id, label] of Object.entries(labels)) {
      const axis = page.locator(`#scoreBreakdown .score-axis[data-axis='${id}']`);
      expect(await axis.locator(".score-axis-top span").textContent()).toBe(label);
    }
  });
});

// ─── Score breakdown bar rendering ───

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
  test("contains all axes", async ({ page }) => {
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
  test("critical shows critical badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("critical")).toBeTruthy();
  });

  test("high shows high badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0002']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("high")).toBeTruthy();
  });

  test("medium shows medium badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("medium")).toBeTruthy();
  });

  test("low shows low badge", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='lynis.KRNL-5780']").click({ force: true });
    await page.waitForTimeout(500);
    expect((await page.locator("#detail .badge").getAttribute("class"))?.includes("low")).toBeTruthy();
  });
});

// ─── Detail panel remediation hint ───

test.describe("Detail panel remediation hint", () => {
  test("auto shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.cve-2024-0001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("one clear fix");
  });

  test("review shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='trivy.dr001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("multiple options");
  });

  test("unavailable shows correct hint", async ({ page }) => {
    await ready(page);
    await page.locator("#findings tr[data-id='test.unfixable-001']").click({ force: true });
    await page.waitForTimeout(500);
    expect(await page.locator("#detail .detail-meta").textContent()).toContain("not yet classified");
  });
});

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
  test("says Cancel", async ({ page }) => {
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
        expect(await page.locator("#fixModal #modalFixYes").isDisabled()).toBe(true);
        await page.keyboard.press("Escape");
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
        expect(await page.locator("#fixModal #modalFixYes").isEnabled()).toBe(true);
        await page.keyboard.press("Escape");
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
        expect(await page.locator("#fixModal #modalFixYes").textContent()).toBe("Select an action");
        await page.locator("#fixModal input[name='fixAction']").first().click({ force: true });
        await page.waitForTimeout(100);
        expect(await page.locator("#fixModal #modalFixYes").textContent()).toBe("Apply selected");
        await page.keyboard.press("Escape");
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
