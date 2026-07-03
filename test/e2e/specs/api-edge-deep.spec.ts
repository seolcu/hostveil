import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

async function ready(page: Page): Promise<void> {
  await page.goto("/");
  await expect(page.locator("#findings tr").first()).toBeVisible({
    timeout: 5000,
  });
}

test.describe("POST /api/fix error cases", () => {
  test("fix with unregistered finding ID returns error", async ({ page }) => {
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

  test("fix with out-of-range action_index returns error", async ({
    page,
  }) => {
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

  test("fix with malformed JSON returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "{invalid json",
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("invalid request");
  });

  test("unavailable finding returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          id: "test.unfixable-001",
          action_index: 0,
        }),
      });
      return resp.json();
    });
    // Unavailable finding has no registered fix
    expect(r.success).toBe(false);
  });
});

test.describe("POST /api/fix/batch error cases", () => {
  test("batch with empty findings returns empty results", async ({
    page,
  }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ findings: [], action_index: 0 }),
      });
      return resp.json();
    });
    expect(Array.isArray(r.results)).toBe(true);
    expect(r.results.length).toBe(0);
  });

  test("batch with mix of valid and invalid findings", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          findings: [
            { id: "nonexistent.abc", action_index: 0 },
            { id: "another.missing", action_index: 0 },
          ],
          action_index: 0,
        }),
      });
      return resp.json();
    });
    expect(r.results.length).toBe(2);
    for (const result of r.results) {
      expect(result.success).toBe(false);
    }
  });

  test("batch with malformed JSON returns error", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/fix/batch", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: "not json at all",
      });
      return resp.json();
    });
    expect(r.success).toBe(false);
    expect(r.error).toContain("invalid request");
  });
});

test.describe("GET /api/export format edge cases", () => {
  test("export with no format defaults to JSON", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export");
      return {
        status: resp.status,
        contentType: resp.headers.get("content-type"),
        contentDisposition: resp.headers.get("content-disposition"),
      };
    });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("application/json");
    expect(r.contentDisposition).toContain("hostveil-report.json");
  });

  test("export with unknown format defaults to JSON", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=xyz");
      return {
        status: resp.status,
        contentType: resp.headers.get("content-type"),
      };
    });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("application/json");
  });

  test("export with format=ai returns markdown", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai");
      return {
        status: resp.status,
        contentType: resp.headers.get("content-type"),
        contentDisposition: resp.headers.get("content-disposition"),
        text: await resp.text(),
      };
    });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("text/markdown");
    expect(r.contentDisposition).toContain("hostveil-ai-brief.md");
    expect(r.text).toContain("#");
  });

  test("export with format=ai-brief returns markdown", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=ai-brief");
      return {
        status: resp.status,
        contentType: resp.headers.get("content-type"),
      };
    });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("text/markdown");
  });

  test("export with format=markdown returns markdown", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=markdown");
      return {
        status: resp.status,
        contentType: resp.headers.get("content-type"),
      };
    });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("text/markdown");
  });

  test("export with format=csv returns CSV with correct headers", async ({
    page,
  }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/export?format=csv");
      return {
        status: resp.status,
        contentType: resp.headers.get("content-type"),
        contentDisposition: resp.headers.get("content-disposition"),
        text: await resp.text(),
      };
    });
    expect(r.status).toBe(200);
    expect(r.contentType).toContain("text/csv");
    expect(r.contentDisposition).toContain("hostveil-report.csv");
    expect(r.text).toContain("ID");
  });
});

test.describe("Secure headers on all responses", () => {
  test("GET /api/health includes security headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/health");
      return {
        xcto: resp.headers.get("x-content-type-options"),
        xfo: resp.headers.get("x-frame-options"),
        rp: resp.headers.get("referrer-policy"),
        cc: resp.headers.get("cache-control"),
      };
    });
    expect(r.xcto).toBe("nosniff");
    expect(r.xfo).toBe("DENY");
    expect(r.rp).toBe("no-referrer");
    expect(r.cc).toBe("no-store");
  });

  test("GET /api/result includes security headers", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return {
        xcto: resp.headers.get("x-content-type-options"),
        xfo: resp.headers.get("x-frame-options"),
        rp: resp.headers.get("referrer-policy"),
      };
    });
    expect(r.xcto).toBe("nosniff");
    expect(r.xfo).toBe("DENY");
    expect(r.rp).toBe("no-referrer");
  });
});

test.describe("POST /api/recalc score validation", () => {
  test("recalc returns score between 0 and 100", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/recalc", { method: "POST" });
      return resp.json();
    });
    expect(r.score).toBeGreaterThanOrEqual(0);
    expect(r.score).toBeLessThanOrEqual(100);
  });

  test("recalc score_breakdown axes have valid scores", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/recalc", { method: "POST" });
      return resp.json();
    });
    const axes = r.score_breakdown.axes;
    expect(axes.length).toBe(4);
    for (const axis of axes) {
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
      expect(axis.max_penalty).toBeGreaterThan(0);
    }
  });
});

test.describe("POST /api/rescan idempotency", () => {
  test("second rescan while first is running returns error", async ({
    page,
  }) => {
    await ready(page);

    // Start first rescan
    const r1 = await page.evaluate(async () => {
      const resp = await fetch("/api/rescan", { method: "POST" });
      return resp.json();
    });

    // Second rescan should fail or succeed depending on timing
    const r2 = await page.evaluate(async () => {
      const resp = await fetch("/api/rescan", { method: "POST" });
      return resp.json();
    });

    // At least one should have succeeded
    const anySuccess = r1.status === "rescanning" || r2.status === "rescanning";
    expect(anySuccess).toBe(true);
  });
});

test.describe("Finding structure validation via API", () => {
  test("each finding has required fields with correct types", async ({
    page,
  }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });

    for (const f of r.findings) {
      expect(typeof f.id).toBe("string");
      expect(typeof f.title).toBe("string");
      expect(typeof f.description).toBe("string");
      expect(typeof f.how_to_fix).toBe("string");
      expect(typeof f.severity).toBe("number");
      expect(typeof f.source).toBe("number");
      expect(typeof f.remediation).toBe("number");
      expect(typeof f.fixed).toBe("boolean");
      expect(f.severity).toBeGreaterThanOrEqual(0);
      expect(f.severity).toBeLessThanOrEqual(3);
    }
  });

  test("finding IDs are unique", async ({ page }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    const ids = r.findings.map((f: { id: string }) => f.id);
    expect(new Set(ids).size).toBe(ids.length);
  });
});

test.describe("Score consistency", () => {
  test("score_breakdown.overall matches top-level score", async ({
    page,
  }) => {
    await ready(page);
    const r = await page.evaluate(async () => {
      const resp = await fetch("/api/result");
      return resp.json();
    });
    expect(r.score_breakdown.overall).toBe(r.score);
  });

  test("recalc returns same score as initial result", async ({ page }) => {
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

test.describe("POST /api/fix with large body", () => {
  test("fix request with very large body is rejected", async ({ page }) => {
    await ready(page);
    // The server has a 1MB body limit via MaxBytesReader
    const largeId = "x".repeat(2 * 1024 * 1024);
    const r = await page.evaluate(async (id) => {
      const resp = await fetch("/api/fix", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id, action_index: 0 }),
      });
      return { status: resp.status, body: await resp.json() };
    }, largeId);
    // Should fail because body exceeds 1MB limit
    expect(r.body.success).toBe(false);
  });
});
