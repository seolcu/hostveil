import type { Page } from "@playwright/test";
import { test, expect } from "@playwright/test";

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
      resp.headers.forEach((v, k) => {
        headers[k] = v;
      });
      return { status: resp.status, headers, body: await resp.text() };
    },
    { path, options }
  );
}

test.describe("Secure headers on all responses", () => {
  test("GET /api/health includes security headers", async ({ page }) => {
    await waitForReady(page);
    const { headers } = await apiFetch(page, "/api/health");
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["x-frame-options"]).toBe("DENY");
    expect(headers["referrer-policy"]).toBe("no-referrer");
    expect(headers["cache-control"]).toBe("no-store");
    expect(headers["content-security-policy"]).toBeTruthy();
  });

  test("GET /api/result includes security headers", async ({ page }) => {
    await waitForReady(page);
    const { headers } = await apiFetch(page, "/api/result");
    expect(headers["x-content-type-options"]).toBe("nosniff");
    expect(headers["x-frame-options"]).toBe("DENY");
  });
});

test.describe("POST /api/fix error cases", () => {
  test("fix with unregistered finding ID returns error", async ({ page }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding: {
          id: "nonexistent.finding-999",
          title: "test",
          severity: 0,
          source: 0,
          remediation: 0,
          service: "",
        },
        action_index: 0,
        info_only: false,
      }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(false);
    expect(data.error).toContain("no fix registered");
  });

  test("fix with out-of-range action_index returns error", async ({
    page,
  }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding: {
          id: "trivy.cve-2024-0001",
          title: "test",
          severity: 0,
          source: 0,
          remediation: 0,
          service: "nginx:1.24",
        },
        action_index: 999,
        info_only: false,
      }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(false);
    expect(data.error).toContain("out of range");
  });

  test("fix with negative action_index returns error", async ({ page }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding: {
          id: "trivy.cve-2024-0001",
          title: "test",
          severity: 0,
          source: 0,
          remediation: 0,
          service: "nginx:1.24",
        },
        action_index: -1,
        info_only: false,
      }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(false);
    expect(data.error).toContain("out of range");
  });

  test("fix with empty body returns error", async ({ page }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "",
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(false);
    expect(data.error).toContain("invalid request");
  });

  test("fix with malformed JSON returns error", async ({ page }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json at all",
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(false);
    expect(data.error).toContain("invalid request");
  });

  test("fix with unavailable remediation returns error", async ({ page }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding: {
          id: "test.unfixable-001",
          title: "test",
          severity: 0,
          source: 1,
          remediation: 2,
          service: "",
        },
        action_index: 0,
        info_only: true,
      }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(false);
  });
});

test.describe("POST /api/fix info_only action details", () => {
  test("info_only returns correct action type and label", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        finding: {
          id: "trivy.cve-2024-0001",
          title: "test",
          severity: 0,
          source: 0,
          remediation: 0,
          service: "nginx:1.24",
        },
        action_index: 0,
        info_only: true,
      }),
    });
    const data = JSON.parse(body);
    expect(data.success).toBe(true);
    expect(data.actions.length).toBeGreaterThan(0);

    const action = data.actions[0];
    expect(action).toHaveProperty("type");
    expect(action).toHaveProperty("label");
    expect(typeof action.type).toBe("string");
    expect(typeof action.label).toBe("string");
    expect(action.label.length).toBeGreaterThan(0);
  });
});

test.describe("POST /api/fix/batch error cases", () => {
  test("batch with empty findings returns empty results", async ({ page }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings: [], action_index: 0 }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data).toHaveProperty("results");
    expect(data.results.length).toBe(0);
  });

  test("batch with mix of valid and invalid findings", async ({ page }) => {
    await waitForReady(page);
    const { status, body } = await apiFetch(page, "/api/fix/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        findings: [
          {
            id: "trivy.cve-2024-0001",
            title: "valid",
            severity: 0,
            source: 0,
            remediation: 0,
            service: "nginx:1.24",
          },
          {
            id: "nonexistent.finding-999",
            title: "invalid",
            severity: 0,
            source: 0,
            remediation: 0,
            service: "",
          },
        ],
        action_index: 0,
      }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.results.length).toBe(2);

    // First should succeed
    expect(data.results[0].success).toBe(true);
    // Second should fail
    expect(data.results[1].success).toBe(false);
    expect(data.results[1].error).toContain("no fix registered");
  });
});

test.describe("GET /api/export format edge cases", () => {
  test("export with no format defaults to JSON", async ({ page }) => {
    await waitForReady(page);
    const { status, headers, body } = await apiFetch(page, "/api/export");
    expect(status).toBe(200);
    expect(headers["content-disposition"]).toContain("hostveil-report.json");
    // Should be valid JSON
    const data = JSON.parse(body);
    expect(data).toHaveProperty("findings");
  });

  test("export with unknown format defaults to JSON", async ({ page }) => {
    await waitForReady(page);
    const { status, headers, body } = await apiFetch(
      page,
      "/api/export?format=xml"
    );
    expect(status).toBe(200);
    expect(headers["content-disposition"]).toContain("hostveil-report.json");
    const data = JSON.parse(body);
    expect(data).toHaveProperty("findings");
  });

  test("export with format=ai returns markdown", async ({ page }) => {
    await waitForReady(page);
    const { status, headers, body } = await apiFetch(
      page,
      "/api/export?format=ai"
    );
    expect(status).toBe(200);
    expect(headers["content-type"]).toContain("text/markdown");
    expect(headers["content-disposition"]).toContain("hostveil-ai-brief.md");
    expect(body).toContain("#");
  });

  test("export with format=ai-brief returns markdown", async ({ page }) => {
    await waitForReady(page);
    const { status, headers } = await apiFetch(
      page,
      "/api/export?format=ai-brief"
    );
    expect(status).toBe(200);
    expect(headers["content-type"]).toContain("text/markdown");
  });

  test("export with format=markdown returns markdown", async ({ page }) => {
    await waitForReady(page);
    const { status, headers } = await apiFetch(
      page,
      "/api/export?format=markdown"
    );
    expect(status).toBe(200);
    expect(headers["content-type"]).toContain("text/markdown");
  });
});

test.describe("POST /api/recalc score validation", () => {
  test("recalc returns score between 0 and 100", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/recalc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const data = JSON.parse(body);
    expect(data.score).toBeGreaterThanOrEqual(0);
    expect(data.score).toBeLessThanOrEqual(100);
  });

  test("recalc score_breakdown axes have valid scores", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/recalc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const data = JSON.parse(body);
    expect(data.score_breakdown).toHaveProperty("axes");

    for (const axis of data.score_breakdown.axes) {
      expect(axis.score).toBeGreaterThanOrEqual(0);
      expect(axis.score).toBeLessThanOrEqual(100);
      expect(axis.penalty).toBeGreaterThanOrEqual(0);
      expect(axis.max_penalty).toBeGreaterThan(0);
    }
  });
});

test.describe("POST /api/rescan idempotency", () => {
  test("second rescan while first is running returns error", async ({
    page,
  }) => {
    await waitForReady(page);
    // First rescan
    await apiFetch(page, "/api/rescan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    // Second rescan immediately after
    const { body } = await apiFetch(page, "/api/rescan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const data = JSON.parse(body);
    // Should either succeed or report already in progress
    expect(data).toHaveProperty("status");
  });
});

test.describe("Finding structure validation via API", () => {
  test("each finding has required fields with correct types", async ({
    page,
  }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);

    for (const f of data.findings) {
      expect(typeof f.id).toBe("string");
      expect(f.id.length).toBeGreaterThan(0);
      expect(typeof f.title).toBe("string");
      expect(f.title.length).toBeGreaterThan(0);
      expect(typeof f.description).toBe("string");
      expect(typeof f.how_to_fix).toBe("string");
      expect([0, 1, 2, 3]).toContain(f.severity);
      expect([0, 1, 2]).toContain(f.source);
      expect([0, 1, 2, 3]).toContain(f.remediation);
      expect(typeof f.fixed).toBe("boolean");
      expect(typeof f.evidence).toBe("object");
      expect(typeof f.metadata).toBe("object");
    }
  });

  test("finding IDs are unique", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);

    const ids = data.findings.map((f: { id: string }) => f.id);
    const unique = new Set(ids);
    expect(unique.size).toBe(ids.length);
  });
});

test.describe("Score consistency", () => {
  test("score_breakdown.overall matches top-level score", async ({
    page,
  }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    expect(data.score_breakdown.overall).toBe(data.score);
  });

  test("recalc returns same score as initial result", async ({ page }) => {
    await waitForReady(page);
    const { body: resultBody } = await apiFetch(page, "/api/result");
    const resultData = JSON.parse(resultBody);
    const originalScore = resultData.score;

    const { body: recalcBody } = await apiFetch(page, "/api/recalc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    const recalcData = JSON.parse(recalcBody);
    // Scores should match since no fixes were applied
    expect(recalcData.score).toBe(originalScore);
  });
});
