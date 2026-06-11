import { test, expect } from "@playwright/test";

const EXPECTED_TOTAL = 14;

async function apiFetch(page: any, path: string, options?: RequestInit) {
  return page.evaluate(
    ({ path, options }: { path: string; options?: RequestInit }) =>
      fetch(path, options).then(async (r) => ({
        status: r.status,
        headers: Object.fromEntries(r.headers.entries()),
        body: await r.text(),
      })),
    { path, options }
  );
}

test.describe("API contract", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({
      timeout: 5000,
    });
  });

  test("GET /api/health returns { status: ok }", async ({ page }) => {
    const { status, body } = await apiFetch(page, "/api/health");
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data).toEqual({ status: "ok" });
  });

  test("GET /api/result returns valid Snapshot schema", async ({ page }) => {
    const { status, body } = await apiFetch(page, "/api/result");
    expect(status).toBe(200);
    const data = JSON.parse(body);

    expect(data).toHaveProperty("phase", "complete");
    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("tools");
    expect(data).toHaveProperty("hostname", "e2e-test-box");
    expect(data).toHaveProperty("local_ip", "192.168.1.100");
    expect(data).toHaveProperty("score_breakdown");

    expect(typeof data.score).toBe("number");
    expect(Array.isArray(data.findings)).toBe(true);
    expect(data.findings.length).toBe(EXPECTED_TOTAL);

    // score_breakdown structure
    expect(data.score_breakdown).toHaveProperty("overall");
    expect(data.score_breakdown).toHaveProperty("axes");
    expect(Array.isArray(data.score_breakdown.axes)).toBe(true);
    for (const axis of data.score_breakdown.axes) {
      expect(axis).toHaveProperty("id");
      expect(axis).toHaveProperty("label");
      expect(axis).toHaveProperty("score");
      expect(axis).toHaveProperty("penalty");
      expect(axis).toHaveProperty("max_penalty");
    }

    // tools structure
    for (const key of Object.keys(data.tools)) {
      const tool = data.tools[key];
      expect(tool).toHaveProperty("status");
      expect(typeof tool.status).toBe("number");
    }

    // each finding structure
    for (const f of data.findings) {
      expect(f).toHaveProperty("id");
      expect(f).toHaveProperty("title");
      expect(f).toHaveProperty("severity");
      expect(f).toHaveProperty("source");
      expect(f).toHaveProperty("remediation");
      expect(typeof f.id).toBe("string");
      expect(typeof f.title).toBe("string");
      expect([0, 1, 2, 3]).toContain(f.severity);
      expect([0, 1, 2]).toContain(f.source);
      expect([0, 1, 2, 3]).toContain(f.remediation);
    }
  });

  test("POST /api/fix info_only returns action metadata", async ({
    page,
  }) => {
    const finding = {
      id: "trivy.cve-2024-0001",
      title: "test",
      severity: 0,
      source: 0,
      remediation: 0,
      service: "nginx:1.24",
    };
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding, action_index: 0, info_only: true }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(true);
    expect(data).toHaveProperty("label");
    expect(data).toHaveProperty("actions");
    expect(Array.isArray(data.actions)).toBe(true);
    expect(data.actions.length).toBeGreaterThan(0);

    for (const action of data.actions) {
      expect(action).toHaveProperty("type");
      expect(action).toHaveProperty("label");
      expect(typeof action.index).toBe("number");
    }
  });

  test("POST /api/fix actual applies fix and returns result", async ({
    page,
  }) => {
    const finding = {
      id: "trivy.cve-2024-0001",
      title: "test",
      severity: 0,
      source: 0,
      remediation: 0,
      service: "nginx:1.24",
    };
    const { status, body } = await apiFetch(page, "/api/fix", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ finding, action_index: 0, info_only: false }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data.success).toBe(true);
    expect(data).toHaveProperty("label");
  });

  test("POST /api/recalc returns Snapshot with score_breakdown", async ({
    page,
  }) => {
    const { status, body } = await apiFetch(page, "/api/recalc", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data).toHaveProperty("phase", "complete");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("score_breakdown");
    expect(data.score_breakdown).toHaveProperty("overall");
    expect(data.score_breakdown).toHaveProperty("axes");
    expect(data.score_breakdown.axes.length).toBeGreaterThan(0);
  });

  test("POST /api/rescan returns rescanning status", async ({ page }) => {
    const { status, body } = await apiFetch(page, "/api/rescan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data).toHaveProperty("status", "rescanning");
  });

  test("GET /api/export format=json returns valid JSON download", async ({
    page,
  }) => {
    const { status, headers, body } = await apiFetch(
      page,
      "/api/export?format=json"
    );
    expect(status).toBe(200);
    expect(headers["content-disposition"]).toContain("hostveil-report.json");
    const data = JSON.parse(body);
    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("phase");
  });

  test("GET /api/export format=csv returns valid CSV download", async ({
    page,
  }) => {
    const { status, headers, body } = await apiFetch(
      page,
      "/api/export?format=csv"
    );
    expect(status).toBe(200);
    expect(headers["content-disposition"]).toContain("hostveil-report.csv");
    expect(headers["content-type"]).toContain("text/csv");

    const lines = body.trim().split("\n");
    expect(lines.length).toBe(EXPECTED_TOTAL + 1); // header + 12 data rows
    expect(lines[0]).toBe(
      "ID,Severity,Source,Service,Title,Description,Remediation,Fixed"
    );

    // verify first data row has valid severity
    const firstRow = lines[1];
    const fields = firstRow.split(",");
    expect(["critical", "high", "medium", "low"]).toContain(fields[1]);
  });

  test("POST /api/fix/batch returns results array", async ({ page }) => {
    const findings = [
      {
        id: "trivy.cve-2024-0001",
        title: "test1",
        severity: 0,
        source: 0,
        remediation: 0,
        service: "nginx:1.24",
      },
      {
        id: "lynis.AUTH-9286",
        title: "test2",
        severity: 1,
        source: 1,
        remediation: 0,
        service: "",
      },
    ];
    const { status, body } = await apiFetch(page, "/api/fix/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ findings, action_index: 0 }),
    });
    expect(status).toBe(200);
    const data = JSON.parse(body);
    expect(data).toHaveProperty("results");
    expect(Array.isArray(data.results)).toBe(true);
    expect(data.results.length).toBe(2);

    for (const result of data.results) {
      expect(result).toHaveProperty("id");
      expect(result).toHaveProperty("success");
      expect(typeof result.success).toBe("boolean");
    }
  });
});
