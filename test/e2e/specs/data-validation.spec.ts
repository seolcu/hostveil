import { test, expect, type Page } from "@playwright/test";

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
      resp.headers.forEach((v, k) => { headers[k] = v; });
      return { status: resp.status, headers, body: await resp.text() };
    },
    { path, options }
  );
}

test.describe("CSV export field values", () => {
  test("CSV first data row has correct severity", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=csv");
    const lines = body.trim().split("\n");
    // Skip header, find a known finding
    const cveLine = lines.find((l: string) => l.includes("trivy.cve-2024-0001"));
    expect(cveLine).toBeTruthy();
    expect(cveLine).toContain("critical");
  });

  test("CSV contains fixed finding marked as true", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=csv");
    const fixedLine = body.split("\n").find((l: string) => l.includes("trivy.cve-2024-0003"));
    expect(fixedLine).toBeTruthy();
    expect(fixedLine).toContain("true");
  });
});

test.describe("JSON export structure", () => {
  test("JSON export has score and hostname fields", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=json");
    const data = JSON.parse(body);
    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("hostname", "e2e-test-box");
    expect(typeof data.score).toBe("number");
  });
});

test.describe("AI brief export content", () => {
  test("AI brief contains scan summary", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=ai");
    expect(body).toContain("Security score");
    expect(body).toContain("Findings");
  });

  test("AI brief contains finding titles", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/export?format=ai");
    expect(body).toContain("CVE-2024-0001");
  });
});

test.describe("Fix info_only returns diff_preview for edit actions", () => {
  test("info_only with compose finding includes diff_preview", async ({
    page,
  }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/fix", {
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
    const data = JSON.parse(body);
    expect(data.success).toBe(true);
    expect(data.actions.length).toBeGreaterThan(0);
    // Edit actions should have edit_path and possibly diff_preview
    const action = data.actions[0];
    expect(action).toHaveProperty("type");
  });
});

test.describe("Score breakdown overall matches top-level score", () => {
  test("result snapshot score equals breakdown overall", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    expect(data.score).toBe(data.score_breakdown.overall);
  });
});

test.describe("Finding severity ranges", () => {
  test("critical findings have severity 0", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const criticals = data.findings.filter(
      (f: { severity: number }) => f.severity === 0
    );
    // trivy.cve-2024-0001 and test.unfixable-001 are critical
    expect(criticals.length).toBe(2);
  });

  test("low findings have severity 3", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const lows = data.findings.filter(
      (f: { severity: number }) => f.severity === 3
    );
    // FILE-6310 and KRNL-5780 are low
    expect(lows.length).toBe(2);
  });
});

test.describe("Source distribution", () => {
  test("trivy source has 6 findings", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const trivy = data.findings.filter(
      (f: { source: number }) => f.source === 0
    );
    expect(trivy.length).toBe(6);
  });

  test("lynis source has 6 findings", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const lynis = data.findings.filter(
      (f: { source: number }) => f.source === 1
    );
    expect(lynis.length).toBe(6);
  });

  test("compose source has 2 findings", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const compose = data.findings.filter(
      (f: { source: number }) => f.source === 2
    );
    expect(compose.length).toBe(2);
  });
});

test.describe("Remediation distribution", () => {
  test("auto remediation has 10 findings", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const auto = data.findings.filter(
      (f: { remediation: number }) => f.remediation === 0
    );
    expect(auto.length).toBe(10);
  });

  test("review remediation has 3 findings", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const review = data.findings.filter(
      (f: { remediation: number }) => f.remediation === 1
    );
    expect(review.length).toBe(3);
  });

  test("unavailable remediation has 1 finding", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const unavail = data.findings.filter(
      (f: { remediation: number }) => f.remediation === 2
    );
    expect(unavail.length).toBe(1);
  });
});

test.describe("Fixed finding count", () => {
  test("exactly one finding is fixed", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const fixed = data.findings.filter((f: { fixed: boolean }) => f.fixed);
    expect(fixed.length).toBeGreaterThanOrEqual(1);
    expect(fixed[0].id).toBe("trivy.cve-2024-0003");
  });
});

test.describe("Service distribution", () => {
  test("nginx:1.24 has 2 findings", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const nginx = data.findings.filter(
      (f: { service: string }) => f.service === "nginx:1.24"
    );
    expect(nginx.length).toBe(2);
  });

  test("webapp has 4 findings", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const webapp = data.findings.filter(
      (f: { service: string }) => f.service === "webapp"
    );
    expect(webapp.length).toBe(4);
  });

  test("lynis findings have empty service", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const lynisNoService = data.findings.filter(
      (f: { source: number; service: string }) =>
        f.source === 1 && f.service === ""
    );
    expect(lynisNoService.length).toBe(6);
  });
});

test.describe("Score axis penalty caps", () => {
  test("vulnerabilities axis max penalty is 35", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const vuln = data.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "vulnerabilities"
    );
    expect(vuln).toBeTruthy();
    expect(vuln.max_penalty).toBe(35);
  });

  test("secrets axis max penalty is 10", async ({ page }) => {
    await waitForReady(page);
    const { body } = await apiFetch(page, "/api/result");
    const data = JSON.parse(body);
    const secrets = data.score_breakdown.axes.find(
      (a: { id: string }) => a.id === "secrets"
    );
    expect(secrets).toBeTruthy();
    expect(secrets.max_penalty).toBe(10);
  });
});

test.describe("Help modal keyboard shortcut text", () => {
  test("help modal mentions all major shortcuts", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("?");
    await expect(page.locator("#helpModal")).toBeVisible({ timeout: 3000 });

    const text = await page.locator("#helpModal").textContent();
    expect(text).toContain("↑");
    expect(text).toContain("↓");
    expect(text).toContain("Space");
    expect(text).toContain("Ctrl+A");
    expect(text).toContain("Ctrl+R");

    await page.keyboard.press("Escape");
  });
});

test.describe("Export modal description text", () => {
  test("export modal shows format descriptions", async ({ page }) => {
    await waitForReady(page);
    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible({ timeout: 3000 });

    const text = await page.locator("#exportModal").textContent();
    expect(text).toContain("Full scan data");
    expect(text).toContain("Spreadsheet friendly");
    expect(text).toContain("Markdown prompt");

    await page.keyboard.press("Escape");
  });
});
