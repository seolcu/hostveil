import { test, expect } from "@playwright/test";

/**
 * Regression tests for the XSS surface in the Web UI.
 *
 * Description / how_to_fix / evidence / metadata text in findings originates
 * from external sources (Trivy reports, Lynis reports, user-edited compose
 * YAML). Any HTML/JS in those fields must render as escaped text, not as
 * live markup. Before the fix in app.js, clicking "View more" in the
 * collapsible section injected body.dataset.full / body.dataset.truncated
 * into innerHTML without re-escaping — the browser auto-decoded the
 * data-attribute entities first, so a malicious description rendered as
 * a working <script>.
 */
test.describe("XSS regression", () => {
  test("description, how_to_fix, evidence, and metadata render as text, not HTML", async ({ page }) => {
    await page.route("**/api/result", async (route) => {
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "xss-test",
          local_ip: "127.0.0.1",
          phase: "complete",
          tools: {
            trivy: { status: 2, message: "ok" },
            lynis: { status: 2, message: "ok" },
          },
          score: 80,
          findings: [
            {
              id: "xss.payload",
              title: "Finding with XSS payloads",
              description: "<script>window.__xss_description=true;</script><img src=x onerror=\"window.__xss_img=true\">",
              how_to_fix: "<a href=\"javascript:window.__xss_href=true\">click</a>",
              severity: 1,
              source: 1,
              service: "host",
              remediation: 0,
              evidence: { "key1": "<script>window.__xss_evidence=true;</script>" },
              metadata: { compose_path: "/tmp/<script>window.__xss_metadata=true;</script>" },
              fixed: false,
            },
          ],
          score_breakdown: {
            overall: 80,
            axes: [],
          },
        }),
      });
    });

    // Reset all XSS flags before the page loads any content.
    await page.addInitScript(() => {
      window.__xss_description = false;
      window.__xss_img = false;
      window.__xss_href = false;
      window.__xss_evidence = false;
      window.__xss_metadata = false;
    });

    await page.goto("/");

    const row = page.locator("#findings tr[data-index]").first();
    await expect(row).toBeVisible({ timeout: 5000 });
    await row.click({ force: true });
    await page.waitForTimeout(200);

    // None of the XSS payloads should have executed.
    expect(await page.evaluate(() => window.__xss_description)).toBe(false);
    expect(await page.evaluate(() => window.__xss_img)).toBe(false);
    expect(await page.evaluate(() => window.__xss_href)).toBe(false);
    expect(await page.evaluate(() => window.__xss_evidence)).toBe(false);
    expect(await page.evaluate(() => window.__xss_metadata)).toBe(false);

    // The payload text should be visible as text content.
    const detail = page.locator("#detail");
    await expect(detail).toContainText("<script>window.__xss_description=true;</script>");
    await expect(detail).toContainText("<a href=\"javascript:window.__xss_href=true\">click</a>");
    await expect(detail).toContainText("<script>window.__xss_evidence=true;</script>");
  });

  test("collapsible 'View more' toggle does not execute embedded scripts", async ({ page }) => {
    const longHowToFix = "X".repeat(350) +
      "<script>window.__xss_collapse=true;</script><img src=x onerror=\"window.__xss_collapse_img=true\">" +
      " Y".repeat(50);

    await page.route("**/api/result", async (route) => {
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          hostname: "xss-test",
          local_ip: "127.0.0.1",
          phase: "complete",
          tools: { trivy: { status: 2, message: "ok" }, lynis: { status: 2, message: "ok" } },
          score: 80,
          findings: [
            {
              id: "xss.collapsible",
              title: "Collapsible finding",
              description: "short",
              how_to_fix: longHowToFix,
              severity: 1,
              source: 1,
              service: "host",
              remediation: 0,
              evidence: {},
              metadata: {},
              fixed: false,
            },
          ],
          score_breakdown: { overall: 80, axes: [] },
        }),
      });
    });

    await page.addInitScript(() => {
      window.__xss_collapse = false;
      window.__xss_collapse_img = false;
    });

    await page.goto("/");
    const row = page.locator("#findings tr[data-index]").first();
    await expect(row).toBeVisible({ timeout: 5000 });
    await row.click({ force: true });
    await page.waitForTimeout(200);

    // Find the View more button (there can be multiple if both description and
    // how_to_fix are long, but in this fixture only how_to_fix is long).
    const toggle = page.locator("#detail .toggle-more").first();
    await expect(toggle).toBeVisible({ timeout: 5000 });
    await toggle.click();
    await page.waitForTimeout(100);
    await toggle.click();
    await page.waitForTimeout(100);

    expect(await page.evaluate(() => window.__xss_collapse)).toBe(false);
    expect(await page.evaluate(() => window.__xss_collapse_img)).toBe(false);
  });
});
