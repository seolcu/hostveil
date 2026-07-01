import { test, expect } from "@playwright/test";

test.describe("Fix flow", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  test("Scenario 4: Fix dry-run shows modal with diff preview", async ({ page }) => {
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(fixableRow).toBeVisible();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });
    await expect(modal.locator("h2")).toContainText("Apply fix");
    await expect(modal.locator("#modalFixYes")).toBeVisible();
    await expect(modal.locator("#modalFixNo")).toBeVisible();

    await modal.locator("#modalFixNo").click();
    await expect(modal).not.toBeVisible();
  });

  test("Scenario 4: Review finding shows action selection modal", async ({ page }) => {
    const rows = page.locator("#findings tr[data-index]");
    const rowCount = await rows.count();
    let reviewRowIndex = -1;
    for (let i = 0; i < rowCount; i++) {
      const fixText = await rows.nth(i).locator("td.muted").last().textContent();
      if (fixText === "Review") {
        reviewRowIndex = i;
        break;
      }
    }
    expect(reviewRowIndex).toBeGreaterThanOrEqual(0);

    await rows.nth(reviewRowIndex).click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    await expect(modal.locator('input[type="radio"]').first()).toBeVisible();
    const confirmBtn = modal.locator("#modalFixYes");
    await expect(confirmBtn).toBeDisabled();
    await expect(confirmBtn).toContainText("Select an action");

    await modal.locator('input[type="radio"]').first().check();
    await expect(confirmBtn).toBeEnabled();
    await expect(confirmBtn).toContainText("Apply selected");

    await modal.locator("#modalFixNo").click();
    await expect(modal).not.toBeVisible();
  });

  test("Scenario 5: Apply fix success", async ({ page }) => {
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(fixableRow).toBeVisible();
    const findingId = await fixableRow.getAttribute("data-id");
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });
    await modal.locator("#modalFixYes").click();
    await expect(modal).not.toBeVisible();

    // Wait for the fix action to complete: look for either the success result
    // in the detail panel or for the finding row to be marked as "fixed"
    const resultDiv = page.locator("#fixResult");
    try {
      await expect(resultDiv.locator(".fix-success")).toBeVisible({ timeout: 8000 });
    } catch {
      // Fallback: check if the finding row got the "fixed" class
      const fixedRow = page.locator(`#findings tr.fixed[data-id="${findingId}"]`);
      await expect(fixedRow).toBeVisible({ timeout: 5000 });
    }

    const toast = page.locator("#toast");
    try {
      await expect(toast).toBeVisible({ timeout: 3000 });
    } catch {
      // toast is optional (only shown if also_fixed > 0)
    }
  });

  test("Scenario 6: Batch fix multiple findings", async ({ page }) => {
    const checkboxes = page.locator("#findings .row-check:not(:disabled)");
    const count = await checkboxes.count();
    expect(count).toBeGreaterThanOrEqual(2);

    for (let i = 0; i < Math.min(count, 2); i++) {
      await checkboxes.nth(i).check();
    }

    const fixSelectedBtn = page.locator("#fixSelectedBtn");
    await expect(fixSelectedBtn).toBeVisible();
    await expect(fixSelectedBtn).toContainText("Fix selected (2");

    await fixSelectedBtn.click();

    const progressModal = page.locator("#fixProgressModal");
    await expect(progressModal).toBeVisible({ timeout: 5000 });
    await expect(progressModal).not.toBeVisible({ timeout: 15000 });

    const toast = page.locator("#toast");
    await expect(toast).toBeVisible({ timeout: 3000 });
    const toastText = await toast.textContent();
    expect(toastText).toContain("Fixed");
  });

  test("Escape key closes fix modal", async ({ page }) => {
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(fixableRow).toBeVisible();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    await page.keyboard.press("Escape");
    await expect(modal).not.toBeVisible();
  });

  test("Fix modal shows action type badge", async ({ page }) => {
    const fixableRow = page.locator("#findings tr[data-index]:not(.disabled)").first();
    await expect(fixableRow).toBeVisible();
    await fixableRow.click({ force: true });
    await page.waitForTimeout(300);

    const fixBtn = page.locator("#detail .fix-btn");
    await expect(fixBtn).toBeVisible({ timeout: 5000 });
    await fixBtn.click();

    const modal = page.locator("#fixModal");
    await expect(modal).toBeVisible({ timeout: 5000 });

    // action type badge should exist
    const badge = modal.locator(".action-type-badge");
    await expect(badge.first()).toBeVisible();

    // action label should exist
    const actionHeader = modal.locator(".action-header strong");
    await expect(actionHeader.first()).toBeVisible();

    await modal.locator("#modalFixNo").click();
  });

  test("Batch fix button shows correct count", async ({ page }) => {
    const fixSelectedBtn = page.locator("#fixSelectedBtn");

    // initially no selection → button should be hidden or empty
    const initialText = await fixSelectedBtn.textContent();
    expect(initialText).not.toContain("Fix selected (");

    // select 3 findings
    for (let i = 0; i < 3; i++) {
      await page.locator("#findings .row-check:not(:disabled)").nth(i).check();
    }
    await page.waitForTimeout(200);

    await expect(fixSelectedBtn).toContainText("Fix selected (3");

    // unselect one
    await page.locator("#findings .row-check:not(:disabled)").first().uncheck();
    await page.waitForTimeout(200);

    await expect(fixSelectedBtn).toContainText("Fix selected (2");
  });
});

test.describe("Fix flow cache refresh", () => {
  test("successful fix refresh invalidates cached findings with related fixed rows", async ({ page }) => {
    const before = {
      hostname: "fix-refresh",
      local_ip: "127.0.0.1",
      phase: "complete",
      tools: { trivy: { status: 2, message: "ok" } },
      score: 80,
      findings: [
        {
          id: "primary.fix",
          title: "Primary fix target",
          description: "First finding",
          how_to_fix: "Apply the primary fix",
          severity: 1,
          source: 1,
          service: "host",
          remediation: 0,
          evidence: {},
          metadata: {},
          fixed: false,
        },
        {
          id: "related.fix",
          title: "Related finding fixed by same action",
          description: "Second finding",
          how_to_fix: "The primary fix should also resolve this",
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
    };
    const after = {
      ...before,
      findings: before.findings.map((finding) => ({ ...finding, fixed: true })),
    };
    let resultCalls = 0;
    let fixCalls = 0;

    await page.route("**/api/result", async (route) => {
      resultCalls++;
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify(resultCalls === 1 ? before : after),
      });
    });
    await page.route("**/api/fix", async (route) => {
      const req = route.request();
      const payload = req.postDataJSON();
      fixCalls++;
      if (payload.info_only) {
        await route.fulfill({
          contentType: "application/json",
          body: JSON.stringify({
            success: true,
            label: "Primary fix",
            actions: [{ label: "Apply primary fix", type: "exec", command: "true" }],
          }),
        });
        return;
      }
      await route.fulfill({
        contentType: "application/json",
        body: JSON.stringify({
          success: true,
          label: "Applied primary fix",
          also_fixed: ["related.fix"],
        }),
      });
    });

    await page.goto("/");
    await expect(page.locator('#findings tr[data-id="primary.fix"]')).toBeVisible({ timeout: 5000 });

    await page.locator('#findings tr[data-id="primary.fix"]').click({ force: true });
    await page.locator("#detail .fix-btn").click();
    await expect(page.locator("#fixModal")).toBeVisible();
    await page.locator("#modalFixYes").click();

    await expect(page.locator('#findings tr[data-id="primary.fix"] td').last()).toHaveText("Fixed");
    await expect(page.locator('#findings tr[data-id="related.fix"] td').last()).toHaveText("Fixed");
    expect(resultCalls).toBeGreaterThanOrEqual(2);
    expect(fixCalls).toBe(2);
  });
});
