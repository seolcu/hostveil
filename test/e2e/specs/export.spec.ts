import { test, expect } from "@playwright/test";

test.describe("Export", () => {
  test.beforeEach(async ({ page }) => {
    await page.goto("/");
    await expect(page.locator("#findings tr").first()).toBeVisible({ timeout: 5000 });
  });

  test("Scenario 8: JSON export downloads file", async ({ page }) => {
    await page.locator("#exportBtn").click();
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      modal.locator("#exportJson").click(),
    ]);

    expect(download.suggestedFilename()).toContain("hostveil-report.json");

    const content = await (await download.createReadStream()).toArray();
    const json = Buffer.concat(content).toString("utf-8");
    const data = JSON.parse(json);

    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("phase", "complete");
    expect(data.findings.length).toBeGreaterThan(0);
  });

  test("Scenario 8: CSV export downloads file", async ({ page }) => {
    await page.locator("#exportBtn").click();
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      modal.locator("#exportCsv").click(),
    ]);

    expect(download.suggestedFilename()).toContain("hostveil-report.csv");

    const content = await (await download.createReadStream()).toArray();
    const csv = Buffer.concat(content).toString("utf-8");

    expect(csv).toContain("ID,Severity,Source,Service,Title,Description,Remediation,Fixed");
    expect(csv).toContain("trivy.cve-2024-0001");
    expect(csv).toContain("lynis.AUTH-9286");

    const lines = csv.trim().split("\n");
    expect(lines.length).toBeGreaterThan(1);
  });

  test("Scenario 8: AI brief export downloads Markdown remediation brief", async ({
    page,
  }) => {
    await page.locator("#exportBtn").click();
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible();

    const aiButton = modal.locator("#exportAi");
    await expect(aiButton).toBeVisible();
    await expect(aiButton).toContainText(/AI brief/i);
    const stableFinding = page.locator('#findings tr[data-id="test.unfixable-001"]');
    await expect(stableFinding).toBeVisible();
    await expect(stableFinding.locator("td").last()).toHaveText("Unavailable");

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      aiButton.click(),
    ]);

    expect(download.suggestedFilename()).toContain("hostveil-ai-brief.md");

    const content = await (await download.createReadStream()).toArray();
    const markdown = Buffer.concat(content).toString("utf-8");

    expect(markdown).toContain("# hostveil AI remediation brief");
    expect(markdown).toContain("Prompt for your AI assistant");
    expect(markdown).toContain("test.unfixable-001");
    expect(markdown).toContain("Custom security policy violation detected");
  });

  test("Scenario 10: Empty state handling", async ({ page }) => {
    await page.locator("#query").fill("ZZZZ_NONEXISTENT_ZZZZ");
    await page.waitForTimeout(300);

    await expect(page.locator("#findings")).toContainText("No findings match");
    const countText = await page.locator("#findingCount").textContent();
    expect(countText).toContain("0 visible");

    await page.locator("#clearFilters").click();
    await page.waitForTimeout(200);
    const restoredText = await page.locator("#findingCount").textContent();
    expect(restoredText).not.toContain("0 visible");
  });

  test("Scenario 10: Fixed finding is visually distinct", async ({ page }) => {
    // There are ~12 findings in the fixture. One is fixed (trivy.cve-2024-0003).
    // Fixed rows have class "fixed".
    const fixedRow = page.locator("#findings tr.fixed");
    await expect(fixedRow.first()).toBeVisible();

    // Fixed findings show checkmark in the second td (severity column)
    // The first td is the checkbox cell, second td has the severity/checkmark
    const sevCell = fixedRow.first().locator("td:nth-child(2)");
    await expect(sevCell).toContainText("✓");

    // The title should use the shared fixed-title styling.
    const titleCell = fixedRow.first().locator("td.title .fixed-title");
    await expect(titleCell).toBeVisible();
    await expect(titleCell).toHaveCSS("text-decoration-line", "line-through");
  });

  test("JSON export contains all required Snapshot fields", async ({
    page,
  }) => {
    await page.locator("#exportBtn").click();
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      modal.locator("#exportJson").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const json = Buffer.concat(content).toString("utf-8");
    const data = JSON.parse(json);

    expect(data).toHaveProperty("phase", "complete");
    expect(data).toHaveProperty("findings");
    expect(data).toHaveProperty("score");
    expect(data).toHaveProperty("tools");
    expect(data).toHaveProperty("hostname");
    expect(data).toHaveProperty("local_ip");
    expect(data).toHaveProperty("score_breakdown");
    expect(data.findings.length).toBe(14);
  });

  test("CSV export has correct row count and field values", async ({
    page,
  }) => {
    await page.locator("#exportBtn").click();
    const modal = page.locator("#exportModal");
    await expect(modal).toBeVisible();

    const [download] = await Promise.all([
      page.waitForEvent("download", { timeout: 5000 }),
      modal.locator("#exportCsv").click(),
    ]);

    const content = await (await download.createReadStream()).toArray();
    const csv = Buffer.concat(content).toString("utf-8");
    const lines = csv.trim().split("\n");

    // header + 14 data rows
    expect(lines.length).toBe(15);

    // verify header
    expect(lines[0]).toBe(
      "ID,Severity,Source,Service,Title,Description,Remediation,Fixed"
    );

    // verify first data row has valid severity value
    const firstFields = lines[1].split(",");
    expect(["critical", "high", "medium", "low"]).toContain(firstFields[1]);
    expect(["trivy", "lynis"]).toContain(firstFields[2]);

    // verify known finding IDs are present
    expect(csv).toContain("trivy.cve-2024-0001");
    expect(csv).toContain("lynis.AUTH-9286");
    expect(csv).toContain("test.unfixable-001");
  });
});
