import { expect, test, type Page } from "@playwright/test";

type Viewport = { width: number; height: number };

async function gotoReady(page: Page, viewport?: Viewport): Promise<void> {
  if (viewport) await page.setViewportSize(viewport);
  await page.goto("/");
  await expect(page.locator(".shell.loading")).toHaveCount(0, { timeout: 5000 });
  await expect(page.locator("#findings tr[data-index]").first()).toBeVisible({ timeout: 5000 });
}

async function expectNoDocumentHorizontalOverflow(page: Page): Promise<void> {
  const overflow = await page.evaluate(() => ({
    htmlClient: document.documentElement.clientWidth,
    htmlScroll: document.documentElement.scrollWidth,
    bodyClient: document.body.clientWidth,
    bodyScroll: document.body.scrollWidth,
  }));

  expect(overflow.htmlScroll, JSON.stringify(overflow)).toBeLessThanOrEqual(
    overflow.htmlClient + 1
  );
  expect(overflow.bodyScroll, JSON.stringify(overflow)).toBeLessThanOrEqual(
    overflow.bodyClient + 1
  );
}

test.describe("Responsive visual regressions", () => {
  test("table keeps sortable headers visible at key widths without document overflow", async ({
    page,
  }) => {
    const breakpoints = [
      {
        name: "desktop",
        viewport: { width: 1280, height: 720 },
        visibleHeaders: ["Severity", "Source", "Finding", "Fix"],
        hiddenHeaders: [] as string[],
      },
      {
        name: "wrapped tablet",
        viewport: { width: 900, height: 720 },
        visibleHeaders: ["Severity", "Source", "Finding", "Fix"],
        hiddenHeaders: [] as string[],
      },
      {
        name: "mobile cutoff",
        viewport: { width: 760, height: 720 },
        visibleHeaders: ["Severity", "Finding"],
        hiddenHeaders: ["Source", "Fix"],
      },
    ];

    for (const { name, viewport, visibleHeaders, hiddenHeaders } of breakpoints) {
      await gotoReady(page, viewport);

      for (const label of visibleHeaders) {
        const header = page.locator("thead th", { hasText: label });
        await expect(header, `${label} header should be visible at ${name}`).toBeVisible();
        await expect(header, `${label} header should remain sortable at ${name}`).toHaveClass(
          /sortable/
        );
        const box = await header.boundingBox();
        expect(box, `${label} header should have a layout box at ${name}`).not.toBeNull();
        expect(box!.x, `${label} header left edge at ${name}`).toBeGreaterThanOrEqual(0);
        expect(box!.x + box!.width, `${label} header right edge at ${name}`).toBeLessThanOrEqual(
          viewport.width + 1
        );
      }

      for (const label of hiddenHeaders) {
        await expect(
          page.locator("thead th", { hasText: label }),
          `${label} header should collapse at ${name}`
        ).toBeHidden();
      }

      await expectNoDocumentHorizontalOverflow(page);
    }
  });

  test("detail panel scrolls internally and keeps evidence inside the viewport", async ({
    page,
  }) => {
    await gotoReady(page, { width: 1440, height: 520 });

    const findingRow = page.locator('#findings tr[data-id="trivy.cve-2024-0001"]');
    await findingRow.click({ force: true });
    await expect(page.locator("#detail h2")).toContainText("CVE-2024-0001");

    await page.locator("#detail details").evaluateAll((details) => {
      for (const detail of details) detail.setAttribute("open", "");
    });

    const metrics = await page.locator("#detail").evaluate((detail) => {
      const rect = detail.getBoundingClientRect();
      return {
        rectTop: rect.top,
        rectBottom: rect.bottom,
        rectLeft: rect.left,
        rectRight: rect.right,
        clientHeight: detail.clientHeight,
        scrollHeight: detail.scrollHeight,
        overflowY: getComputedStyle(detail).overflowY,
        viewportWidth: window.innerWidth,
        viewportHeight: window.innerHeight,
      };
    });

    expect(metrics.scrollHeight, JSON.stringify(metrics)).toBeGreaterThan(metrics.clientHeight);
    expect(metrics.overflowY).toMatch(/^(auto|scroll)$/);
    expect(metrics.rectTop, JSON.stringify(metrics)).toBeGreaterThanOrEqual(0);
    expect(metrics.rectLeft, JSON.stringify(metrics)).toBeGreaterThanOrEqual(0);
    expect(metrics.rectBottom, JSON.stringify(metrics)).toBeLessThanOrEqual(
      metrics.viewportHeight + 1
    );
    expect(metrics.rectRight, JSON.stringify(metrics)).toBeLessThanOrEqual(
      metrics.viewportWidth + 1
    );
    await expectNoDocumentHorizontalOverflow(page);
  });

  test("help modal content remains bounded by a short viewport", async ({ page }) => {
    await gotoReady(page, { width: 640, height: 360 });

    await page.keyboard.press("?");
    const content = page.locator("#helpModal .modal-content");
    await expect(content).toBeVisible();

    const metrics = await content.evaluate((modal) => {
      const rect = modal.getBoundingClientRect();
      return {
        top: rect.top,
        bottom: rect.bottom,
        left: rect.left,
        right: rect.right,
        clientHeight: modal.clientHeight,
        scrollHeight: modal.scrollHeight,
        overflowY: getComputedStyle(modal).overflowY,
        viewportWidth: window.innerWidth,
        viewportHeight: window.innerHeight,
      };
    });

    expect(metrics.left, JSON.stringify(metrics)).toBeGreaterThanOrEqual(0);
    expect(metrics.right, JSON.stringify(metrics)).toBeLessThanOrEqual(metrics.viewportWidth + 1);
    expect(metrics.top, JSON.stringify(metrics)).toBeGreaterThanOrEqual(0);
    expect(metrics.bottom, JSON.stringify(metrics)).toBeLessThanOrEqual(
      metrics.viewportHeight + 1
    );
    if (metrics.scrollHeight > metrics.clientHeight) {
      expect(metrics.overflowY).toMatch(/^(auto|scroll)$/);
    }
  });

  test("Escape closes export modal and returns keyboard shortcuts to the page", async ({
    page,
  }) => {
    await gotoReady(page, { width: 1024, height: 720 });

    await page.keyboard.press("e");
    await expect(page.locator("#exportModal")).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(page.locator("#exportModal")).toHaveCount(0);

    await page.keyboard.press("/");
    await expect(page.locator("#query")).toBeFocused();
  });

  test("select-all ignores visible unavailable findings instead of enabling an empty batch fix", async ({
    page,
  }) => {
    await gotoReady(page, { width: 1280, height: 720 });

    await page.locator("#remediationFilters .chip", { hasText: "Unavailable" }).click();
    await expect(page.locator("#findingCount")).toHaveText("1 visible");

    const unavailableRow = page.locator('#findings tr[data-id="test.unfixable-001"]');
    await expect(unavailableRow).toBeVisible();
    const unavailableCheckbox = unavailableRow.locator(".row-check");
    await expect(unavailableCheckbox).toBeDisabled();

    const selectAll = page.locator("#selectAllCheck");
    await selectAll.check({ force: true });

    await expect(unavailableCheckbox).not.toBeChecked();
    await expect(selectAll).not.toBeChecked();
    await expect(page.locator("#fixSelectedBtn")).toBeHidden();
  });

  test("rescan button stays in loading state while the rescan request is pending", async ({
    page,
  }) => {
    await gotoReady(page, { width: 1280, height: 720 });

    let releaseRescan!: () => void;
    const allowRescan = new Promise<void>((resolve) => {
      releaseRescan = resolve;
    });
    const rescanRequested = new Promise<void>((resolve) => {
      page.route("**/api/rescan", async (route) => {
        resolve();
        await allowRescan;
        await route.continue();
      });
    });

    const rescanBtn = page.locator("#rescanBtn");
    await rescanBtn.click();
    await rescanRequested;

    await expect(rescanBtn).toBeDisabled();
    await expect(rescanBtn).toHaveText("Scanning...");
    await expect(rescanBtn).toHaveClass(/loading/);

    releaseRescan();
    await expect(rescanBtn).toBeEnabled({ timeout: 5000 });
    await expect(rescanBtn).toHaveText("Rescan");
    await expect(rescanBtn).not.toHaveClass(/loading/);
    await expect(page.locator("#findings tr[data-index]")).toHaveCount(14);
  });
});
