import { spawn } from "child_process";
import path from "path";
import fs from "fs";
import http from "http";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const FIXTURE_PATH = path.resolve(__dirname, "..", "fixtures", "mock-snapshot.json");
const PROJECT_ROOT = path.resolve(__dirname, "..", "..", "..");
const BINARY_PATH = path.resolve(PROJECT_ROOT, "hostveil-e2e");

export interface E2EServer {
  url: string;
  pid: number;
  stop: () => Promise<void>;
}

async function buildBinary(): Promise<void> {
  const { execSync } = await import("child_process");
  execSync("go build -o " + BINARY_PATH + " ./cmd/hostveil/", {
    cwd: PROJECT_ROOT,
    stdio: "inherit",
  });
}

export async function startServer(
  port: number = 8787
): Promise<E2EServer> {
  if (!fs.existsSync(BINARY_PATH)) {
    console.log("Building hostveil-e2e binary...");
    await buildBinary();
  }

  const url = `http://127.0.0.1:${port}`;

  const proc = spawn(BINARY_PATH, ["serve", "--fixture", FIXTURE_PATH, "--addr", `127.0.0.1:${port}`], {
    cwd: PROJECT_ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, HOSTVEIL_TEST: "1" },
  });

  proc.stdout?.on("data", (data: Buffer) => {
    const text = data.toString().trim();
    if (text) console.log(`[hostveil] ${text}`);
  });

  proc.stderr?.on("data", (data: Buffer) => {
    const text = data.toString().trim();
    if (text) console.log(`[hostveil] ${text}`);
  });

  proc.on("exit", (code: number | null) => {
    if (code !== 0 && code !== null) {
      console.error(`hostveil exited with code ${code}`);
    }
  });

  await waitForServer(url, 15000);

  return {
    url,
    pid: proc.pid || 0,
    stop: async () => {
      return new Promise((resolve) => {
        proc.kill("SIGTERM");
        const timeout = setTimeout(() => {
          proc.kill("SIGKILL");
        }, 5000);
        proc.on("exit", () => {
          clearTimeout(timeout);
          resolve();
        });
      });
    },
  };
}

function waitForServer(
  url: string,
  timeoutMs: number = 15000
): Promise<void> {
  const healthUrl = `${url}/api/health`;
  const start = Date.now();

  return new Promise((resolve, reject) => {
    function check() {
      if (Date.now() - start > timeoutMs) {
        reject(new Error(`Server did not start within ${timeoutMs}ms`));
        return;
      }

      http
        .get(healthUrl, (res) => {
          if (res.statusCode === 200) {
            resolve();
          } else {
            setTimeout(check, 300);
          }
        })
        .on("error", () => {
          setTimeout(check, 300);
        });
    }
    check();
  });
}
