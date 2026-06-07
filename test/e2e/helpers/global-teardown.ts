import { execSync } from "child_process";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PID_FILE = path.resolve(__dirname, "..", ".e2e-server-pid");
const KILL_SCRIPT = path.resolve(__dirname, "..", ".e2e-kill.sh");

export default async function () {
  if (fs.existsSync(KILL_SCRIPT)) {
    try {
      execSync(KILL_SCRIPT, { stdio: "ignore" });
    } catch {
      // ignore
    }
    fs.unlinkSync(KILL_SCRIPT);
  }

  if (fs.existsSync(PID_FILE)) {
    const pid = parseInt(fs.readFileSync(PID_FILE, "utf-8").trim(), 10);
    if (!isNaN(pid)) {
      try {
        process.kill(pid, "SIGTERM");
      } catch {
        // process already gone
      }
      setTimeout(() => {
        try {
          process.kill(pid, "SIGKILL");
        } catch {
          // already gone
        }
      }, 2000);
    }
    fs.unlinkSync(PID_FILE);
  }
}
