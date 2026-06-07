import { startServer } from "./server";
import fs from "fs";
import path from "path";

const PID_FILE = path.resolve(__dirname, "..", ".e2e-server-pid");

export default async function () {
  console.log("Starting E2E test server...");
  const { url, stop, pid } = await startServer(8787);
  console.log(`Server ready at ${url} (PID ${pid})`);
  fs.writeFileSync(PID_FILE, String(pid));
  // Store stop function by writing a shell script that kills the PID
  // (globalSetup and globalTeardown run in separate processes)
  const killScript = `#!/bin/bash\nkill ${pid} 2>/dev/null\nsleep 0.5\nkill -9 ${pid} 2>/dev/null\nexit 0\n`;
  fs.writeFileSync(path.resolve(__dirname, "..", ".e2e-kill.sh"), killScript, { mode: 0o755 });
}
