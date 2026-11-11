const http = require("http");

module.exports = async ({ page, step, askRequest, out, ownerSocket }) => {
  const check = (name, ok) => { step(name, ok); if (!ok) throw new Error(name); };
  const owner = (method, path, body) => new Promise((resolve, reject) => {
    const req = http.request({ socketPath: ownerSocket, method, path, headers: { "Content-Type": "application/json" } }, res => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => resolve({ status: res.statusCode, data }));
    });
    req.on("error", reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
  const saved = await page.inputValue("#yaml");
  const savePolicy = async policy => {
    await page.fill("#yaml", policy);
    const response = page.waitForResponse(r => r.url().endsWith("/api/policy") && r.request().method() === "POST");
    await page.click("#yaml-save");
    check("Privacy test policy saved", (await response).ok());
    await page.locator('[aria-busy="true"]').waitFor({ state: "hidden" });
  };
  const savePaths = async (paths, expected = 200) => {
    await page.fill("#local-only-paths", paths);
    const response = page.waitForResponse(r => r.url().endsWith("/api/privacy") && r.request().method() === "POST");
    await page.getByRole("button", { name: "Save local-only paths", exact: true }).click();
    check("Privacy form returns expected save result", (await response).status() === expected);
    await page.locator('[aria-busy="true"]').waitFor({ state: "hidden" });
  };
  await savePolicy(`schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: files
    effect: allow
    match: {principals: [codex-agent], operations: [filesystem.read, filesystem.write], resources: [{kind: path, value: /workspace/**}]}
`);
  await savePaths("/workspace/private/**");
  const created = await owner("POST", "/sessions", { default: true, workspace_mediated: true,
    workspace: {mounts: [{virtual: "/workspace", filesystem: "1", root: "/browser-fixture"}]} });
  check("Privacy session created through owner API", created.status === 201);
  const session = JSON.parse(created.data);
  try {
    check("Cloud initially available for a new session", (await owner("GET", `/sessions/${session.session}/cloud`)).status === 204);
    const result = await askRequest({ kind: "file_read", paths: ["/workspace/private/key"] }, session.approval_socket);
    check("Local-only rule preserves allowed local reads", result.effect === "ALLOW");
    check("Read stops cloud requests through owner boundary", (await owner("GET", `/sessions/${session.session}/cloud`)).status === 403);
    await page.locator("#private-sessions", { hasText: session.session }).waitFor();
    check("UI names the session with cloud access blocked", (await page.textContent("#private-sessions")).includes("Cloud blocked"));
    const copied = await askRequest({ kind: "file_write", changes: [{ path: "/workspace/encoded-copy", change: "add" }] }, session.approval_socket);
    check("Private session cannot leave a public output for another agent", copied.effect === "BLOCK" && copied.reasons.includes("LOCAL_ONLY_OUTPUT_REQUIRED"));
    const local = await askRequest({ kind: "file_write", changes: [{ path: "/workspace/private/report", change: "add" }] }, session.approval_socket);
    check("Private session can write a local-only report", local.effect === "ALLOW");
    await savePaths("/workspace/../bad", 400);
    check("Invalid privacy paths preserve the editable value", await page.inputValue("#local-only-paths") === "/workspace/../bad");
    await page.click("#privacy-discard");
    for (let i = 0; i < 30 && await page.inputValue("#local-only-paths") !== "/workspace/private/**"; i++) await page.waitForTimeout(100);
    check("Discard restores saved privacy paths", await page.inputValue("#local-only-paths") === "/workspace/private/**");
    await page.fill("#local-only-paths", "/workspace/draft/**");
    await page.waitForTimeout(1700);
    check("Polling preserves privacy edits", await page.inputValue("#local-only-paths") === "/workspace/draft/**");
    await page.click("#privacy-discard");
    await page.click("#flash-dismiss");
    for (const width of [320, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      const panel = page.locator('section[aria-labelledby="h-privacy"]');
      await panel.scrollIntoViewIfNeeded();
      check(`Privacy controls fit ${width}px`, await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await panel.screenshot({ path: `${out}/privacy-${width}.png` });
    }
    await savePaths("");
    check("Removing paths does not erase this session's private knowledge", (await owner("GET", `/sessions/${session.session}/cloud`)).status === 403);
  } finally {
    await owner("DELETE", "/sessions/" + session.session);
    await page.setViewportSize({ width: 1200, height: 900 });
    await savePolicy(saved);
  }
};
