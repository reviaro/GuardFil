const http = require("http");

module.exports = async ({ page, step, askRequest, out, ownerSocket }) => {
  const check = (name, ok) => { step(name, ok); if (!ok) throw new Error(name); };
  const owner = (method, path, body) => new Promise((resolve, reject) => {
    const req = http.request({ socketPath: ownerSocket, method, path, headers: { "Content-Type": "application/json" } }, res => {
      let data = "";
      res.on("data", chunk => data += chunk);
      res.on("end", () => res.statusCode < 300 ? resolve(data ? JSON.parse(data) : null) : reject(new Error(data)));
    });
    req.on("error", reject);
    req.end(body ? JSON.stringify(body) : undefined);
  });
  await page.click("#tab-policy-btn");
  const details = page.locator("#tab-policy details");
  if (await details.getAttribute("open") === null) await details.locator("summary").click();
  const saved = await page.inputValue("#yaml");
  const save = async text => {
    await page.fill("#yaml", text);
    const response = page.waitForResponse(r => r.url().endsWith("/api/policy") && r.request().method() === "POST");
    await page.click("#yaml-save");
    check("File approval test policy saved", (await response).ok());
    await page.locator('[aria-busy="true"]').waitFor({ state: "hidden" });
  };
  const policy = `schema_version: 1
tenant_id: synthetic
revision: 1
default: deny
rules:
  - id: ask-files
    effect: require_approval
    match:
      principals: [codex-agent]
      operations: [filesystem.read, filesystem.write]
      resources: [{kind: path, value: /workspace/**}]
`;
  await save(policy);
  const session = await owner("POST", "/sessions", { default: true });
  const other = await owner("POST", "/sessions", { default: true });
  const read = (path = "/workspace/note", socket = session.approval_socket) => askRequest({ kind: "file_read", paths: [path] }, socket);
  try {
    const first = read();
    await page.getByRole("button", { name: "Allow for session", exact: true }).waitFor();
    for (const width of [320, 768, 1440]) {
      await page.setViewportSize({ width, height: 900 });
      await page.locator("#pending").scrollIntoViewIfNeeded();
      check(`File approval controls fit ${width}px`, await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
      await page.locator(".pending-card").screenshot({ path: `${out}/file-approval-${width}.png` });
    }
    await page.getByRole("button", { name: "Allow for session", exact: true }).click();
    check("Session approval releases the file read", (await first).effect === "ALLOW");
    for (let i = 0; i < 5; i++) check(`Repeated file read ${i + 1} needs no extra prompt`, (await read()).effect === "ALLOW");
    await page.getByRole("button", { name: "Clear file approvals", exact: true }).waitFor();
    check("Reusable access remains visible and revocable", (await page.textContent("#file-grants")).includes("1 read, 0 write"));

    const secondSession = read("/workspace/note", other.approval_socket);
    await page.getByRole("button", { name: "Deny", exact: true }).click();
    check("Read approval does not cross sessions", (await secondSession).effect === "BLOCK");
    const write = askRequest({ kind: "file_write", changes: [{ path: "/workspace/note", change: "update" }] }, session.approval_socket);
    await page.getByRole("button", { name: "Deny", exact: true }).click();
    check("Read approval does not authorize writes", (await write).effect === "BLOCK");

    await page.getByRole("button", { name: "Clear file approvals", exact: true }).click();
    await page.locator("#file-grants-section").waitFor({ state: "hidden" });
    const afterRevoke = read();
    await page.getByRole("button", { name: "Allow once", exact: true }).click();
    check("Revocation asks again and keeps one-call approval", (await afterRevoke).effect === "ALLOW");
    const afterOnce = read();
    await page.getByRole("button", { name: "Deny", exact: true }).click();
    check("Allow once does not become a reusable grant", (await afterOnce).effect === "BLOCK");

    const toGrant = read();
    await page.getByRole("button", { name: "Allow for session", exact: true }).click();
    await toGrant;
    await save(policy);
    await page.locator("#file-grants-section").waitFor({ state: "hidden" });
    const afterEdit = read();
    await page.getByRole("button", { name: "Deny", exact: true }).click();
    check("Policy saves invalidate session file approvals", (await afterEdit).effect === "BLOCK");
  } finally {
    await owner("DELETE", "/sessions/" + session.session);
    await owner("DELETE", "/sessions/" + other.session);
    await page.setViewportSize({ width: 1200, height: 900 });
    await save(saved);
  }
};
