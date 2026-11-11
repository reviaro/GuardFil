// Create the new rules through visible controls, then exercise real decisions.
module.exports = async ({ page, step, askRequest, askShell, out }) => {
  const check = (name, ok) => { step(name, ok); if (!ok) throw new Error(name); };
  await page.click("#tab-policy-btn");
  const details = page.locator("#tab-policy details");
  if (await details.getAttribute("open") === null) await details.locator("summary").click();
  const saved = await page.inputValue("#yaml");
  const savePolicy = async yaml => {
    await page.fill("#yaml", yaml);
    const response = page.waitForResponse(r => r.url().endsWith("/api/policy") && r.request().method() === "POST");
    await page.click("#yaml-save");
    if (!(await response).ok()) throw new Error("policy save failed");
    await page.locator('[aria-busy="true"]').waitFor({ state: "hidden" });
  };
  await savePolicy("schema_version: 1\ntenant_id: synthetic\nrevision: 1\ndefault: deny\nrules: []\n");
  await page.locator("#rules button").waitFor({ state: "detached" });
  const add = async (action, target, value) => {
    await page.selectOption("#r-principal", "codex-agent");
    await page.selectOption("#r-action", action);
    await page.selectOption("#r-target", target);
    await page.fill("#r-value", value);
    const count = await page.locator("#rules button").count();
    const response = page.waitForResponse(r => r.url().endsWith("/api/rules") && r.request().method() === "POST");
    await page.click("#add-rule button");
    if (!(await response).ok()) throw new Error("command rule save failed");
    await page.locator(`#rules tr:nth-child(${count + 1})`).waitFor();
  };
  await add("allow", "command", "git status");
  check("Exact command permits only the configured arguments", (await askShell("git status")).effect === "ALLOW" && (await askShell("git status --short")).effect === "BLOCK");
  check("Unmatched shell command is denied", (await askShell("rm notes")).effect === "BLOCK");
  await add("monitor", "command-prefix", "git status");
  const monitored = await askShell("git status --short");
  check("Command prefix permits extra arguments and records Monitor", monitored.effect === "ALLOW" && monitored.reasons.includes("POLICY_MONITORED"));
  check("Command prefix respects argument boundaries", (await askShell("git status-other")).effect === "BLOCK");
  check("A second command cannot hide behind an allowed prefix", (await askShell("git status; rm notes")).effect === "BLOCK");
  check("Dynamic command substitution is refused", (await askShell("git $(echo status)")).effect === "BLOCK");
  await page.fill("#r-value", "git status > notes");
  const invalid = page.waitForResponse(r => r.url().endsWith("/api/rules") && r.request().method() === "POST");
  await page.click("#add-rule button");
  check("Invalid command rule stays editable with a useful error", (await invalid).status() === 400 && await page.inputValue("#r-value") === "git status > notes");
  await add("ask", "command-prefix", "rm");
  const held = askShell("rm notes");
  await page.locator("#pending .pending-item").waitFor();
  check("Command-specific Ask shows the original command", (await page.textContent("#pending")).includes("rm notes"));
  await page.locator("#pending button", { hasText: "Deny" }).click();
  check("Command-specific owner denial blocks dispatch", (await held).effect === "BLOCK");
  await add("allow", "reads", "/workspace");
  await add("block", "reads", "/workspace/secret");
  const read = p => askRequest({ kind: "file_read", paths: [p] });
  check("Filesystem reads follow browser-saved rules", (await read("/workspace/public/note")).effect === "ALLOW" && (await read("/workspace/secret/key")).effect === "BLOCK");
  await page.selectOption("#r-target", "command-prefix");
  await page.fill("#r-value", "git status");
  for (const width of [320, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    await page.locator("#add-rule").scrollIntoViewIfNeeded();
    check(`Command form fits ${width}px`, await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth));
    await page.screenshot({ path: `${out}/commands-${width}.png`, fullPage: true });
    await page.locator("#add-rule").screenshot({ path: `${out}/command-form-${width}.png` });
  }
  await page.setViewportSize({ width: 1200, height: 900 });
  await savePolicy(saved);
};
