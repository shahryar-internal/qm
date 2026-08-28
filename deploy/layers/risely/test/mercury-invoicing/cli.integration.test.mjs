import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createHash } from "node:crypto";
import { once } from "node:events";
import { lstat, readFile } from "node:fs/promises";
import { createServer } from "node:http";
import test from "node:test";
import { ceoDeploymentProfile } from "../../canary/deployment-profiles/index.mjs";
import { createMercuryInvoicingProgram } from "../../canary/mercury-invoicing/index.mjs";

const cliPath = process.env.TEST_MERCURY_CLI_BIN;
const pinnedLinuxAmd64BinarySha256 = "3bb3a39a3676376998ea3a48034b7a636c5c31d7b7d08dca4c26cebd64520b8b";

const collect = (stream, maximum = 128 * 1024) =>
  new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    stream.on("data", (chunk) => {
      size += chunk.length;
      if (size > maximum) {
        reject(new Error("Mercury CLI output exceeded its test boundary"));
        return;
      }
      chunks.push(chunk);
    });
    stream.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    stream.on("error", reject);
  });

test(
  "the pinned Mercury CLI accepts the exact compiled invoice body over stdin",
  { skip: !cliPath, timeout: 15_000 },
  async (t) => {
    const executable = await lstat(cliPath);
    assert.equal(executable.isFile(), true);
    assert.equal(executable.isSymbolicLink(), false);
    assert.equal(executable.size > 0 && executable.size <= 32 * 1024 * 1024, true);
    assert.equal(
      createHash("sha256")
        .update(await readFile(cliPath))
        .digest("hex"),
      pinnedLinuxAmd64BinarySha256,
    );
    const versionChild = spawn(cliPath, ["--version"], {
      env: { MERCURY_NO_UPDATE_CHECK: "1" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    const [versionStdout, versionStderr, [versionExitCode]] = await Promise.all([
      collect(versionChild.stdout),
      collect(versionChild.stderr),
      once(versionChild, "exit"),
    ]);
    assert.equal(versionExitCode, 0, versionStderr);
    assert.equal(versionStdout.trim(), "mercury version 0.11.8");
    const program = createMercuryInvoicingProgram(ceoDeploymentProfile);
    const record = {
      billingRecordRef: "billing-record:cli-contract:2026-08",
      customerRef: "mercury-customer:cli-contract",
      customerId: "182bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
      customerEmail: "billing@cli-contract.example",
      destinationAccountRef: "mercury-account:risely-operating",
      destinationAccountId: "282bd5e5-6e1a-4fe4-a799-aa6d9a6ab26e",
      invoiceDate: "2026-08-31",
      dueDate: "2026-09-30",
      servicePeriodStartDate: "2026-08-01",
      servicePeriodEndDate: "2026-08-31",
      currencyCode: "USD",
      lineItems: [{ name: "Risely platform", quantity: 1, unitPriceCents: 250_000, salesTaxBasisPoints: null }],
      ccEmails: [],
      payerMemo: "August services",
      internalNote: null,
      poNumber: null,
      deliveryMode: "prepare_only",
    };
    record.billingRecordSha256 = program.runtimeScope.contracts.PrincipalBinding.hash(record);
    const batch = program.buildBatch({
      programRef: "mercury-invoicing:cli-contract:v1",
      environment: "sandbox",
      schedule: {
        scheduleRef: "schedule:mercury:cli-contract",
        cadence: "monthly",
        timeZone: "America/Los_Angeles",
        localTime: "09:00",
        weeklyDay: null,
        monthlyDay: 28,
        activeFrom: "2026-08-01",
        activeUntil: "2027-07-31",
      },
      occurrenceAt: "2026-08-28T16:00:00.000Z",
      billingRecords: [record],
    });
    const candidate = batch.candidates[0];
    const requests = [];
    const server = createServer(async (request, response) => {
      const chunks = [];
      for await (const chunk of request) chunks.push(chunk);
      requests.push({
        method: request.method,
        url: request.url,
        authorization: request.headers.authorization,
        body: JSON.parse(Buffer.concat(chunks).toString("utf8")),
      });
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ id: "invoice-cli-contract", status: "Unpaid" }));
    });
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    t.after(() => server.close());
    const address = server.address();
    const baseUrl = `http://127.0.0.1:${address.port}/api/v1/`;
    const token = "test-only-mercury-cli-token";
    const child = spawn(
      cliPath,
      ["--base-url", baseUrl, "--format", "json", "--format-error", "json", "invoices", "create"],
      {
        env: { MERCURY_API_KEY: token, MERCURY_NO_UPDATE_CHECK: "1" },
        stdio: ["pipe", "pipe", "pipe"],
      },
    );
    child.stdin.end(JSON.stringify(candidate.cliPlan.stdin));
    const [stdout, stderr, [exitCode]] = await Promise.all([
      collect(child.stdout),
      collect(child.stderr),
      once(child, "exit"),
    ]);
    assert.equal(exitCode, 0, stderr);
    assert.equal(requests.length, 1);
    assert.equal(requests[0].method, "POST");
    assert.equal(requests[0].url, "/api/v1/ar/invoices");
    assert.equal(requests[0].authorization, `Bearer ${token}`);
    assert.deepEqual(requests[0].body, candidate.cliPlan.stdin);
    assert.deepEqual(JSON.parse(stdout), { id: "invoice-cli-contract", status: "Unpaid" });
    assert.equal(stdout.includes(token), false);
    assert.equal(stderr.includes(token), false);
  },
);
