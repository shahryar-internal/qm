import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const enabled = process.env.TEST_CANARY_CONTAINER === "1";
const skip = enabled ? false : "set TEST_CANARY_CONTAINER=1 to run the isolated service-image acceptance";
const image = `risely-ceo-canary-container-proof-${process.pid}`;
const testImage = `risely-ceo-canary-test-container-proof-${process.pid}`;
const layerDirectory = fileURLToPath(new URL("../../canary/", import.meta.url));
const dockerfile = fileURLToPath(new URL("../../canary/service/ceo-canary/Dockerfile", import.meta.url));

function docker(args) {
  return new Promise((resolve, reject) => {
    const child = spawn("docker", args, { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (exitCode) => resolve({ exitCode, stderr, stdout }));
  });
}

test(
  "runtime image contains the exact shared module graph and fails closed before network startup",
  { skip, timeout: 180000 },
  async (t) => {
    t.after(async () => {
      await docker(["image", "rm", "--force", image, testImage]);
    });
    const build = await docker(["build", "--target", "runtime", "--tag", image, "--file", dockerfile, layerDirectory]);
    assert.equal(build.exitCode, 0, build.stderr || build.stdout);
    const imports = await docker([
      "run",
      "--rm",
      "--network",
      "none",
      image,
      "node",
      "--input-type=module",
      "--eval",
      "await Promise.all([...['postgres-store.mjs','evaluation-writer.mjs','migrate.mjs','retention.mjs'].map((name) => import('/app/canary/service/ceo-canary/src/' + name)), import('/app/canary/deployment-profiles/provider-effect-policy.mjs'), import('/app/canary/provider-effects/index.mjs')])",
    ]);
    assert.equal(imports.exitCode, 0, imports.stderr || imports.stdout);
    const productionTestingImport = await docker([
      "run",
      "--rm",
      "--network",
      "none",
      image,
      "node",
      "--input-type=module",
      "--eval",
      `for (const modulePath of [
       '/app/canary/deployment-profiles/testing.mjs',
       '/app/canary/evals/testing.mjs',
       '/app/canary/evals/testing-result-store.mjs',
     ]) {
       let absent = false;
       try { await import(modulePath); }
       catch (error) { if (error?.code === 'ERR_MODULE_NOT_FOUND') absent = true; else throw error; }
       if (!absent) throw new Error('production testing module present: ' + modulePath);
     }
     const { readdir, readFile } = await import('node:fs/promises');
     const forbidden = [
       'shadow-judge-key:quality:test:v1',
       'shadow-judge-key:safety:test:v1',
       'e8r7J1z3K5eM2qQFHNhX8f3dOfYZyzv9Up0LTw9XOrA',
       'urrw8LxAXbNRAeIJri7OgCxH8x9E44ZOwMg0kx4QwmY',
     ];
     const visit = async (path) => {
       for (const entry of await readdir(path, {withFileTypes: true})) {
         const target = path + '/' + entry.name;
         if (entry.isDirectory()) await visit(target);
         else if (entry.name.endsWith('.mjs')) {
           const source = await readFile(target, 'utf8');
           if (forbidden.some((value) => source.includes(value))) throw new Error('production test key material present');
         }
       }
     };
     await visit('/app/canary');`,
    ]);
    assert.equal(productionTestingImport.exitCode, 0, productionTestingImport.stderr || productionTestingImport.stdout);
    const testBuild = await docker([
      "build",
      "--target",
      "test",
      "--tag",
      testImage,
      "--file",
      dockerfile,
      layerDirectory,
    ]);
    assert.equal(testBuild.exitCode, 0, testBuild.stderr || testBuild.stdout);
    const testImports = await docker([
      "run",
      "--rm",
      "--network",
      "none",
      testImage,
      "node",
      "--input-type=module",
      "--eval",
      "await Promise.all([import('/app/canary/deployment-profiles/provider-effect-policy.mjs'), import('/app/canary/provider-effects/index.mjs'), import('/app/canary/deployment-profiles/testing.mjs'), import('/app/canary/evals/testing.mjs'), import('/app/canary/evals/testing-result-store.mjs')])",
    ]);
    assert.equal(testImports.exitCode, 0, testImports.stderr || testImports.stdout);
    const startup = await docker(["run", "--rm", "--network", "none", image]);
    assert.notEqual(startup.exitCode, 0);
    assert.equal(startup.stderr, "CEO canary startup failed\n");
  },
);
