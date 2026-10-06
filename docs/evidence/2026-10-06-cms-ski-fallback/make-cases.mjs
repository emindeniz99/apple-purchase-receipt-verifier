// Writes a cases.json into the directory given as the first argument,
// which must hold p/probe-rfc.der, p/probe-ms.der and their roots
// (p/probe-rfc-root.der, p/probe-ms-root.der). Each case expects ok, so
// the Go conformance runner prints the core's actual answer for any
// other. See README.md beside this file.
import fs from "node:fs";
import crypto from "node:crypto";

const dir = process.argv[2];
const fixtures = {};
const cases = [];
for (const tag of ["rfc", "ms"]) {
  for (const [id, path, role] of [
    [`p-${tag}`, `p/probe-${tag}.der`, "input"],
    [`p-${tag}-root`, `p/probe-${tag}-root.der`, "trust-anchor"],
  ]) {
    const bytes = fs.readFileSync(`${dir}/${path}`);
    fixtures[id] = {
      path,
      role,
      codec: "raw",
      contentSha256: crypto.createHash("sha256").update(bytes).digest("hex"),
    };
  }
  cases.push({
    id: `receipt/probe-${tag}`,
    description: "probe",
    operation: "verifyReceipt",
    input: { fixture: `p-${tag}` },
    config: { trustedRoots: { source: "fixtures", fixtures: [`p-${tag}-root`] } },
    expected: { status: "ok", environment: "Sandbox" },
    tags: ["receipt"],
  });
}
fs.writeFileSync(
  `${dir}/cases.json`,
  JSON.stringify({ $schema: "./cases.schema.json", schemaVersion: 2, comment: "probe", fixtures, cases }, null, 2),
);
