import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const ROOT = new URL("..", import.meta.url).pathname;
const HELPER_REPOSITORY = "SpamArtist/docx-integration";
const HELPER_REF = "f43e96f6e83d14013c6d31c334cc7fd2e5c8faa4";

for (const workflowPath of [
  ".github/workflows/reusable-docx-audit.yml",
  ".github/workflows/reusable-docx-audit-maintenance.yml",
]) {
  test(`${workflowPath} checks out pinned Integration Repository helpers`, () => {
    const workflow = readFileSync(join(ROOT, workflowPath), "utf8");
    const checkoutSteps = [...workflow.matchAll(/- name: Checkout integration helpers[\s\S]*?(?=\n      - name:|\n  \w|$)/g)];

    assert(checkoutSteps.length > 0);
    assert.doesNotMatch(workflow, /github\.workflow_(ref|sha)|integration-source/);
    for (const [checkoutStep] of checkoutSteps) {
      assert.match(checkoutStep, new RegExp(`repository: ${HELPER_REPOSITORY}`));
      assert.match(checkoutStep, new RegExp(`ref: ${HELPER_REF}`));
      assert.doesNotMatch(checkoutStep, /token:\s*["']{2}/);
    }
  });
}
