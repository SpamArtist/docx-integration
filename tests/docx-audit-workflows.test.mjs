import assert from "node:assert/strict";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import test from "node:test";

const ROOT = new URL("..", import.meta.url).pathname;
const REUSABLE_WORKFLOW = readFileSync(
  join(ROOT, ".github/workflows/reusable-docx-audit.yml"),
  "utf8",
);
const MAINTENANCE_WORKFLOW = readFileSync(
  join(ROOT, ".github/workflows/reusable-docx-audit-maintenance.yml"),
  "utf8",
);
const CONSUMER_WORKFLOW = readFileSync(
  join(ROOT, "consumer-repository/.github/workflows/docx-pull-request-audit.yml"),
  "utf8",
);
const SECOND_CONSUMER_WORKFLOW = readFileSync(
  join(ROOT, "repository-neutral-second-consumer/.github/workflows/docx-pull-request-audit.yml"),
  "utf8",
);
const CONSUMER_MAINTENANCE_WORKFLOW = readFileSync(
  join(ROOT, "consumer-repository/.github/workflows/docx-pull-request-audit-maintenance.yml"),
  "utf8",
);
const GUARD_SCRIPT = readFileSync(join(ROOT, "scripts/docx-audit-workflow-guards.mjs"), "utf8");
const ISSUE_743_EVIDENCE = readFileSync(
  join(ROOT, "../../docs/repository-neutral-consumer-proof.md"),
  "utf8",
);
const ISSUE_744_EVIDENCE = readFileSync(
  join(ROOT, "../../docs/final-pilot-acceptance-evidence.md"),
  "utf8",
);

test("Consumer Workflow accepts only supported pull request events to main", () => {
  assert.match(CONSUMER_WORKFLOW, /^\s*pull_request:/m);
  for (const action of ["opened", "synchronize", "reopened", "ready_for_review"]) {
    assert.match(CONSUMER_WORKFLOW, new RegExp(`- ${action}`));
  }
  assert.doesNotMatch(CONSUMER_WORKFLOW, /pull_request_target/);
  assert.doesNotMatch(CONSUMER_WORKFLOW, /-\s*closed\b/);
  assert.match(CONSUMER_WORKFLOW, /branches:\n\s+- main/);
});

test("Consumer Workflow starts each pull request head audit independently", () => {
  assert.doesNotMatch(CONSUMER_WORKFLOW, /^concurrency:/m);
  assert.doesNotMatch(CONSUMER_WORKFLOW, /cancel-in-progress/);
  assert.match(CONSUMER_WORKFLOW, /^\s*-\s*synchronize$/m);
  assert.match(CONSUMER_WORKFLOW, /github\.event\.pull_request\.head\.sha/);
});

test("Reusable workflow interface accepts required inputs and one named secret", () => {
  assert.match(REUSABLE_WORKFLOW, /^\s*workflow_call:/m);
  for (const input of ["docx_version", "bundle_path", "report_format"]) {
    assert.match(REUSABLE_WORKFLOW, new RegExp(`^\\s{6}${input}:`, "m"));
  }
  for (const output of ["report_url", "artifact_id", "artifact_name", "audited_sha", "report_format", "artifact_metadata"]) {
    assert.match(REUSABLE_WORKFLOW, new RegExp(`^\\s{6}${output}:`, "m"));
  }
  assert.match(REUSABLE_WORKFLOW, /^\s{6}binary_download_token:/m);
  assert.doesNotMatch(REUSABLE_WORKFLOW, /secrets:\s*inherit/);
});

test("Maintenance workflows support daily and manual runs through reusable workflow", () => {
  assert.match(MAINTENANCE_WORKFLOW, /^\s*workflow_call:/m);
  assert.match(MAINTENANCE_WORKFLOW, /^\s*workflow_dispatch:/m);
  assert.match(MAINTENANCE_WORKFLOW, /^\s*schedule:/m);
  assert.match(CONSUMER_MAINTENANCE_WORKFLOW, /^\s*workflow_dispatch:/m);
  assert.match(CONSUMER_MAINTENANCE_WORKFLOW, /^\s*schedule:/m);
  assert.match(
    CONSUMER_MAINTENANCE_WORKFLOW,
    /uses: SpamArtist\/docx-integration\/\.github\/workflows\/reusable-docx-audit-maintenance\.yml@[0-9a-f]{40}/,
  );
  assert.doesNotMatch(CONSUMER_MAINTENANCE_WORKFLOW, /0123456789abcdef0123456789abcdef01234567/);
});

test("Consumer maintenance uses one pinned Integration Repository commit and 30 day report retention", () => {
  const auditPin = CONSUMER_WORKFLOW.match(
    /uses: SpamArtist\/docx-integration\/\.github\/workflows\/reusable-docx-audit\.yml@([0-9a-f]{40})/,
  );
  const maintenancePin = CONSUMER_MAINTENANCE_WORKFLOW.match(
    /uses: SpamArtist\/docx-integration\/\.github\/workflows\/reusable-docx-audit-maintenance\.yml@([0-9a-f]{40})/,
  );
  assert(auditPin);
  assert(maintenancePin);
  assert.equal(auditPin[1], maintenancePin[1]);
  assert.equal(maintenancePin[1], "16cd7316c9d73088b8bf1b00e67afb0849fd1b58");

  for (const workflow of [REUSABLE_WORKFLOW, MAINTENANCE_WORKFLOW]) {
    const retentionDays = [...workflow.matchAll(/retention-days:\s*(\d+)/g)]
      .map((match) => Number(match[1]));
    assert(retentionDays.some((days) => days >= 30));
  }
});

test("Issue 743 evidence states second consumer proof limits without invented URLs", () => {
  for (const requiredText of [
    "Second consumer build command is `python3 scripts/package_extension.py --out build/audit/release.zip`.",
    "Second consumer `bundle_path` is `browser/release.zip`.",
    "No live run URL, artifact URL, comment URL, or screenshot was created for this issue.",
    "Issue #744 must record live URLs or screenshots",
    "Analyzer timing is not applicable",
  ]) {
    assert.match(ISSUE_743_EVIDENCE, escapeRegExp(requiredText));
  }
  assert.doesNotMatch(ISSUE_743_EVIDENCE, /https:\/\/github\.com\/[^)\s]+\/actions\/runs\/\d+/);
  assert.doesNotMatch(ISSUE_743_EVIDENCE, /https:\/\/github\.com\/[^)\s]+\/pull\/\d+#issuecomment-\d+/);
});

test("Issue 744 evidence records final pilot blocked state and live observations", () => {
  for (const requiredText of [
    "Status: BLOCKED",
    `${"FX"} ${"Inline"} workflow directory`,
    "`DOCX_BINARY_DOWNLOAD_TOKEN` was not present.",
    "no artifact whose name matched `docx`, `DocX`, or `Pull Request Audit`",
    "`gh repo view SpamArtist/docx-integration` returned `Could not resolve to a Repository`.",
    "`gh repo view SpamArtist/docx-binary-distribution` returned `Could not resolve to a Repository`.",
    `Live PR #95 and #96 have no comments.`,
  ]) {
    assert.match(ISSUE_744_EVIDENCE, escapeRegExp(requiredText));
  }
});

test("Issue 744 evidence covers required acceptance areas and exact gaps", () => {
  for (const area of [
    "Setup",
    "Trigger and guard",
    "Bundle",
    "Binary",
    "Report",
    "Report access",
    "Comment",
    "Failure",
    "Lifecycle",
    "Secret",
    "Repository-neutral proof",
    "Counts",
    "Timing",
  ]) {
    assert.match(ISSUE_744_EVIDENCE, new RegExp(`\\| ${escapeRegExpSource(area)} \\|`));
  }
  for (const gap of [
    "Create or give access to public Integration Repository `SpamArtist/docx-integration`.",
    "Create or give access to private Binary Distribution Repository `SpamArtist/docx-binary-distribution`.",
    `Store it in ${"FX"} ${"Inline"} as \`DOCX_BINARY_DOWNLOAD_TOKEN\`.`,
    `Run successful ${"FX"} ${"Inline"} HTML audit`,
    `Run successful ${"FX"} ${"Inline"} JSON audit`,
    "Record out-of-order run behavior",
    "Run second repository-neutral Consumer Repository proof",
  ]) {
    assert.match(ISSUE_744_EVIDENCE, escapeRegExp(gap));
  }
});

test("Issue 744 evidence does not invent live workflow artifact or pull request comment URLs", () => {
  const allowedIssueCommentUrls = [
    "https://github.com/SpamArtist/docX/issues/741#issuecomment-5232951601",
    "https://github.com/SpamArtist/docX/issues/742#issuecomment-5233032618",
    "https://github.com/SpamArtist/docX/issues/743#issuecomment-5233108108",
  ];
  const liveRunUrls = [...ISSUE_744_EVIDENCE.matchAll(/https:\/\/github\.com\/[^)\s]+\/actions\/runs\/\d+/g)];
  const artifactApiUrls = [...ISSUE_744_EVIDENCE.matchAll(/https:\/\/api\.github\.com\/repos\/[^)\s]+\/actions\/artifacts\/\d+/g)];
  const pullRequestCommentUrls = [...ISSUE_744_EVIDENCE.matchAll(/https:\/\/github\.com\/[^)\s]+\/pull\/\d+#issuecomment-\d+/g)];
  const issueCommentUrls = [...ISSUE_744_EVIDENCE.matchAll(/https:\/\/github\.com\/SpamArtist\/docX\/issues\/\d+#issuecomment-\d+/g)]
    .map((match) => match[0]);

  assert.deepEqual(liveRunUrls, []);
  assert.deepEqual(artifactApiUrls, []);
  assert.deepEqual(pullRequestCommentUrls, []);
  assert.deepEqual(issueCommentUrls, allowedIssueCommentUrls);
});

test("Maintenance accepts no repository identity, extra token, or secret", () => {
  assert.doesNotMatch(MAINTENANCE_WORKFLOW, /^\s{4}inputs:/m);
  assert.doesNotMatch(MAINTENANCE_WORKFLOW, /^\s{4}secrets:/m);
  assert.doesNotMatch(CONSUMER_MAINTENANCE_WORKFLOW, /secrets:|GITHUB_TOKEN|GH_TOKEN|repository:/);
  assert.match(MAINTENANCE_WORKFLOW, /GITHUB_REPOSITORY: \$\{\{ github\.repository \}\}/);
  assert.match(MAINTENANCE_WORKFLOW, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/);
  assert.doesNotMatch(MAINTENANCE_WORKFLOW, /inputs\.repository|REPOSITORY: \$\{\{ inputs\./);
});

test("Maintenance uses only current repository token permissions", () => {
  const planJob = jobBlock(MAINTENANCE_WORKFLOW, "plan");
  const refreshJob = jobBlock(MAINTENANCE_WORKFLOW, "refresh");
  for (const job of [planJob, refreshJob]) {
    assert.match(job, /permissions:\n\s+actions: write\n\s+pull-requests: write/);
    assert.doesNotMatch(job, /contents:|packages:|id-token:|issues:/);
  }
});

test("Maintenance validates artifact identity before any refresh change", () => {
  assert.match(GUARD_SCRIPT, /parsePullRequestAuditArtifactName/);
  assert.match(GUARD_SCRIPT, /validateMaintenanceArtifactIdentity/);
  assert.match(GUARD_SCRIPT, /workflowRun\.event !== "pull_request"/);
  assert.match(GUARD_SCRIPT, /fullHeadSha\.slice\(0, 8\)/);
  assert.match(GUARD_SCRIPT, /pullRequest\.state !== "open"/);
  assert.match(GUARD_SCRIPT, /shouldRefreshPullRequestAuditArtifact/);
  assert(GUARD_SCRIPT.indexOf("validateMaintenanceArtifactIdentity") < GUARD_SCRIPT.indexOf("items.push"));
});

test("Maintenance refresh order preserves retry safety", () => {
  assert(MAINTENANCE_WORKFLOW.indexOf("Upload replacement Pull Request Audit Artifact") < MAINTENANCE_WORKFLOW.indexOf("Validate replacement Pull Request Audit Artifact"));
  assert(MAINTENANCE_WORKFLOW.indexOf("Validate replacement Pull Request Audit Artifact") < MAINTENANCE_WORKFLOW.indexOf("Refresh current report comment"));
  assert(MAINTENANCE_WORKFLOW.indexOf("Refresh current report comment") < MAINTENANCE_WORKFLOW.indexOf("Delete old Pull Request Audit Artifact"));
  assert.match(stepBlock(MAINTENANCE_WORKFLOW, "Download old Pull Request Audit Artifact"), /if: matrix\.item\.operation == 'refresh'/);
  assert.match(MAINTENANCE_WORKFLOW, /if: steps\.upload-replacement\.outcome == 'success'/);
  assert.match(MAINTENANCE_WORKFLOW, /if: matrix\.item\.is_current_report == true && steps\.validate-replacement\.outputs\.accepted == 'true'/);
  assert.match(stepBlock(MAINTENANCE_WORKFLOW, "Delete old Pull Request Audit Artifact"), /MAINTENANCE_OPERATION: \$\{\{ matrix\.item\.operation \}\}/);
  assert.match(GUARD_SCRIPT, /Old Pull Request Audit Artifact kept for retry/);
  assert.match(GUARD_SCRIPT, /shouldDeleteOldMaintenanceArtifact/);
});

test("Maintenance workflow supports closed pull request delete lifecycle", () => {
  assert.match(GUARD_SCRIPT, /CLOSED_PULL_REQUEST_RETENTION_MS = 30 \* 24 \* 60 \* 60 \* 1000/);
  assert.match(GUARD_SCRIPT, /planMaintenanceAction/);
  assert.match(GUARD_SCRIPT, /merged-non-final/);
  assert.match(GUARD_SCRIPT, /merged-final-expired/);
  assert.match(GUARD_SCRIPT, /closed-expired/);
  assert.match(GUARD_SCRIPT, /expiresAt\.getTime\(\) <= deletionTime\.getTime\(\)/);
  assert.match(GUARD_SCRIPT, /MAINTENANCE_OPERATION/);
});

test("Maintenance isolates per-item failures", () => {
  const refreshJob = jobBlock(MAINTENANCE_WORKFLOW, "refresh");
  assert.match(refreshJob, /fail-fast: false/);
  for (const step of [
    "Download old Pull Request Audit Artifact",
    "Upload replacement Pull Request Audit Artifact",
    "Validate replacement Pull Request Audit Artifact",
    "Refresh current report comment",
    "Delete old Pull Request Audit Artifact",
  ]) {
    assert.match(stepBlock(MAINTENANCE_WORKFLOW, step), /continue-on-error: true/);
  }
  assert.match(GUARD_SCRIPT, /catch \{\n\s+failures\.push/);
});

test("Build handoff uses one named artifact and no DocX secret in build job", () => {
  assert.match(CONSUMER_WORKFLOW, /name: docx-extension-bundle/);
  const buildJob = jobBlock(CONSUMER_WORKFLOW, "build-extension");
  const checkoutStep = stepBlock(CONSUMER_WORKFLOW, "Checkout pull request head");
  assert.match(buildJob, /permissions:\n\s+contents: read/);
  assert.doesNotMatch(buildJob, /actions:|pull-requests:|id-token:|packages:|issues:/);
  assert.doesNotMatch(buildJob, /DOCX_BINARY_DOWNLOAD_TOKEN|binary_download_token|secrets\./);
  assert.match(checkoutStep, /ref: \$\{\{ github\.event\.pull_request\.head\.sha \}\}/);
  assert.match(checkoutStep, /persist-credentials: false/);
  assert.match(buildJob, /github\.event\.pull_request\.head\.sha/);
  assert.match(stepBlock(CONSUMER_WORKFLOW, "Prepare Extension Bundle Artifact"), /cp -R dist\/extension docx-extension-bundle\/extension/);
});

test("Second consumer uses different repository-owned build steps and bundle path", () => {
  const primaryBuild = jobBlock(CONSUMER_WORKFLOW, "build-extension");
  const secondBuild = jobBlock(SECOND_CONSUMER_WORKFLOW, "build-extension");
  const secondAudit = jobBlock(SECOND_CONSUMER_WORKFLOW, "docx-audit");

  assert.match(secondBuild, /python3 scripts\/package_extension\.py --out build\/audit\/release\.zip/);
  assert.match(secondBuild, /cp build\/audit\/release\.zip docx-extension-bundle\/browser\/release\.zip/);
  assert.match(secondAudit, /bundle_path: browser\/release\.zip/);
  assert.doesNotMatch(primaryBuild, /python3 scripts\/package_extension\.py/);
  assert.doesNotMatch(primaryBuild, /browser\/release\.zip/);
  assert.doesNotMatch(secondBuild, /npm ci|npm run build|dist\/extension/);
});

test("Second consumer uses only the standard reusable audit interface", () => {
  const secondAudit = jobBlock(SECOND_CONSUMER_WORKFLOW, "docx-audit");

  assert.match(secondAudit, /uses: SpamArtist\/docx-integration\/\.github\/workflows\/reusable-docx-audit\.yml@[0-9a-f]{40}/);
  assert.match(secondAudit, /docx_version: 1\.2\.3/);
  assert.match(secondAudit, /bundle_path: browser\/release\.zip/);
  assert.match(secondAudit, /report_format: \$\{\{ vars\.DOCX_PULL_REQUEST_AUDIT_FORMAT \|\| 'html' \}\}/);
  assert.match(secondAudit, /permissions:\n\s+contents: read\n\s+actions: write\n\s+pull-requests: write/);
  assert.match(secondAudit, /secrets:\n\s+binary_download_token: \$\{\{ secrets\.DOCX_BINARY_DOWNLOAD_TOKEN \}\}/);
  assert.doesNotMatch(secondAudit, new RegExp(`secrets:\\s*inherit|repository:|asset:|url:|${"allow"}${"list"}`));
});

test("Second consumer keeps fork and Dependabot guards before reusable workflow secret", () => {
  for (const workflow of [CONSUMER_WORKFLOW, SECOND_CONSUMER_WORKFLOW]) {
    const buildJob = jobBlock(workflow, "build-extension");
    assert.match(buildJob, /!github\.event\.pull_request\.draft/);
    assert.match(buildJob, /github\.event\.pull_request\.head\.repo\.full_name == github\.event\.pull_request\.base\.repo\.full_name/);
    assert.match(buildJob, /github\.actor != 'dependabot\[bot\]'/);
    assert.match(buildJob, /github\.event\.pull_request\.user\.login != 'dependabot\[bot\]'/);
    assert.doesNotMatch(buildJob, /DOCX_BINARY_DOWNLOAD_TOKEN|binary_download_token|secrets\./);
  }
});

test("Second consumer proof covers success and safe failure observations", () => {
  for (const requiredText of [
    "| Successful audit |",
    "| Invalid bundle |",
    "| DocX failure |",
    "| Publication failure |",
    "| Fork pull request |",
    "| Cross-consumer isolation |",
  ]) {
    assert.match(ISSUE_743_EVIDENCE, escapeRegExp(requiredText));
  }
});

test("Consumer Workflow reusable call uses minimum permissions and one named secret", () => {
  const auditJob = jobBlock(CONSUMER_WORKFLOW, "docx-audit");
  assert.match(auditJob, /needs:\n\s+- build-extension/);
  assert.match(auditJob, /if: needs\.build-extension\.result == 'success'/);
  assert.match(auditJob, /permissions:\n\s+contents: read\n\s+actions: write\n\s+pull-requests: write/);
  assert.doesNotMatch(auditJob, /id-token:|packages:|issues:|checks:|statuses:|deployments:/);
  assert.match(auditJob, /secrets:\n\s+binary_download_token: \$\{\{ secrets\.DOCX_BINARY_DOWNLOAD_TOKEN \}\}/);
  assert.doesNotMatch(auditJob, /secrets:\s*inherit|DOCX_BINARY_DOWNLOAD_TOKEN.*build-extension/);
});

test("Consumer Workflow pins stable DocX inputs and supports HTML or JSON report mode", () => {
  const auditJob = jobBlock(CONSUMER_WORKFLOW, "docx-audit");
  assert.match(auditJob, /docx_version: 1\.2\.3/);
  assert.doesNotMatch(auditJob, /docx_version:\s*(v|latest|main|master|[^\n]*\*)/);
  assert.match(auditJob, /bundle_path: extension/);
  assert.doesNotMatch(auditJob, /bundle_path:\s*(\/|\.\.|https?:|.*\*|.*\.xpi|.*,.+)/);
  assert.match(auditJob, /report_format: \$\{\{ vars\.DOCX_PULL_REQUEST_AUDIT_FORMAT \|\| 'html' \}\}/);
  assert.match(GUARD_SCRIPT, /const SUPPORTED_REPORT_FORMATS = new Set\(\["html", "json"\]\)/);
});

test("Consumer Workflow keeps consumer-specific details inside build steps", () => {
  const buildJob = jobBlock(CONSUMER_WORKFLOW, "build-extension");
  const auditJob = jobBlock(CONSUMER_WORKFLOW, "docx-audit");
  const reusableWorkflows = `${REUSABLE_WORKFLOW}\n${MAINTENANCE_WORKFLOW}\n${CONSUMER_MAINTENANCE_WORKFLOW}`;

  for (const consumerDetail of ["npm ci", "npm run build", "dist/extension"]) {
    assert.match(buildJob, escapeRegExp(consumerDetail));
    assert.doesNotMatch(auditJob, escapeRegExp(consumerDetail));
    assert.doesNotMatch(reusableWorkflows, escapeRegExp(consumerDetail));
  }
});

test("Integration Repository source set has no first-consumer-specific names or rules", () => {
  const source = listFiles(ROOT)
    .map((file) => readFileSync(join(ROOT, file), "utf8"))
    .join("\n");
  for (const forbidden of [
    `FX ${"Inline"}`,
    `FX-${"Inline"}`,
    `fx-${"inline"}`,
    `FX_${"INLINE"}`,
    `Chrome Web ${"Store"}`,
    `currency-conversion-extension-${"tool"}`,
  ]) {
    assert.doesNotMatch(source, escapeRegExp(forbidden));
  }
  assert.doesNotMatch(source, new RegExp(`\\b${"allow"}${"list"}\\b`, "i"));
});

test("Reusable workflow gates secret-dependent step", () => {
  const secretStep = stepBlock(REUSABLE_WORKFLOW, "Download and verify Prebuilt DocX Binary");
  assert.match(secretStep, /if: steps\.current-head\.outputs\.should_use_secret == 'true'/);
  assert.match(secretStep, /GH_TOKEN: \$\{\{ secrets\.binary_download_token \}\}/);

  for (const skippedCode of [
    "draft-pull-request",
    "fork-pull-request",
    "dependabot-pull-request",
    "non-main-base",
    "unsupported-action",
    "unsupported-event",
    "stale-head",
  ]) {
    assert.match(
      readFileSync(join(ROOT, "tests/docx-audit-workflow-guards.test.mjs"), "utf8"),
      new RegExp(skippedCode),
    );
  }
});

test("Reusable workflow uses verified executable only after binary verification", () => {
  const binaryStep = stepBlock(REUSABLE_WORKFLOW, "Download and verify Prebuilt DocX Binary");
  const auditStep = stepBlock(REUSABLE_WORKFLOW, "Run DocX audit");

  assert.match(binaryStep, /download-binary/);
  assert.match(binaryStep, /BINARY_VERIFICATION_STATE: \$\{\{ runner\.temp \}\}\/docx-binary-verification\/state\.json/);
  assert.match(auditStep, /if: steps\.binary\.outputs\.verified == 'true'/);
  assert.match(auditStep, /resolve-executable/);
  assert.match(auditStep, /\$DOCX_BIN" audit "\$BUNDLE_PATH"/);
  assert(auditStep.indexOf("resolve-executable") < auditStep.indexOf('$DOCX_BIN" audit'));
  assert.doesNotMatch(auditStep, /secrets\.|GH_TOKEN|binary_download_token/i);
});

test("Reusable workflow passes selected audited root config explicitly to DocX", () => {
  const checkoutStep = stepBlock(REUSABLE_WORKFLOW, "Checkout root configuration");
  const auditStep = stepBlock(REUSABLE_WORKFLOW, "Run DocX audit");

  assert.match(checkoutStep, /ref: \$\{\{ steps\.request\.outputs\.head_sha \}\}/);
  assert.match(checkoutStep, /docx\.yml/);
  assert.match(checkoutStep, /docx\.toml/);
  assert.match(auditStep, /--config "consumer-root-config\/docx\.yml"/);
  assert.match(auditStep, /--config "consumer-root-config\/docx\.toml"/);
  assert(auditStep.indexOf("docx.yml") < auditStep.indexOf("docx.toml"));
});

test("Reusable workflow uploads one immutable uncompressed artifact with short SHA name", () => {
  const reportStep = stepBlock(REUSABLE_WORKFLOW, "Validate selected report file");
  const nameStep = stepBlock(REUSABLE_WORKFLOW, "Prepare Pull Request Audit Artifact name");
  const uploadStep = stepBlock(REUSABLE_WORKFLOW, "Upload Pull Request Audit Artifact");
  const outputStep = stepBlock(REUSABLE_WORKFLOW, "Publish report URL and artifact metadata");

  assert.match(reportStep, /validate-report/);
  assert.match(nameStep, /artifact-name/);
  assert.match(nameStep, /REPOSITORY: \$\{\{ github\.event\.repository\.full_name \}\}/);
  assert.match(uploadStep, /name: \$\{\{ steps\.artifact-name\.outputs\.artifact_name \}\}/);
  assert.match(uploadStep, /path: \$\{\{ steps\.report-file\.outputs\.report_path \}\}/);
  assert.match(uploadStep, /compression-level: 0/);
  assert.match(uploadStep, /overwrite: false/);
  assert.match(outputStep, /UPLOAD_ARTIFACT_URL: \$\{\{ steps\.upload-report\.outputs\.artifact-url \}\}/);
  assert.match(outputStep, /UPLOAD_ARTIFACT_ID: \$\{\{ steps\.upload-report\.outputs\.artifact-id \}\}/);
  assert.match(outputStep, /publish-report-output/);
});

test("Reusable workflow writes operational records and keeps them for 30 days", () => {
  const binaryStep = stepBlock(REUSABLE_WORKFLOW, "Download and verify Prebuilt DocX Binary");
  const auditStep = stepBlock(REUSABLE_WORKFLOW, "Run DocX audit");
  const recordsStep = stepBlock(REUSABLE_WORKFLOW, "Upload audit operational records");

  assert.match(binaryStep, /BINARY_DOWNLOAD_RECORD_PATH: \$\{\{ runner\.temp \}\}\/docx-audit-operational-records\/binary-download-record\.json/);
  assert.match(binaryStep, /CONSUMER_REPOSITORY: \$\{\{ github\.event\.repository\.full_name \}\}/);
  assert.match(binaryStep, /WORKFLOW_RUN_ID: \$\{\{ github\.run_id \}\}/);
  assert.match(binaryStep, /WORKFLOW_RUN_ATTEMPT: \$\{\{ github\.run_attempt \}\}/);
  assert.match(binaryStep, /COMMIT_SHA: \$\{\{ steps\.request\.outputs\.head_sha \}\}/);
  assert.match(auditStep, /DOCX_EXECUTION_RECEIPT_PATH: \$\{\{ runner\.temp \}\}\/docx-audit-operational-records\/docx-execution-receipt\.json/);
  assert.match(auditStep, /DOCX_EXIT_CODE="\$status" node docx-integration\/scripts\/docx-audit-workflow-guards\.mjs write-execution-receipt/);
  assert(auditStep.indexOf('DOCX_EXIT_CODE="$status"') < auditStep.indexOf('if [ "$status" -ne 0 ]'));
  assert.match(recordsStep, /if: always\(\) && steps\.current-head\.outputs\.should_use_secret == 'true'/);
  assert.match(recordsStep, /name: docx-operational-records-\$\{\{ github\.run_id \}\}-\$\{\{ github\.run_attempt \}\}/);
  assert.match(recordsStep, /path: \$\{\{ runner\.temp \}\}\/docx-audit-operational-records\/\*\.json/);
  assert.match(recordsStep, /retention-days: 30/);
  assert.match(recordsStep, /compression-level: 0/);
  assert.doesNotMatch(recordsStep, /binary_download_token|GH_TOKEN|secrets\./i);
});

test("Reusable workflow updates one marked pull request comment after report upload", () => {
  const commentJob = jobBlock(REUSABLE_WORKFLOW, "comment");
  const commentStep = stepBlock(REUSABLE_WORKFLOW, "Update marked comment");

  assert.match(GUARD_SCRIPT, /<!-- docx-pull-request-audit -->/);
  assert.match(commentJob, /needs:\n\s+- audit/);
  assert.match(commentJob, /if: needs\.audit\.outputs\.report_url != ''/);
  assert.match(commentJob, /permissions:\n\s+pull-requests: write/);
  assert.doesNotMatch(commentJob, /actions: write/);
  assert.match(commentStep, /continue-on-error: true/);
  assert.match(commentStep, /GITHUB_TOKEN: \$\{\{ github\.token \}\}/);
  assert.match(commentStep, /DOCX_VERSION: \$\{\{ inputs\.docx_version \}\}/);
  assert.match(commentStep, /AUDITED_SHA: \$\{\{ needs\.audit\.outputs\.audited_sha \}\}/);
  assert.match(commentStep, /REPORT_FORMAT: \$\{\{ needs\.audit\.outputs\.report_format \}\}/);
  assert.match(commentStep, /REPORT_URL: \$\{\{ needs\.audit\.outputs\.report_url \}\}/);
  assert.match(commentStep, /update-comment/);
  assert.doesNotMatch(commentStep, /binary_download_token|secrets\./i);
  assert(REUSABLE_WORKFLOW.indexOf("Upload Pull Request Audit Artifact") < REUSABLE_WORKFLOW.indexOf("Update marked comment"));
});

test("Reusable workflow reads live pull request head before comment update", () => {
  assert.match(GUARD_SCRIPT, /getPullRequestHeadSha\(repository, pullRequestNumber\)/);
  assert.match(GUARD_SCRIPT, /Current pull request head does not match audited commit/);
  assert.match(GUARD_SCRIPT, /listIssueComments\(repository, pullRequestNumber\)/);
  assert.match(GUARD_SCRIPT, /github-actions\[bot\]/);
  assert.match(GUARD_SCRIPT, /createIssueComment\(repository, pullRequestNumber, body\)/);
  assert.match(GUARD_SCRIPT, /updateIssueComment\(repository, commentId, body\)/);
});

test("Reusable workflow deletes older same-identity artifact only after comment update succeeds", () => {
  const cleanupJob = jobBlock(REUSABLE_WORKFLOW, "artifact-cleanup");
  const cleanupStep = stepBlock(REUSABLE_WORKFLOW, "Delete older artifact for same report identity");

  assert.match(cleanupJob, /needs:\n\s+- audit\n\s+- comment/);
  assert.match(cleanupJob, /if: needs\.comment\.outputs\.updated == 'true'/);
  assert.match(cleanupJob, /permissions:\n\s+actions: write/);
  assert.match(cleanupStep, /continue-on-error: true/);
  assert.match(cleanupStep, /ARTIFACT_NAME: \$\{\{ needs\.audit\.outputs\.artifact_name \}\}/);
  assert.match(cleanupStep, /CURRENT_ARTIFACT_ID: \$\{\{ needs\.audit\.outputs\.artifact_id \}\}/);
  assert.match(cleanupStep, /delete-older-artifacts/);
  assert(REUSABLE_WORKFLOW.indexOf("Update marked comment") < REUSABLE_WORKFLOW.indexOf("Delete older artifact for same report identity"));
});

test("Reusable workflow leaves report URL empty for DocX, report, or upload failure", () => {
  const auditStep = stepBlock(REUSABLE_WORKFLOW, "Run DocX audit");
  const reportStep = stepBlock(REUSABLE_WORKFLOW, "Validate selected report file");
  const uploadStep = stepBlock(REUSABLE_WORKFLOW, "Upload Pull Request Audit Artifact");
  const outputStep = stepBlock(REUSABLE_WORKFLOW, "Publish report URL and artifact metadata");

  assert.match(auditStep, /continue-on-error: true/);
  assert.match(auditStep, /cleanup-report/);
  assert.match(auditStep, /docx-exit-code-\$\{status\}/);
  assert(auditStep.indexOf("cleanup-report") < auditStep.indexOf("exit \"$status\""));
  assert.match(reportStep, /if: steps\.audit\.outcome == 'success'/);
  assert.match(reportStep, /continue-on-error: true/);
  assert.match(uploadStep, /if: steps\.report-file\.outputs\.accepted == 'true'/);
  assert.match(uploadStep, /continue-on-error: true/);
  assert.match(outputStep, /UPLOAD_OUTCOME: \$\{\{ steps\.upload-report\.outcome \}\}/);
});

test("Reusable workflow contains expected and unexpected audit failures", () => {
  const auditJob = jobBlock(REUSABLE_WORKFLOW, "audit");
  const commentJob = jobBlock(REUSABLE_WORKFLOW, "comment");
  const cleanupJob = jobBlock(REUSABLE_WORKFLOW, "artifact-cleanup");
  const downloadStep = stepBlock(REUSABLE_WORKFLOW, "Download Extension Bundle Artifact");
  const artifactHeadStep = stepBlock(REUSABLE_WORKFLOW, "Validate Extension Bundle Artifact head");
  const rootConfigStep = stepBlock(REUSABLE_WORKFLOW, "Checkout root configuration");
  const currentHeadStep = stepBlock(REUSABLE_WORKFLOW, "Confirm current pull request head");
  const downloadWarningStep = stepBlock(REUSABLE_WORKFLOW, "Warn about Extension Bundle Artifact download failure");
  const configWarningStep = stepBlock(REUSABLE_WORKFLOW, "Warn about root configuration checkout failure");

  assert.match(auditJob, /continue-on-error: true/);
  assert.match(commentJob, /continue-on-error: true/);
  assert.match(cleanupJob, /continue-on-error: true/);
  assert.match(downloadStep, /continue-on-error: true/);
  assert.match(rootConfigStep, /continue-on-error: true/);
  assert.match(artifactHeadStep, /if: steps\.request\.outputs\.should_run == 'true' && steps\.extension-bundle\.outcome == 'success'/);
  assert.match(currentHeadStep, /if: steps\.bundle\.outputs\.accepted == 'true' && steps\.root-config\.outcome == 'success'/);
  assert.match(downloadWarningStep, /extension-bundle-download-failed/);
  assert.match(configWarningStep, /root-config-checkout-failed/);
});

test("Binary verifier checks release attestation before asset attestation", () => {
  assert.match(GUARD_SCRIPT, /async verifyRelease\(repository, tag\)/);
  assert.match(GUARD_SCRIPT, /"release",\s*"verify",\s*tag,\s*"--repo",\s*repository/);
  assert(GUARD_SCRIPT.indexOf("await client.verifyRelease(") < GUARD_SCRIPT.indexOf("await client.verifyReleaseAsset("));
});

test("Reusable workflow confirms current head from actual checkout", () => {
  const currentHeadStep = stepBlock(REUSABLE_WORKFLOW, "Confirm current pull request head");

  assert.match(currentHeadStep, /git -C consumer-root-config rev-parse HEAD/);
  assert.match(currentHeadStep, /export CHECKED_OUT_SHA/);
  assert.doesNotMatch(
    currentHeadStep,
    /CHECKED_OUT_SHA:\s*\$\{\{\s*steps\.request\.outputs\.head_sha\s*\}\}/,
  );
});

test("Reusable workflow keeps Binary Download Token only in verification step", () => {
  const tokenMentions = REUSABLE_WORKFLOW
    .split("\n")
    .map((line, index) => ({ line, index }))
    .filter(({ line }) => /binary_download_token|GH_TOKEN/.test(line));
  const secretStep = stepBlock(REUSABLE_WORKFLOW, "Download and verify Prebuilt DocX Binary");

  assert(tokenMentions.length > 0);
  for (const { line } of tokenMentions) {
    if (/^\s{6}binary_download_token:/.test(line)) {
      continue;
    }
    assert.match(secretStep, escapeRegExp(line.trim()));
  }
});

test("Reusable workflow does not use cache, fallback, toolchain commands, or source checkout", () => {
  assert.doesNotMatch(REUSABLE_WORKFLOW, /actions\/cache|cache:/i);
  assert.doesNotMatch(REUSABLE_WORKFLOW, /\bfallback\b|\blatest\b/);
  assert.doesNotMatch(
    REUSABLE_WORKFLOW,
    new RegExp(`\\b${"rust"}up\\b|\\b${"rust"}${"c"}\\b|\\b${"car"}${"go"}\\b|${"rust"}-toolchain`, "i"),
  );
  assert.doesNotMatch(REUSABLE_WORKFLOW, /DocX source|checkout.*DocX/i);
});

test("Reusable workflow helper checkout pins the Integration Repository", () => {
  for (const workflow of [REUSABLE_WORKFLOW, MAINTENANCE_WORKFLOW]) {
    assert.doesNotMatch(workflow, /github\.workflow_(ref|sha)|integration-source/);
    for (const checkoutStep of workflow.matchAll(/- name: Checkout integration helpers[\s\S]*?(?=\n      - name:|\n  \w|$)/g)) {
      assert.match(checkoutStep[0], /repository: SpamArtist\/docx-integration/);
      assert.match(checkoutStep[0], /ref: [0-9a-f]{40}/i);
    }
  }
});

test("Workflow action references use full commit SHAs", () => {
  for (const workflow of [
    REUSABLE_WORKFLOW,
    MAINTENANCE_WORKFLOW,
    CONSUMER_WORKFLOW,
    SECOND_CONSUMER_WORKFLOW,
    CONSUMER_MAINTENANCE_WORKFLOW,
  ]) {
    for (const line of workflow.split("\n").filter((candidate) => candidate.includes("uses: "))) {
      const ref = line.split("@")[1];
      assert.match(ref, /^[0-9a-f]{40}$/i, line);
    }
  }
});

test("Integration source set contains no DocX source or Prebuilt DocX Binary", () => {
  const files = listFiles(ROOT);
  assert(!files.some((file) => file.endsWith(".rs")), "rs source must stay out");
  const manifestName = `${"Car"}${"go"}.toml`;
  assert(!files.some((file) => file.endsWith(manifestName)), "toolchain manifest files must stay out");
  assert(!files.some((file) => /(^|\/)DocX($|[-.])/.test(file)), "DocX binary must stay out");
});

function jobBlock(workflow, jobName) {
  const start = workflow.indexOf(`  ${jobName}:`);
  assert.notEqual(start, -1, jobName);
  const rest = workflow.slice(start + 1);
  const nextJob = rest.search(/\n  [a-zA-Z0-9_-]+:\n/);
  return nextJob === -1 ? rest : rest.slice(0, nextJob);
}

function stepBlock(workflow, stepName) {
  const start = workflow.indexOf(`- name: ${stepName}`);
  assert.notEqual(start, -1, stepName);
  const rest = workflow.slice(start);
  const nextStep = rest.indexOf("\n      - name: ", 1);
  return nextStep === -1 ? rest : rest.slice(0, nextStep);
}

function escapeRegExp(value) {
  return new RegExp(value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
}

function escapeRegExpSource(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function listFiles(directory) {
  const entries = [];
  for (const name of readdirSync(directory)) {
    const path = join(directory, name);
    const stats = statSync(path);
    if (stats.isDirectory()) {
      entries.push(...listFiles(path));
    } else {
      entries.push(path.slice(ROOT.length));
    }
  }
  return entries;
}
