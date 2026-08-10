import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  BinaryVerificationError,
  DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER,
  buildBinaryDownloadRecord,
  buildDocXExecutionReceipt,
  buildSafeWorkflowWarning,
  buildPullRequestAuditArtifactName,
  buildPullRequestAuditCommentBody,
  deleteOlderPullRequestAuditArtifacts,
  deriveBinaryRelease,
  evaluateAuditRequest,
  parsePullRequestAuditArtifactName,
  planMaintenanceAction,
  planPullRequestAuditMaintenance,
  publishPullRequestAuditArtifactMetadata,
  removePartialPullRequestAuditReport,
  refreshCurrentPullRequestAuditComment,
  shouldDeleteOldMaintenanceArtifact,
  shouldRefreshPullRequestAuditArtifact,
  updatePullRequestAuditComment,
  validateMaintenanceArtifactIdentity,
  validateMaintenanceUpload,
  verifyPrebuiltBinary,
  verifyPrebuiltBinaryAttempt,
  validateArtifactHead,
  validateBundlePath,
  validatePullRequestAuditReportFile,
} from "../scripts/docx-audit-workflow-guards.mjs";

const HEAD_SHA = "1111111111111111111111111111111111111111";
const NEXT_HEAD_SHA = "2222222222222222222222222222222222222222";
const ROOT = new URL("..", import.meta.url).pathname;
const GUARD_SCRIPT_PATH = join(ROOT, "scripts/docx-audit-workflow-guards.mjs");
const RECORD_TIME = "2026-08-09T00:00:00.000Z";
const MARKED_TEST_SECRET = "DOCX_TEST_SECRET_BINARY_DOWNLOAD_TOKEN_738";
const MARKED_RESTRICTED_VALUES = [
  MARKED_TEST_SECRET,
  "DOCX_TEST_RESTRICTED_REQUEST_HEADER_738",
  "DOCX_TEST_RESTRICTED_API_BODY_738",
  "https://example.invalid/DOCX_TEST_RESTRICTED_SIGNED_URL_738?sig=secret",
  "feedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedfacefeedface",
  "DOCX_TEST_RESTRICTED_ENV_DUMP_738",
  "DOCX_TEST_RESTRICTED_REPORT_CONTENT_738",
  "DOCX_TEST_RESTRICTED_CONFIG_CONTENT_738",
];

test("accepts eligible pull request event before secret use", () => {
  const result = evaluateAuditRequest({
    eventName: "pull_request",
    action: "opened",
    actor: "alice",
    docxVersion: "1.2.3",
    event: pullRequestEvent(),
  });

  assert.equal(result.shouldRun, true);
  assert.equal(result.shouldUseSecret, true);
  assert.equal(result.headSha, HEAD_SHA);
  assert.equal(result.reportFormat, "html");
});

test("rejects ineligible requests before secret use", () => {
  const cases = [
    ["draft-pull-request", { event: pullRequestEvent({ draft: true }) }],
    ["fork-pull-request", { event: pullRequestEvent({ headRepo: "other/repo" }) }],
    ["dependabot-pull-request", { actor: "dependabot[bot]" }],
    ["non-main-base", { event: pullRequestEvent({ baseRef: "develop" }) }],
    ["unsupported-action", { action: "closed" }],
    ["unsupported-event", { eventName: "workflow_dispatch" }],
    ["stale-head", { checkedOutSha: "2222222222222222222222222222222222222222" }],
    ["invalid-docx-version", { docxVersion: "v1.2.3" }],
    ["invalid-docx-version", { docxVersion: "1.2.3-beta.1" }],
    ["invalid-docx-version", { docxVersion: "1.2.x" }],
    ["invalid-docx-version", { docxVersion: "1111111111111111111111111111111111111111" }],
    ["unsupported-report-format", { reportFormat: "xml" }],
  ];

  for (const [code, overrides] of cases) {
    const result = evaluateAuditRequest({
      eventName: "pull_request",
      action: "opened",
      actor: "alice",
      docxVersion: "1.2.3",
      reportFormat: "html",
      event: pullRequestEvent(),
      ...overrides,
    });
    assert.equal(result.shouldRun, false, code);
    assert.equal(result.shouldUseSecret, false, code);
    assert.equal(result.code, code);
  }
});

test("accepts one supported bundle path inside artifact root", () => {
  const root = fixtureRoot();
  mkdirSync(join(root, "extension"));
  writeFileSync(join(root, "extension.zip"), "zip");
  writeFileSync(join(root, "extension.crx"), "crx");

  assertAcceptedBundle(root, "extension", "directory");
  assertAcceptedBundle(root, "extension.zip", "zip");
  assertAcceptedBundle(root, "extension.crx", "crx");
});

test("rejects unsafe or unsupported bundle paths", () => {
  const root = fixtureRoot();
  mkdirSync(join(root, "extension"));
  writeFileSync(join(root, "extension.zip"), "zip");
  writeFileSync(join(root, "extension.xpi"), "xpi");
  writeFileSync(join(root, "extension.txt"), "text");
  const outside = fixtureRoot();
  writeFileSync(join(outside, "outside.zip"), "zip");
  symlinkSync(join(outside, "outside.zip"), join(root, "outside.zip"));

  const cases = [
    ["absolute-path", join(root, "extension.zip")],
    ["parent-path", "../extension.zip"],
    ["missing-path", "missing.zip"],
    ["outside-root", "outside.zip"],
    ["url-path", "https://example.com/extension.zip"],
    ["glob-path", "*.zip"],
    ["xpi-not-supported", "extension.xpi"],
    ["multiple-paths", "extension.zip,extension.crx"],
    ["unsupported-type", "extension.txt"],
  ];

  for (const [code, bundlePath] of cases) {
    const result = validateBundlePath({ artifactRoot: root, bundlePath });
    assert.equal(result.accepted, false, bundlePath);
    assert.equal(result.code, code, bundlePath);
  }
});

test("validates Extension Bundle Artifact head marker", () => {
  assert.equal(
    validateArtifactHead({ expectedHeadSha: HEAD_SHA, artifactHeadSha: HEAD_SHA }).accepted,
    true,
  );
  const result = validateArtifactHead({
    expectedHeadSha: HEAD_SHA,
    artifactHeadSha: "2222222222222222222222222222222222222222",
  });
  assert.equal(result.accepted, false);
  assert.equal(result.code, "artifact-head-mismatch");
});

test("verifies exact immutable Prebuilt DocX Binary release", async () => {
  const fixture = binaryReleaseFixture("1.2.3");
  const client = new FakeReleaseClient(fixture);
  const statePath = join(fixture.root, "state.json");

  const result = await verifyPrebuiltBinary({
    version: "1.2.3",
    downloadDir: join(fixture.root, "download"),
    statePath,
  }, client);

  assert.equal(result.verified, true);
  assert.equal(client.verifiedRelease, true);
  assert.equal(client.verifiedAssets.length, 2);
  const state = JSON.parse(readFileSync(statePath, "utf8"));
  assert.equal(sha256File(state.executable_path), fixture.executableSha256);
  assert.equal(existsSync(state.executable_path), true);
});

test("writes one Binary Download Record per verification attempt", async () => {
  const successFixture = binaryReleaseFixture("1.2.3");
  const successRecordPath = join(successFixture.root, "records", "binary-download-record.json");
  await verifyPrebuiltBinaryAttempt(binaryAttemptInput(successFixture, { recordPath: successRecordPath }), new FakeReleaseClient(successFixture));
  const successRecord = JSON.parse(readFileSync(successRecordPath, "utf8"));
  assert.deepEqual(Object.keys(successRecord), [
    "consumer_repository",
    "workflow_run_id",
    "workflow_run_attempt",
    "commit_sha",
    "docx_version",
    "release_tag",
    "asset_name",
    "time",
    "result",
    "safe_failure_code",
    "verified_archive_digest",
  ]);
  assert.equal(successRecord.result, "verified");
  assert.equal(successRecord.safe_failure_code, "");
  assert.equal(successRecord.verified_archive_digest, successFixture.archiveSha256);

  const earlyFailureFixture = binaryReleaseFixture("1.2.3");
  const earlyFailureRecordPath = join(earlyFailureFixture.root, "records", "binary-download-record.json");
  await assert.rejects(
    verifyPrebuiltBinaryAttempt(
      binaryAttemptInput(earlyFailureFixture, { recordPath: earlyFailureRecordPath }),
      new FakeReleaseClient(earlyFailureFixture, { failure: "invalid-token" }),
    ),
    /Binary Download Token was rejected/,
  );
  const earlyFailureRecord = JSON.parse(readFileSync(earlyFailureRecordPath, "utf8"));
  assert.deepEqual(Object.keys(earlyFailureRecord), [
    "consumer_repository",
    "workflow_run_id",
    "workflow_run_attempt",
    "commit_sha",
    "docx_version",
    "release_tag",
    "asset_name",
    "time",
    "result",
    "safe_failure_code",
  ]);
  assert.equal(earlyFailureRecord.result, "failed");
  assert.equal(earlyFailureRecord.safe_failure_code, "invalid-token");

  const lateFailureFixture = binaryReleaseFixture("1.2.3");
  const lateFailureRecordPath = join(lateFailureFixture.root, "records", "binary-download-record.json");
  await assert.rejects(
    verifyPrebuiltBinaryAttempt(
      binaryAttemptInput(lateFailureFixture, { recordPath: lateFailureRecordPath }),
      new FakeReleaseClient(lateFailureFixture, { wrongExecutableDigest: true }),
    ),
    /executable manifest/,
  );
  const lateFailureRecord = JSON.parse(readFileSync(lateFailureRecordPath, "utf8"));
  assert.equal(lateFailureRecord.result, "failed");
  assert.equal(lateFailureRecord.safe_failure_code, "digest-mismatch");
  assert.equal(lateFailureRecord.verified_archive_digest, lateFailureFixture.archiveSha256);
});

test("binary verification derives release identity from exact version", () => {
  const identity = deriveBinaryRelease("1.2.3");
  assert.equal(identity.repository, "SpamArtist/docx-binary-distribution");
  assert.equal(identity.tag, "v1.2.3");
  assert.equal(identity.archiveName, "DocX-v1.2.3-x86_64-unknown-linux-gnu.tar.gz");
  assert.equal(identity.manifestName, "DocX-v1.2.3-x86_64-unknown-linux-gnu.manifest.json");
  assert.throws(() => deriveBinaryRelease("v1.2.3"), /stable semantic version/);
});

test("binary verification stops on token, release, attestation, and digest failures", async () => {
  const cases = [
    ["invalid-token", "invalid-token", "rejected", (fixture) => new FakeReleaseClient(fixture, { failure: "invalid-token" })],
    ["missing-exact-release", "missing-exact-release", "missing", (fixture) => new FakeReleaseClient(fixture, { missingRelease: true })],
    ["mutable-release", "mutable-release", "not immutable", (fixture) => new FakeReleaseClient(fixture, { mutableRelease: true })],
    ["wrong-release-attestation", "wrong-release-attestation", "attestation", (fixture) => new FakeReleaseClient(fixture, { failure: "wrong-release-attestation" })],
    ["wrong-attestation", "wrong-attestation", "attestation", (fixture) => new FakeReleaseClient(fixture, { failure: "wrong-attestation" })],
    ["wrong-archive-digest", "digest-mismatch", "archive GitHub metadata", (fixture) => new FakeReleaseClient(fixture, { wrongArchiveDigest: true })],
    ["wrong-executable-digest", "digest-mismatch", "executable manifest", (fixture) => new FakeReleaseClient(fixture, { wrongExecutableDigest: true })],
  ];

  for (const [name, expectedCode, expectedMessage, clientFactory] of cases) {
    const fixture = binaryReleaseFixture("1.2.3");
    const statePath = join(fixture.root, "state.json");
    const client = clientFactory(fixture);
    await assert.rejects(
      verifyPrebuiltBinary({
        version: "1.2.3",
        downloadDir: join(fixture.root, "download"),
        statePath,
      }, client),
      (error) => {
        assert.equal(error instanceof BinaryVerificationError, true, name);
        assert.equal(error.code, expectedCode, name);
        assert.match(error.message, new RegExp(expectedMessage), name);
        return true;
      },
      name,
    );
    assert.equal(existsSync(statePath), false, name);
    if (name === "wrong-release-attestation") {
      assert.equal(client.downloadedAssets.length, 0, name);
    }
  }
});

test("builds visible Pull Request Audit Artifact name with repo, PR, short SHA, and format", () => {
  const name = buildPullRequestAuditArtifactName({
    repository: "SpamArtist/consumer-extension",
    pullRequestNumber: 735,
    headSha: HEAD_SHA,
    reportFormat: "html",
  });

  assert.equal(name, "SpamArtist-consumer-extension-pr-735-11111111-html");
});

test("accepts exactly one complete selected report file in private temp", () => {
  const privateTemp = fixtureRoot();
  const reportDir = join(privateTemp, "docx-pull-request-audit-report");
  mkdirSync(reportDir);
  const reportPath = join(reportDir, "report.json");
  writeFileSync(reportPath, "{}\n");

  const result = validatePullRequestAuditReportFile({
    privateTempDir: privateTemp,
    reportDir,
    reportPath,
    reportFormat: "json",
  });

  assert.equal(result.accepted, true);
  assert.equal(result.reportPath.endsWith("/docx-pull-request-audit-report/report.json"), true);
  assert.equal(result.size, 3);
});

test("rejects missing, empty, extra, wrong format, and outside report files", () => {
  const privateTemp = fixtureRoot();
  const reportDir = join(privateTemp, "docx-pull-request-audit-report");
  mkdirSync(reportDir);
  const outside = fixtureRoot();
  const cases = [
    ["missing-report", join(reportDir, "missing.html"), () => {}],
    ["incomplete-report", join(reportDir, "empty.html"), (path) => writeFileSync(path, "")],
    ["multiple-report-files", join(reportDir, "report.html"), (path) => {
      writeFileSync(path, "<html></html>");
      writeFileSync(join(reportDir, "extra.html"), "<html></html>");
    }],
    ["wrong-report-format", join(reportDir, "report.json"), (path) => writeFileSync(path, "{}\n")],
    ["outside-private-temp", join(outside, "report.html"), (path) => writeFileSync(path, "<html></html>")],
  ];

  for (const [code, reportPath, prepare] of cases) {
    rmSync(reportDir, { recursive: true, force: true });
    mkdirSync(reportDir);
    prepare(reportPath);
    const result = validatePullRequestAuditReportFile({
      privateTempDir: privateTemp,
      reportDir,
      reportPath,
      reportFormat: "html",
    });
    assert.equal(result.accepted, false, code);
    assert.equal(result.code, code);
  }
});

test("publishes exact upload URL and metadata only after upload success", () => {
  const metadata = publishPullRequestAuditArtifactMetadata({
    uploadOutcome: "success",
    artifactUrl: "https://github.com/SpamArtist/consumer/actions/runs/1/artifacts/123",
    artifactId: "123",
    artifactName: "SpamArtist-consumer-pr-735-11111111-html",
    repository: "SpamArtist/consumer",
    pullRequestNumber: 735,
    headSha: HEAD_SHA,
    reportFormat: "html",
  });

  assert.equal(metadata.reportUrl, "https://github.com/SpamArtist/consumer/actions/runs/1/artifacts/123");
  assert.equal(metadata.artifactId, "123");
  assert.deepEqual(JSON.parse(metadata.metadataJson), {
    repository: "SpamArtist/consumer",
    pull_request_number: 735,
    audited_commit_sha: HEAD_SHA,
    report_format: "html",
    artifact_name: "SpamArtist-consumer-pr-735-11111111-html",
    github_artifact_id: "123",
    report_url: "https://github.com/SpamArtist/consumer/actions/runs/1/artifacts/123",
  });
});

test("returns empty report URL when upload does not succeed", () => {
  for (const uploadOutcome of ["failure", "skipped", "cancelled", ""]) {
    const metadata = publishPullRequestAuditArtifactMetadata({
      uploadOutcome,
      artifactUrl: "https://github.com/SpamArtist/consumer/actions/runs/1/artifacts/123",
      artifactId: "123",
      artifactName: "SpamArtist-consumer-pr-735-11111111-html",
      repository: "SpamArtist/consumer",
      pullRequestNumber: 735,
      headSha: HEAD_SHA,
      reportFormat: "html",
    });
    assert.equal(metadata.reportUrl, "", uploadOutcome);
    assert.equal(metadata.artifactId, "", uploadOutcome);
    assert.equal(metadata.metadataJson, "", uploadOutcome);
    assert.match(metadata.code, /^report-[a-z-]+$/, uploadOutcome);
  }
});

test("builds safe workflow warnings with ASD Simplified Technical English", () => {
  const warning = buildSafeWorkflowWarning(
    "report-upload-failed",
    "Pull Request Audit Artifact upload failed.",
  );

  assert.equal(
    warning,
    "::warning::DocX Pull Request Audit stopped: report-upload-failed. Pull Request Audit Artifact upload failed.",
  );
  assert.throws(
    () => buildSafeWorkflowWarning("bad code", "Bad code."),
    /Safe failure code is invalid/,
  );
});

test("writes one DocX Execution Receipt with exact process exit code", () => {
  const receipt = buildDocXExecutionReceipt({
    consumerRepository: "SpamArtist/consumer",
    workflowRunId: "123456789",
    requestedDocxVersion: "1.2.3",
    docxExitCode: "3",
  });

  assert.deepEqual(receipt, {
    consumer_repository: "SpamArtist/consumer",
    workflow_run_id: "123456789",
    requested_docx_version: "1.2.3",
    docx_exit_code: 3,
  });

  const receiptPath = join(fixtureRoot(), "docx-execution-receipt.json");
  const command = runGuardCommand("write-execution-receipt", {
    DOCX_EXECUTION_RECEIPT_PATH: receiptPath,
    CONSUMER_REPOSITORY: "SpamArtist/consumer",
    WORKFLOW_RUN_ID: "123456789",
    DOCX_VERSION: "1.2.3",
    DOCX_EXIT_CODE: "2",
  });
  assert.equal(command.status, 0);
  assert.match(command.outputs, /^docx_exit_code=2$/m);
  assert.deepEqual(JSON.parse(readFileSync(receiptPath, "utf8")), {
    consumer_repository: "SpamArtist/consumer",
    workflow_run_id: "123456789",
    requested_docx_version: "1.2.3",
    docx_exit_code: 2,
  });
});

test("marked test secrets and restricted values stay out of unsafe surfaces", async () => {
  const request = runGuardCommand("validate-request", {
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_EVENT_ACTION: "opened",
    GITHUB_ACTOR: "alice",
    GH_TOKEN: MARKED_TEST_SECRET,
    DOCX_EVENT_JSON: JSON.stringify(pullRequestEvent({
      extra: {
        header: MARKED_RESTRICTED_VALUES[1],
        body: MARKED_RESTRICTED_VALUES[2],
        signedUrl: MARKED_RESTRICTED_VALUES[3],
        envDump: MARKED_RESTRICTED_VALUES[5],
        config: MARKED_RESTRICTED_VALUES[7],
      },
    })),
    DOCX_VERSION: "1.2.3",
    REPORT_FORMAT: "html",
  });
  assert.equal(request.status, 0);

  const privateTemp = fixtureRoot();
  const reportDir = join(privateTemp, "docx-pull-request-audit-report");
  mkdirSync(reportDir);
  const reportPath = join(reportDir, "report.html");
  writeFileSync(reportPath, `<html>${MARKED_RESTRICTED_VALUES[6]}</html>`);
  const report = runGuardCommand("validate-report", {
    RUNNER_TEMP: privateTemp,
    REPORT_DIR: reportDir,
    REPORT_PATH: reportPath,
    REPORT_FORMAT: "html",
    GH_TOKEN: MARKED_TEST_SECRET,
    DOCX_TEST_HEADER: MARKED_RESTRICTED_VALUES[1],
    DOCX_TEST_API_BODY: MARKED_RESTRICTED_VALUES[2],
    DOCX_TEST_SIGNED_URL: MARKED_RESTRICTED_VALUES[3],
    DOCX_TEST_ENV_DUMP: MARKED_RESTRICTED_VALUES[5],
    DOCX_TEST_CONFIG: MARKED_RESTRICTED_VALUES[7],
  });
  assert.equal(report.status, 0);
  const warning = runGuardCommand("validate-bundle", {
    ARTIFACT_ROOT: fixtureRoot(),
    BUNDLE_PATH: "missing.zip",
    GH_TOKEN: MARKED_TEST_SECRET,
    DOCX_TEST_HEADER: MARKED_RESTRICTED_VALUES[1],
    DOCX_TEST_API_BODY: MARKED_RESTRICTED_VALUES[2],
    DOCX_TEST_SIGNED_URL: MARKED_RESTRICTED_VALUES[3],
    DOCX_TEST_DIGEST: MARKED_RESTRICTED_VALUES[4],
    DOCX_TEST_ENV_DUMP: MARKED_RESTRICTED_VALUES[5],
    DOCX_TEST_CONFIG: MARKED_RESTRICTED_VALUES[7],
  });
  assert.equal(warning.status, 0);

  const binaryFixture = binaryReleaseFixture("1.2.3");
  const binaryRecordPath = join(binaryFixture.root, "records", "binary-download-record.json");
  const binaryStatePath = join(binaryFixture.root, "state.json");
  await verifyPrebuiltBinaryAttempt({
    token: MARKED_TEST_SECRET,
    version: "1.2.3",
    downloadDir: join(binaryFixture.root, "download"),
    statePath: binaryStatePath,
    recordPath: binaryRecordPath,
    consumerRepository: "SpamArtist/consumer",
    workflowRunId: "123456789",
    workflowRunAttempt: "1",
    commitSha: HEAD_SHA,
    time: RECORD_TIME,
  }, new FakeReleaseClient(binaryFixture));

  const record = buildBinaryDownloadRecord({
    consumerRepository: "SpamArtist/consumer",
    workflowRunId: "123456789",
    workflowRunAttempt: "1",
    commitSha: HEAD_SHA,
    docxVersion: "1.2.3",
    releaseTag: "v1.2.3",
    assetName: "DocX-v1.2.3-x86_64-unknown-linux-gnu.tar.gz",
    time: RECORD_TIME,
    result: "verified",
    safeFailureCode: "",
    verifiedArchiveDigest: sha256String("allowed archive digest"),
  });
  const receipt = buildDocXExecutionReceipt({
    consumerRepository: "SpamArtist/consumer",
    workflowRunId: "123456789",
    requestedDocxVersion: "1.2.3",
    docxExitCode: "0",
  });
  const comment = buildPullRequestAuditCommentBody(commentInput());
  const metadata = publishPullRequestAuditArtifactMetadata({
    uploadOutcome: "success",
    artifactUrl: "https://github.com/SpamArtist/consumer/actions/runs/1/artifacts/123",
    artifactId: "123",
    artifactName: "SpamArtist-consumer-pr-735-11111111-html",
    repository: "SpamArtist/consumer",
    pullRequestNumber: 735,
    headSha: HEAD_SHA,
    reportFormat: "html",
  });

  assertNoMarkedValues("request command", `${request.stdout}\n${request.stderr}\n${request.outputs}`);
  assertNoMarkedValues("report validation command", `${report.stdout}\n${report.stderr}\n${report.outputs}`);
  assertNoMarkedValues("warning command", `${warning.stdout}\n${warning.stderr}\n${warning.outputs}`);
  assertNoMarkedValues("record artifact", JSON.stringify(record));
  assertNoMarkedValues("binary record artifact", readFileSync(binaryRecordPath, "utf8"));
  assertNoMarkedValues("verification cache", readFileSync(binaryStatePath, "utf8"));
  assertNoMarkedValues("receipt", JSON.stringify(receipt));
  assertNoMarkedValues("comment", comment);
  assertNoMarkedValues("artifact metadata", metadata.metadataJson);
  assertNoMarkedValues("report", "<html>DocX report</html>");
});

test("removes partial report only inside private temporary storage", () => {
  const privateTemp = fixtureRoot();
  const reportDir = join(privateTemp, "docx-pull-request-audit-report");
  mkdirSync(reportDir);
  writeFileSync(join(reportDir, "report.html"), "<html>partial</html>");

  const result = removePartialPullRequestAuditReport({
    privateTempDir: privateTemp,
    reportDir,
  });

  assert.equal(result.removed, true);
  assert.equal(result.code, "partial-report-removed");
  assert.equal(existsSync(reportDir), false);

  const outside = fixtureRoot();
  const outsideReportDir = join(outside, "docx-pull-request-audit-report");
  mkdirSync(outsideReportDir);
  writeFileSync(join(outsideReportDir, "report.html"), "<html>partial</html>");
  const outsideResult = removePartialPullRequestAuditReport({
    privateTempDir: privateTemp,
    reportDir: outsideReportDir,
  });

  assert.equal(outsideResult.removed, false);
  assert.equal(outsideResult.code, "partial-report-outside-temp");
  assert.equal(existsSync(outsideReportDir), true);
});

test("builds marked Pull Request Audit comment with exact audit identity", () => {
  const body = buildPullRequestAuditCommentBody({
    docxVersion: "1.2.3",
    auditedSha: HEAD_SHA,
    reportFormat: "json",
    reportUrl: "https://github.com/SpamArtist/consumer/actions/runs/1/artifacts/123",
  });

  assert.match(body, new RegExp(DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER));
  assert.match(body, /DocX version \| `1\.2\.3`/);
  assert.match(body, new RegExp(`Audited commit SHA \\| \`${HEAD_SHA}\``));
  assert.match(body, /Report format \| `json`/);
  assert.match(body, /https:\/\/github\.com\/SpamArtist\/consumer\/actions\/runs\/1\/artifacts\/123/);
});

test("updates only marked comments owned by github-actions bot", async () => {
  const client = new FakePullRequestAuditClient({
    currentHeadSha: HEAD_SHA,
    comments: [
      {
        id: 10,
        body: `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nuser copy`,
        user: { login: "alice" },
      },
      {
        id: 20,
        body: `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nold`,
        user: { login: "github-actions[bot]" },
      },
    ],
  });

  const result = await updatePullRequestAuditComment(commentInput(), client);

  assert.equal(result.updated, true);
  assert.equal(result.code, "updated");
  assert.deepEqual(client.updatedCommentIds, ["20"]);
  assert.deepEqual(client.createdComments, []);
  assert.equal(client.comments.find((comment) => comment.id === 10).body, `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nuser copy`);
  assert.match(client.comments.find((comment) => comment.id === 20).body, /Report format \| `html`/);
});

test("creates first marked comment only after report upload output exists", async () => {
  const client = new FakePullRequestAuditClient({ currentHeadSha: HEAD_SHA, comments: [] });

  const result = await updatePullRequestAuditComment(commentInput(), client);

  assert.equal(result.updated, true);
  assert.equal(result.code, "created");
  assert.equal(client.createdComments.length, 1);
  assert.match(client.createdComments[0].body, new RegExp(DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER));
});

test("does not replace current comment when audited SHA is older than pull request head", async () => {
  const client = new FakePullRequestAuditClient({
    currentHeadSha: NEXT_HEAD_SHA,
    comments: [
      {
        id: 20,
        body: `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nprevious link`,
        user: { login: "github-actions[bot]" },
      },
    ],
  });

  const result = await updatePullRequestAuditComment(commentInput({ auditedSha: HEAD_SHA }), client);

  assert.equal(result.updated, false);
  assert.equal(result.code, "stale-head");
  assert.deepEqual(client.updatedCommentIds, []);
  assert.equal(client.comments[0].body, `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nprevious link`);
});

test("race keeps current commit link when two audits finish out of order", async () => {
  const client = new FakePullRequestAuditClient({ currentHeadSha: NEXT_HEAD_SHA, comments: [] });

  const oldRun = await updatePullRequestAuditComment(commentInput({ auditedSha: HEAD_SHA }), client);
  const currentRun = await updatePullRequestAuditComment(commentInput({
    auditedSha: NEXT_HEAD_SHA,
    reportUrl: "https://github.com/SpamArtist/consumer/actions/runs/2/artifacts/222",
  }), client);

  assert.equal(oldRun.updated, false);
  assert.equal(currentRun.updated, true);
  assert.equal(client.comments.length, 1);
  assert.match(client.comments[0].body, new RegExp(NEXT_HEAD_SHA));
  assert.doesNotMatch(client.comments[0].body, new RegExp(HEAD_SHA));
});

test("removes duplicate marked bot comments after primary update succeeds", async () => {
  const client = new FakePullRequestAuditClient({
    currentHeadSha: HEAD_SHA,
    comments: [
      { id: 30, body: `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nthird`, user: { login: "github-actions[bot]" } },
      { id: 20, body: `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nsecond`, user: { login: "github-actions[bot]" } },
    ],
  });

  const result = await updatePullRequestAuditComment(commentInput(), client);

  assert.equal(result.updated, true);
  assert.equal(result.duplicateCommentCount, 1);
  assert.deepEqual(client.updatedCommentIds, ["20"]);
  assert.deepEqual(client.deletedCommentIds, ["30"]);
  assert.deepEqual(client.comments.map((comment) => comment.id), [20]);
});

test("comment update failure leaves previous successful link unchanged", async () => {
  const previous = `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}\nprevious link`;
  const client = new FakePullRequestAuditClient({
    currentHeadSha: HEAD_SHA,
    comments: [
      { id: 20, body: previous, user: { login: "github-actions[bot]" } },
    ],
    failUpdate: true,
  });

  await assert.rejects(updatePullRequestAuditComment(commentInput(), client), /comment update failed/);
  assert.equal(client.comments[0].body, previous);
});

test("comment command contains update failure and writes safe outputs", () => {
  assertCommandContainsFailure("update-comment", "comment-update-failed");
});

test("deletes only older artifacts with the same report identity", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      { id: 100, name: "SpamArtist-consumer-pr-736-11111111-html" },
      { id: 101, name: "SpamArtist-consumer-pr-736-11111111-html" },
      { id: 102, name: "SpamArtist-consumer-pr-736-22222222-html" },
    ],
  });

  const result = await deleteOlderPullRequestAuditArtifacts({
    repository: "SpamArtist/consumer",
    artifactName: "SpamArtist-consumer-pr-736-11111111-html",
    currentArtifactId: "101",
  }, client);

  assert.equal(result.deleted, 1);
  assert.deepEqual(client.deletedArtifactIds, ["100"]);
  assert.deepEqual(client.artifacts.map((artifact) => artifact.id), [101, 102]);
});

test("artifact cleanup failure keeps current and older artifacts for a later run", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      { id: 100, name: "SpamArtist-consumer-pr-736-11111111-html" },
      { id: 101, name: "SpamArtist-consumer-pr-736-11111111-html" },
    ],
    failDeleteArtifact: true,
  });

  await assert.rejects(
    deleteOlderPullRequestAuditArtifacts({
      repository: "SpamArtist/consumer",
      artifactName: "SpamArtist-consumer-pr-736-11111111-html",
      currentArtifactId: "101",
    }, client),
    /artifact delete failed/,
  );
  assert.deepEqual(client.deletedArtifactIds, []);
  assert.deepEqual(client.artifacts.map((artifact) => artifact.id), [100, 101]);
});

test("guard command failure injection returns safe outputs and workflow warnings", () => {
  const bundleRoot = fixtureRoot();
  const invalidInputResult = runGuardCommand("validate-request", {
    GITHUB_EVENT_NAME: "pull_request",
    GITHUB_EVENT_ACTION: "opened",
    GITHUB_ACTOR: "alice",
    DOCX_EVENT_JSON: JSON.stringify(pullRequestEvent()),
    DOCX_VERSION: "v1.2.3",
    REPORT_FORMAT: "html",
  });
  assert.equal(invalidInputResult.status, 0);
  assert.match(invalidInputResult.stdout, /::warning::DocX Pull Request Audit stopped: invalid-docx-version\./);
  assert.match(invalidInputResult.outputs, /^should_run=false$/m);
  assert.match(invalidInputResult.outputs, /^code=invalid-docx-version$/m);

  const bundleResult = runGuardCommand("validate-bundle", {
    ARTIFACT_ROOT: bundleRoot,
    BUNDLE_PATH: "missing.zip",
  });
  assert.equal(bundleResult.status, 0);
  assert.match(bundleResult.stdout, /::warning::DocX Pull Request Audit stopped: missing-path\./);
  assert.match(bundleResult.outputs, /^accepted=false$/m);
  assert.match(bundleResult.outputs, /^code=missing-path$/m);

  const binaryResult = runGuardCommand("download-binary", {
    DOCX_VERSION: "1.2.3",
    BINARY_DOWNLOAD_DIR: join(bundleRoot, "binary"),
    BINARY_VERIFICATION_STATE: join(bundleRoot, "state.json"),
    GH_TOKEN: "",
  });
  assert.equal(binaryResult.status, 0);
  assert.match(binaryResult.stdout, /missing-token\. Binary Download Token is missing\. No fallback was used\./);
  assert.match(binaryResult.outputs, /^verified=false$/m);
  assert.match(binaryResult.outputs, /^code=missing-token$/m);

  const uploadResult = runGuardCommand("publish-report-output", {
    UPLOAD_OUTCOME: "failure",
    UPLOAD_ARTIFACT_URL: "",
    UPLOAD_ARTIFACT_ID: "",
    ARTIFACT_NAME: "SpamArtist-consumer-pr-736-11111111-html",
    REPOSITORY: "SpamArtist/consumer",
    PULL_REQUEST_NUMBER: "736",
    HEAD_SHA,
    REPORT_FORMAT: "html",
  });
  assert.equal(uploadResult.status, 0);
  assert.match(uploadResult.stdout, /::warning::DocX Pull Request Audit stopped: report-upload-failed\./);
  assert.match(uploadResult.outputs, /^report_url=$/m);
  assert.match(uploadResult.outputs, /^artifact_id=$/m);
});

test("parses maintenance artifact names only for current repository", () => {
  const accepted = parsePullRequestAuditArtifactName({
    repository: "SpamArtist/consumer",
    artifactName: "SpamArtist-consumer-pr-739-11111111-html",
  });
  assert.equal(accepted.accepted, true);
  assert.equal(accepted.pullRequestNumber, 739);
  assert.equal(accepted.shortSha, "11111111");
  assert.equal(accepted.reportFormat, "html");

  const rejected = parsePullRequestAuditArtifactName({
    repository: "Other/consumer",
    artifactName: "SpamArtist-consumer-pr-739-11111111-html",
  });
  assert.equal(rejected.accepted, false);
  assert.equal(rejected.code, "invalid-artifact-name");
});

test("validates maintenance identity before refresh or delete", () => {
  const identity = validateMaintenanceArtifactIdentity({
    repository: "SpamArtist/consumer",
    artifact: maintenanceArtifact(),
    workflowRun: maintenanceWorkflowRun(),
    pullRequest: maintenancePullRequest(),
  });

  assert.equal(identity.accepted, true);
  assert.equal(identity.artifactId, "300");
  assert.equal(identity.producingWorkflowRunId, "900");
  assert.equal(identity.pullRequestNumber, 739);
  assert.equal(identity.auditedSha, HEAD_SHA);
  assert.equal(identity.isCurrentReport, true);

  const mismatch = validateMaintenanceArtifactIdentity({
    repository: "SpamArtist/consumer",
    artifact: maintenanceArtifact(),
    workflowRun: maintenanceWorkflowRun({ headSha: NEXT_HEAD_SHA }),
    pullRequest: maintenancePullRequest(),
  });
  assert.equal(mismatch.accepted, false);
  assert.equal(mismatch.code, "artifact-head-mismatch");
});

test("controlled time refreshes at seven days or less before expiry", () => {
  const now = "2026-08-09T00:00:00.000Z";
  assert.equal(
    shouldRefreshPullRequestAuditArtifact({
      now,
      expiresAt: "2026-08-16T00:00:00.000Z",
    }),
    true,
  );
  assert.equal(
    shouldRefreshPullRequestAuditArtifact({
      now,
      expiresAt: "2026-08-16T00:00:01.000Z",
    }),
    false,
  );
});

test("merged lifecycle deletes non-final reports and retains final report for 30 complete days", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      maintenanceArtifact({ id: 300, expiresAt: "2026-09-20T00:00:00.000Z" }),
      maintenanceArtifact({
        id: 301,
        name: "SpamArtist-consumer-pr-739-22222222-html",
        workflowRunId: 901,
        expiresAt: "2026-09-20T00:00:00.000Z",
      }),
    ],
    workflowRuns: {
      900: maintenanceWorkflowRun({ headSha: HEAD_SHA }),
      901: maintenanceWorkflowRun({ id: 901, headSha: NEXT_HEAD_SHA }),
    },
    pullRequests: {
      739: maintenancePullRequest({
        state: "closed",
        headSha: NEXT_HEAD_SHA,
        merged: true,
        mergedAt: "2026-08-09T00:00:00.000Z",
        closedAt: "2026-08-09T00:05:00.000Z",
      }),
    },
  });

  const beforeBoundary = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-09-07T23:59:59.000Z",
  }, client);

  assert.deepEqual(
    beforeBoundary.items.map((item) => [item.old_artifact_id, item.operation, item.lifecycle]),
    [["300", "delete", "merged-non-final"]],
  );
  assert.equal(beforeBoundary.items[0].audited_sha, HEAD_SHA);

  const atBoundary = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-09-08T00:00:00.000Z",
  }, client);
  assert.deepEqual(
    atBoundary.items.map((item) => [item.old_artifact_id, item.operation, item.lifecycle]),
    [
      ["300", "delete", "merged-non-final"],
      ["301", "delete", "merged-final-expired"],
    ],
  );
});

test("missing final report is not replaced by an older merged report", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      maintenanceArtifact({ id: 300, expiresAt: "2026-08-12T00:00:00.000Z" }),
    ],
    workflowRuns: {
      900: maintenanceWorkflowRun({ headSha: HEAD_SHA }),
    },
    pullRequests: {
      739: maintenancePullRequest({
        state: "closed",
        headSha: NEXT_HEAD_SHA,
        merged: true,
        mergedAt: "2026-08-09T00:00:00.000Z",
      }),
    },
  });

  const result = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-08-10T00:00:00.000Z",
  }, client);

  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].operation, "delete");
  assert.equal(result.items[0].lifecycle, "merged-non-final");
  assert.equal(result.items[0].audited_sha, HEAD_SHA);
});

test("unmerged close keeps all reports for 30 complete days and then deletes them", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      maintenanceArtifact({ id: 300, expiresAt: "2026-09-20T00:00:00.000Z" }),
      maintenanceArtifact({
        id: 301,
        name: "SpamArtist-consumer-pr-739-22222222-json",
        workflowRunId: 901,
        expiresAt: "2026-09-20T00:00:00.000Z",
      }),
    ],
    workflowRuns: {
      900: maintenanceWorkflowRun({ headSha: HEAD_SHA }),
      901: maintenanceWorkflowRun({ id: 901, headSha: NEXT_HEAD_SHA }),
    },
    pullRequests: {
      739: maintenancePullRequest({
        state: "closed",
        headSha: NEXT_HEAD_SHA,
        closedAt: "2026-08-09T00:00:00.000Z",
      }),
    },
  });

  const beforeBoundary = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-09-07T23:59:59.000Z",
  }, client);
  assert.equal(beforeBoundary.items.length, 0);

  const atBoundary = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-09-08T00:00:00.000Z",
  }, client);
  assert.deepEqual(
    atBoundary.items.map((item) => [item.old_artifact_id, item.operation, item.lifecycle]),
    [
      ["300", "delete", "closed-expired"],
      ["301", "delete", "closed-expired"],
    ],
  );
});

test("closed report refresh preserves artifact until required deletion time", () => {
  const pullRequest = maintenancePullRequest({
    state: "closed",
    headSha: HEAD_SHA,
    closedAt: "2026-08-09T00:00:00.000Z",
  });

  const refresh = planMaintenanceAction({
    now: "2026-08-25T00:00:00.000Z",
    expiresAt: "2026-08-27T00:00:00.000Z",
    pullRequest,
    auditedSha: HEAD_SHA,
  });
  assert.equal(refresh.operation, "refresh");
  assert.equal(refresh.lifecycle, "closed-retained");

  const keep = planMaintenanceAction({
    now: "2026-08-25T00:00:00.000Z",
    expiresAt: "2026-09-20T00:00:00.000Z",
    pullRequest,
    auditedSha: HEAD_SHA,
  });
  assert.equal(keep.operation, "keep");
  assert.equal(keep.lifecycle, "closed-retained");
});

test("reopened pull request returns surviving reports to open lifecycle", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      maintenanceArtifact({ id: 300, expiresAt: "2026-08-16T00:00:00.000Z" }),
    ],
    workflowRuns: {
      900: maintenanceWorkflowRun({ headSha: HEAD_SHA }),
    },
    pullRequests: {
      739: maintenancePullRequest({
        state: "open",
        headSha: NEXT_HEAD_SHA,
        closedAt: "2026-08-01T00:00:00.000Z",
      }),
    },
  });

  const result = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-08-09T00:00:00.000Z",
  }, client);

  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].operation, "refresh");
  assert.equal(result.items[0].lifecycle, "open");
  assert.equal(result.items[0].is_current_report, false);
});

test("later close after reopen uses new closed time", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      maintenanceArtifact({ id: 300, expiresAt: "2026-10-01T00:00:00.000Z" }),
    ],
    workflowRuns: {
      900: maintenanceWorkflowRun({ headSha: HEAD_SHA }),
    },
    pullRequests: {
      739: maintenancePullRequest({
        state: "closed",
        headSha: HEAD_SHA,
        closedAt: "2026-08-20T00:00:00.000Z",
      }),
    },
  });

  const beforeNewBoundary = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-09-18T23:59:59.000Z",
  }, client);
  assert.equal(beforeNewBoundary.items.length, 0);

  const atNewBoundary = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-09-19T00:00:00.000Z",
  }, client);
  assert.equal(atNewBoundary.items.length, 1);
  assert.equal(atNewBoundary.items[0].operation, "delete");
  assert.equal(atNewBoundary.items[0].lifecycle, "closed-expired");
});

test("maintenance upload validates replacement before old artifact deletion", () => {
  const accepted = validateMaintenanceUpload({
    uploadOutcome: "success",
    oldArtifactId: "300",
    newArtifactId: "301",
    artifactName: "SpamArtist-consumer-pr-739-11111111-html",
    artifactUrl: "https://github.com/SpamArtist/consumer/actions/runs/2/artifacts/301",
  });

  assert.equal(accepted.accepted, true);
  assert.equal(
    shouldDeleteOldMaintenanceArtifact({
      operation: "refresh",
      uploadAccepted: true,
      isCurrentReport: true,
      commentUpdated: true,
    }),
    true,
  );
  assert.equal(
    shouldDeleteOldMaintenanceArtifact({
      operation: "refresh",
      uploadAccepted: true,
      isCurrentReport: true,
      commentUpdated: false,
    }),
    false,
  );
  assert.equal(
    shouldDeleteOldMaintenanceArtifact({
      operation: "refresh",
      uploadAccepted: true,
      isCurrentReport: false,
      commentUpdated: false,
    }),
    true,
  );

  const failedUpload = validateMaintenanceUpload({
    uploadOutcome: "failure",
    oldArtifactId: "300",
    newArtifactId: "301",
    artifactName: "SpamArtist-consumer-pr-739-11111111-html",
    artifactUrl: "https://github.com/SpamArtist/consumer/actions/runs/2/artifacts/301",
  });
  assert.equal(failedUpload.accepted, false);
  assert.equal(shouldDeleteOldMaintenanceArtifact({ uploadAccepted: false }), false);
  assert.equal(shouldDeleteOldMaintenanceArtifact({ operation: "delete" }), true);
});

test("maintenance comment refresh updates marked current comment only after replacement URL", async () => {
  const client = new FakePullRequestAuditClient({
    currentHeadSha: HEAD_SHA,
    comments: [
      {
        id: 20,
        body: buildPullRequestAuditCommentBody(commentInput()),
        user: { login: "github-actions[bot]" },
      },
    ],
  });

  const result = await refreshCurrentPullRequestAuditComment({
    repository: "SpamArtist/consumer",
    pullRequestNumber: 739,
    auditedSha: HEAD_SHA,
    reportFormat: "html",
    reportUrl: "https://github.com/SpamArtist/consumer/actions/runs/2/artifacts/301",
  }, client);

  assert.equal(result.updated, true);
  assert.match(client.comments[0].body, /artifacts\/301/);
  assert.match(client.comments[0].body, /DocX version \| `1\.2\.3`/);
});

test("maintenance item planning isolates failures and continues", async () => {
  const client = new FakePullRequestAuditClient({
    artifacts: [
      maintenanceArtifact({ id: 300, expiresAt: "2026-08-16T00:00:00.000Z" }),
      maintenanceArtifact({
        id: 301,
        name: "SpamArtist-consumer-pr-739-22222222-html",
        expiresAt: "2026-08-16T00:00:00.000Z",
      }),
      maintenanceArtifact({
        id: 302,
        name: "SpamArtist-consumer-pr-739-11111111-json",
        expiresAt: "2026-08-20T00:00:01.000Z",
      }),
    ],
    workflowRuns: {
      900: maintenanceWorkflowRun(),
    },
    pullRequests: {
      739: maintenancePullRequest(),
    },
  });

  const result = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-08-09T00:00:00.000Z",
  }, client);

  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].old_artifact_id, "300");
  assert.equal(result.failures.length, 1);
  assert.equal(result.failures[0].artifact_id, "301");
});

test("maintenance uses only current repository for list, refresh, comment, and delete work", async () => {
  const client = new FakePullRequestAuditClient({
    currentHeadSha: HEAD_SHA,
    comments: [
      {
        id: 20,
        body: buildPullRequestAuditCommentBody(commentInput()),
        user: { login: "github-actions[bot]" },
      },
    ],
    artifacts: [
      maintenanceArtifact({ id: 300, expiresAt: "2026-08-16T00:00:00.000Z" }),
      {
        ...maintenanceArtifact({ id: 301, expiresAt: "2026-08-16T00:00:00.000Z" }),
        name: "Other-consumer-pr-739-11111111-html",
      },
    ],
    workflowRuns: {
      900: maintenanceWorkflowRun(),
    },
    pullRequests: {
      739: maintenancePullRequest(),
    },
  });

  const result = await planPullRequestAuditMaintenance({
    repository: "SpamArtist/consumer",
    now: "2026-08-09T00:00:00.000Z",
  }, client);
  await refreshCurrentPullRequestAuditComment({
    repository: "SpamArtist/consumer",
    pullRequestNumber: 739,
    auditedSha: HEAD_SHA,
    reportFormat: "html",
    reportUrl: "https://github.com/SpamArtist/consumer/actions/runs/2/artifacts/301",
  }, client);
  await client.deleteArtifact("SpamArtist/consumer", "300");

  assert.equal(result.items.length, 1);
  assert.equal(result.items[0].old_artifact_id, "300");
  assert(client.calledRepositories.length > 0);
  assert(client.calledRepositories.every((repository) => repository === "SpamArtist/consumer"));
  assert.deepEqual(client.deletedArtifactIds, ["300"]);
});

test("audit publication uses only selected Consumer Repository", async () => {
  const client = new FakePullRequestAuditClient({
    currentHeadSha: HEAD_SHA,
    comments: [
      {
        id: 20,
        body: buildPullRequestAuditCommentBody(commentInput()),
        user: { login: "github-actions[bot]" },
      },
    ],
    artifacts: [
      { id: 100, name: "SpamArtist-neutral-one-pr-736-11111111-html" },
      { id: 101, name: "SpamArtist-neutral-one-pr-736-11111111-html" },
      { id: 200, name: "SpamArtist-neutral-two-pr-736-11111111-html" },
    ],
  });

  await updatePullRequestAuditComment({
    ...commentInput({
      repository: "SpamArtist/neutral-one",
      reportUrl: "https://github.com/SpamArtist/neutral-one/actions/runs/1/artifacts/101",
    }),
  }, client);
  await deleteOlderPullRequestAuditArtifacts({
    repository: "SpamArtist/neutral-one",
    artifactName: "SpamArtist-neutral-one-pr-736-11111111-html",
    currentArtifactId: "101",
  }, client);

  assert(client.calledRepositories.length > 0);
  assert(client.calledRepositories.every((repository) => repository === "SpamArtist/neutral-one"));
  assert.deepEqual(client.deletedArtifactIds, ["100"]);
  assert.deepEqual(client.artifacts.map((artifact) => artifact.id), [101, 200]);
});

function pullRequestEvent(overrides = {}) {
  const headRepo = overrides.headRepo ?? "SpamArtist/consumer";
  const baseRepo = overrides.baseRepo ?? "SpamArtist/consumer";
  return {
    action: overrides.action ?? "opened",
    sender: { login: overrides.sender ?? "alice" },
    ...overrides.extra,
    pull_request: {
      draft: overrides.draft ?? false,
      user: { login: overrides.user ?? "alice" },
      head: {
        sha: overrides.headSha ?? HEAD_SHA,
        repo: { full_name: headRepo },
      },
      base: {
        ref: overrides.baseRef ?? "main",
        repo: { full_name: baseRepo },
      },
    },
  };
}

function binaryAttemptInput(fixture, overrides = {}) {
  return {
    token: "token",
    version: "1.2.3",
    downloadDir: join(fixture.root, "download"),
    statePath: join(fixture.root, "state.json"),
    recordPath: join(fixture.root, "binary-download-record.json"),
    consumerRepository: "SpamArtist/consumer",
    workflowRunId: "123456789",
    workflowRunAttempt: "1",
    commitSha: HEAD_SHA,
    time: RECORD_TIME,
    ...overrides,
  };
}

function assertNoMarkedValues(surface, value) {
  for (const marker of MARKED_RESTRICTED_VALUES) {
    assert.doesNotMatch(String(value), escapeRegExpString(marker), `${surface} leaked ${marker}`);
  }
}

function escapeRegExpString(value) {
  return new RegExp(String(value).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
}

function commentInput(overrides = {}) {
  return {
    repository: "SpamArtist/consumer",
    pullRequestNumber: 736,
    docxVersion: "1.2.3",
    auditedSha: HEAD_SHA,
    reportFormat: "html",
    reportUrl: "https://github.com/SpamArtist/consumer/actions/runs/1/artifacts/123",
    ...overrides,
  };
}

function maintenanceArtifact(overrides = {}) {
  return {
    id: overrides.id ?? 300,
    name: overrides.name ?? "SpamArtist-consumer-pr-739-11111111-html",
    expires_at: overrides.expiresAt ?? "2026-08-16T00:00:00.000Z",
    workflow_run: { id: overrides.workflowRunId ?? 900 },
  };
}

function maintenanceWorkflowRun(overrides = {}) {
  return {
    id: overrides.id ?? 900,
    event: overrides.event ?? "pull_request",
    head_sha: overrides.headSha ?? HEAD_SHA,
    pull_requests: overrides.pullRequests ?? [{ number: 739 }],
  };
}

function maintenancePullRequest(overrides = {}) {
  return {
    number: overrides.number ?? 739,
    state: overrides.state ?? "open",
    merged: overrides.merged ?? false,
    merged_at: overrides.mergedAt ?? null,
    closed_at: overrides.closedAt ?? null,
    head: { sha: overrides.headSha ?? HEAD_SHA },
  };
}

function fixtureRoot() {
  return mkdtempSync(join(tmpdir(), "docx-audit-guard-"));
}

function assertAcceptedBundle(root, bundlePath, kind) {
  const result = validateBundlePath({ artifactRoot: root, bundlePath });
  assert.equal(result.accepted, true, bundlePath);
  assert.equal(result.kind, kind, bundlePath);
}

function assertCommandContainsFailure(command, code) {
  const source = readFileSync(GUARD_SCRIPT_PATH, "utf8");
  const commandStart = source.indexOf(`if (command === "${command}")`);
  assert.notEqual(commandStart, -1, command);
  const commandRest = source.slice(commandStart);
  const nextCommand = commandRest.indexOf("\n  if (command === ", 1);
  const commandBlock = nextCommand === -1 ? commandRest : commandRest.slice(0, nextCommand);

  assert.match(commandBlock, new RegExp(`code: "${code}"`));
  assert.match(commandBlock, new RegExp(`writeGitHubWarning\\("${code}"`));
  assert.doesNotMatch(commandBlock, /throw error/);
}

function runGuardCommand(command, env) {
  const outputPath = join(fixtureRoot(), "github-output");
  const result = spawnSync(process.execPath, [GUARD_SCRIPT_PATH, command], {
    encoding: "utf8",
    env: {
      ...process.env,
      GITHUB_OUTPUT: outputPath,
      ...env,
    },
  });
  return {
    status: result.status,
    stdout: result.stdout,
    stderr: result.stderr,
    outputs: existsSync(outputPath) ? readFileSync(outputPath, "utf8") : "",
  };
}

function binaryReleaseFixture(version) {
  const root = mkdtempSync(join(tmpdir(), "docx-binary-release-"));
  const identity = deriveBinaryRelease(version);
  const packageRoot = join(root, identity.rootDirectory);
  mkdirSync(packageRoot, { recursive: true });
  const executablePath = join(packageRoot, identity.executableName);
  writeFileSync(executablePath, "#!/usr/bin/env sh\nexit 0\n");
  chmodSync(executablePath, 0o755);

  const archivePath = join(root, identity.archiveName);
  run("tar", ["-czf", archivePath, "-C", root, identity.rootDirectory]);
  const archiveSha256 = sha256File(archivePath);
  const executableSha256 = sha256File(executablePath);
  const manifest = {
    manifest_schema_version: "1",
    docx_version: version,
    source_commit: "1111111111111111111111111111111111111111",
    rust_target: "x86_64-unknown-linux-gnu",
    minimum_ubuntu_version: "22.04",
    archive_name: identity.archiveName,
    archive_sha256: archiveSha256,
    archive_root_directory: `${identity.rootDirectory}/`,
    executable_name: identity.executableName,
    executable_sha256: executableSha256,
    release_workflow_file: ".github/workflows/release.yml",
    release_workflow_commit: "1111111111111111111111111111111111111111",
    release_workflow_run_id: "123456789",
    build_time: "2026-08-09T00:00:00Z",
    approval_status: "approved",
    reviewer: "docx-release-owner",
    approval_time: "2026-08-09T01:02:03Z",
  };
  const manifestPath = join(root, identity.manifestName);
  writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  rmSync(packageRoot, { recursive: true, force: true });

  return {
    root,
    identity,
    archivePath,
    manifestPath,
    archiveSha256,
    manifestSha256: sha256File(manifestPath),
    executableSha256,
  };
}

class FakeReleaseClient {
  constructor(fixture, options = {}) {
    this.fixture = fixture;
    this.options = options;
    this.downloadedAssets = [];
    this.verifiedRelease = false;
    this.verifiedAssets = [];
  }

  async getRelease(repository, tag) {
    if (this.options.failure === "invalid-token") {
      throw new BinaryVerificationError("invalid-token", "Binary Download Token was rejected.");
    }
    if (this.options.missingRelease) {
      throw new BinaryVerificationError("missing-exact-release", "Exact immutable release is missing.");
    }
    const manifestDigest = this.options.wrongExecutableDigest
      ? sha256String(mutatedExecutableDigestManifest(this.fixture.manifestPath))
      : this.fixture.manifestSha256;
    return {
      tagName: tag,
      isDraft: false,
      isPrerelease: false,
      isImmutable: !this.options.mutableRelease,
      assets: [
        {
          name: this.fixture.identity.archiveName,
          digest: `sha256:${this.options.wrongArchiveDigest ? "0".repeat(64) : this.fixture.archiveSha256}`,
        },
        {
          name: this.fixture.identity.manifestName,
          digest: `sha256:${manifestDigest}`,
        },
      ],
    };
  }

  async downloadAsset(repository, tag, assetName, outputPath) {
    this.downloadedAssets.push(assetName);
    if (assetName === this.fixture.identity.archiveName) {
      copyFileSync(this.fixture.archivePath, outputPath);
      return;
    }
    if (this.options.wrongExecutableDigest) {
      writeFileSync(outputPath, mutatedExecutableDigestManifest(this.fixture.manifestPath));
      return;
    }
    copyFileSync(this.fixture.manifestPath, outputPath);
  }

  async verifyRelease(repository, tag) {
    if (this.options.failure === "wrong-release-attestation") {
      throw new BinaryVerificationError("wrong-release-attestation", "GitHub release attestation did not verify.");
    }
    this.verifiedRelease = true;
  }

  async verifyReleaseAsset(repository, tag, assetPath) {
    if (this.options.failure === "wrong-attestation") {
      throw new BinaryVerificationError("wrong-attestation", "GitHub release attestation did not verify.");
    }
    this.verifiedAssets.push(assetPath);
  }
}

class FakePullRequestAuditClient {
  constructor(options = {}) {
    this.currentHeadSha = options.currentHeadSha ?? HEAD_SHA;
    this.comments = (options.comments ?? []).map((comment) => ({ ...comment }));
    this.artifacts = (options.artifacts ?? []).map((artifact) => ({ ...artifact }));
    this.workflowRuns = options.workflowRuns ?? {};
    this.pullRequests = options.pullRequests ?? {};
    this.failUpdate = options.failUpdate ?? false;
    this.failDeleteArtifact = options.failDeleteArtifact ?? false;
    this.updatedCommentIds = [];
    this.createdComments = [];
    this.deletedCommentIds = [];
    this.deletedArtifactIds = [];
    this.calledRepositories = [];
    this.nextCommentId = 1000;
  }

  async getPullRequestHeadSha(repository) {
    this.calledRepositories.push(repository);
    return this.currentHeadSha;
  }

  async listIssueComments(repository) {
    this.calledRepositories.push(repository);
    return this.comments.map((comment) => ({ ...comment }));
  }

  async createIssueComment(repository, pullRequestNumber, body) {
    this.calledRepositories.push(repository);
    const comment = {
      id: this.nextCommentId++,
      body,
      user: { login: "github-actions[bot]" },
    };
    this.comments.push(comment);
    this.createdComments.push(comment);
    return { ...comment };
  }

  async updateIssueComment(repository, commentId, body) {
    this.calledRepositories.push(repository);
    if (this.failUpdate) {
      throw new Error("comment update failed");
    }
    const comment = this.comments.find((candidate) => String(candidate.id) === String(commentId));
    if (!comment) {
      throw new Error("comment missing");
    }
    comment.body = body;
    this.updatedCommentIds.push(String(commentId));
    return { ...comment };
  }

  async deleteIssueComment(repository, commentId) {
    this.calledRepositories.push(repository);
    this.comments = this.comments.filter((comment) => String(comment.id) !== String(commentId));
    this.deletedCommentIds.push(String(commentId));
  }

  async listArtifactsByName(repository, artifactName) {
    this.calledRepositories.push(repository);
    return this.artifacts.filter((artifact) => artifact.name === artifactName).map((artifact) => ({ ...artifact }));
  }

  async listArtifacts(repository) {
    this.calledRepositories.push(repository);
    return this.artifacts.map((artifact) => ({ ...artifact }));
  }

  async getWorkflowRun(repository, runId) {
    this.calledRepositories.push(repository);
    const run = this.workflowRuns[String(runId)];
    if (!run) {
      throw new Error("workflow run missing");
    }
    return { ...run };
  }

  async getPullRequest(repository, pullRequestNumber) {
    this.calledRepositories.push(repository);
    const pullRequest = this.pullRequests[String(pullRequestNumber)];
    if (!pullRequest) {
      throw new Error("pull request missing");
    }
    return { ...pullRequest, head: { ...(pullRequest.head ?? {}) } };
  }

  async deleteArtifact(repository, artifactId) {
    this.calledRepositories.push(repository);
    if (this.failDeleteArtifact) {
      throw new Error("artifact delete failed");
    }
    this.artifacts = this.artifacts.filter((artifact) => String(artifact.id) !== String(artifactId));
    this.deletedArtifactIds.push(String(artifactId));
  }
}

function sha256File(path) {
  const hash = createHash("sha256");
  hash.update(readFileSync(path));
  return hash.digest("hex");
}

function sha256String(value) {
  const hash = createHash("sha256");
  hash.update(value);
  return hash.digest("hex");
}

function mutatedExecutableDigestManifest(manifestPath) {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  manifest.executable_sha256 = "f".repeat(64);
  return `${JSON.stringify(manifest, null, 2)}\n`;
}

function run(command, args) {
  const result = spawnSync(command, args, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new Error(`${command} failed: ${result.stderr || result.stdout}`);
  }
}
