#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  appendFileSync,
  chmodSync,
  copyFileSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, extname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ACCEPTED_PULL_REQUEST_ACTIONS = new Set([
  "opened",
  "synchronize",
  "reopened",
  "ready_for_review",
]);
const SUPPORTED_REPORT_FORMATS = new Set(["html", "json"]);
const SUPPORTED_BUNDLE_EXTENSIONS = new Set([".zip", ".crx"]);
const QUIET_REQUEST_SKIP_CODES = new Set([
  "draft-pull-request",
  "fork-pull-request",
  "dependabot-pull-request",
  "non-main-base",
  "unsupported-action",
  "unsupported-event",
]);
export const DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER = "<!-- docx-pull-request-audit -->";
const GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]";
const MAINTENANCE_REFRESH_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
const CLOSED_PULL_REQUEST_RETENTION_MS = 30 * 24 * 60 * 60 * 1000;
const BINARY_CONTRACT = Object.freeze({
  repository: "SpamArtist/docx-binary-distribution",
  binName: "DocX",
  target: "x86_64-unknown-linux-gnu",
  minimumUbuntu: "22.04",
  manifestSchemaVersion: "1",
  releaseWorkflowFile: ".github/workflows/release.yml",
});
const REQUIRED_MANIFEST_FIELDS = [
  "manifest_schema_version",
  "docx_version",
  "source_commit",
  "rust_target",
  "minimum_ubuntu_version",
  "archive_name",
  "archive_sha256",
  "archive_root_directory",
  "executable_name",
  "executable_sha256",
  "release_workflow_file",
  "release_workflow_commit",
  "release_workflow_run_id",
  "build_time",
  "approval_status",
  "reviewer",
  "approval_time",
];

export function evaluateAuditRequest(input) {
  const event = input.event ?? {};
  const pullRequest = event.pull_request;
  const actor = input.actor ?? event.sender?.login ?? "";
  const action = input.action ?? event.action ?? "";
  const eventName = input.eventName ?? "";
  const docxVersion = input.docxVersion ?? "";
  const reportFormat = normalizeReportFormat(input.reportFormat);
  const checkedOutSha = input.checkedOutSha ?? "";

  const versionError = validateDocxVersion(docxVersion);
  if (versionError) {
    return skip("invalid-docx-version", versionError);
  }

  if (!SUPPORTED_REPORT_FORMATS.has(reportFormat)) {
    return skip("unsupported-report-format", "Report format must be html or json.");
  }

  if (eventName !== "pull_request") {
    return skip("unsupported-event", "Event must be pull_request.");
  }

  if (!ACCEPTED_PULL_REQUEST_ACTIONS.has(action)) {
    return skip("unsupported-action", "Pull request action is not accepted.");
  }

  if (!pullRequest) {
    return skip("missing-pull-request", "Pull request payload is missing.");
  }

  if (pullRequest.base?.ref !== "main") {
    return skip("non-main-base", "Pull request base branch must be main.");
  }

  if (pullRequest.draft === true) {
    return skip("draft-pull-request", "Draft pull request skipped.");
  }

  const headRepo = pullRequest.head?.repo?.full_name;
  const baseRepo = pullRequest.base?.repo?.full_name;
  if (!headRepo || !baseRepo || headRepo !== baseRepo) {
    return skip("fork-pull-request", "Fork pull request skipped.");
  }

  if (isDependabot(actor) || isDependabot(event.sender?.login) || isDependabot(pullRequest.user?.login)) {
    return skip("dependabot-pull-request", "Dependabot pull request skipped.");
  }

  const headSha = pullRequest.head?.sha ?? "";
  if (!isFullSha(headSha)) {
    return skip("missing-head-sha", "Pull request head SHA is missing.");
  }

  if (checkedOutSha && checkedOutSha !== headSha) {
    return skip("stale-head", "Checked-out commit is not current pull request head.");
  }

  return {
    shouldRun: true,
    shouldUseSecret: true,
    code: "accepted",
    message: "Pull request accepted.",
    headSha,
    reportFormat,
  };
}

export function validateBundlePath(input) {
  const artifactRoot = input.artifactRoot ?? "";
  const bundlePath = input.bundlePath ?? "";
  if (!bundlePath || bundlePath.trim() !== bundlePath) {
    return rejectBundle("missing-path", "Bundle path is missing.");
  }

  if (hasMultiplePathValues(bundlePath)) {
    return rejectBundle("multiple-paths", "Bundle path must identify one path.");
  }

  if (isAbsolute(bundlePath)) {
    return rejectBundle("absolute-path", "Bundle path must be relative.");
  }

  if (isUrl(bundlePath)) {
    return rejectBundle("url-path", "Bundle path must not be a URL.");
  }

  if (hasGlobSyntax(bundlePath)) {
    return rejectBundle("glob-path", "Bundle path must not use a glob.");
  }

  const segments = bundlePath.split(/[\\/]+/).filter(Boolean);
  if (segments.length === 0 || segments.includes("..")) {
    return rejectBundle("parent-path", "Bundle path must stay inside artifact root.");
  }

  const extension = extname(bundlePath).toLowerCase();
  if (extension === ".xpi") {
    return rejectBundle("xpi-not-supported", "XPI bundle files are not supported.");
  }

  if (!artifactRoot || !existsSync(artifactRoot)) {
    return rejectBundle("missing-artifact-root", "Extension Bundle Artifact root is missing.");
  }

  const rootRealPath = realpathSync(artifactRoot);
  const candidatePath = resolve(rootRealPath, bundlePath);
  if (!existsSync(candidatePath)) {
    return rejectBundle("missing-path", "Bundle path does not exist.");
  }

  const candidateRealPath = realpathSync(candidatePath);
  if (!isInsideRoot(rootRealPath, candidateRealPath)) {
    return rejectBundle("outside-root", "Bundle path resolves outside artifact root.");
  }

  if (lstatSync(candidatePath).isSymbolicLink()) {
    return rejectBundle("outside-root", "Bundle path must not be a link.");
  }

  const stats = statSync(candidateRealPath);
  if (stats.isDirectory()) {
    return acceptBundle(candidateRealPath, "directory");
  }

  if (stats.isFile() && SUPPORTED_BUNDLE_EXTENSIONS.has(extension)) {
    return acceptBundle(candidateRealPath, extension.slice(1));
  }

  return rejectBundle("unsupported-type", "Bundle path must be a directory, zip file, or crx file.");
}

export function validateArtifactHead(input) {
  const expectedHeadSha = input.expectedHeadSha ?? "";
  const artifactHeadSha = input.artifactHeadSha ?? "";
  if (!isFullSha(expectedHeadSha)) {
    return rejectArtifact("missing-head-sha", "Expected head SHA is missing.");
  }
  if (artifactHeadSha !== expectedHeadSha) {
    return rejectArtifact("artifact-head-mismatch", "Extension Bundle Artifact does not match head commit.");
  }
  return { accepted: true, code: "accepted", message: "Extension Bundle Artifact head accepted." };
}

export function deriveBinaryRelease(version) {
  const versionError = validateDocxVersion(version);
  if (versionError) {
    throw new BinaryVerificationError("invalid-docx-version", versionError);
  }
  const rootDirectory = `${BINARY_CONTRACT.binName}-v${version}-${BINARY_CONTRACT.target}`;
  return {
    repository: BINARY_CONTRACT.repository,
    tag: `v${version}`,
    rootDirectory,
    archiveName: `${rootDirectory}.tar.gz`,
    manifestName: `${rootDirectory}.manifest.json`,
    executableName: BINARY_CONTRACT.binName,
  };
}

export async function verifyPrebuiltBinary(input, client = new GhReleaseClient(input.token)) {
  const version = input.version ?? "";
  const downloadDir = input.downloadDir ?? "";
  const statePath = input.statePath ?? "";
  const releaseIdentity = deriveBinaryRelease(version);
  const repository = input.repository ?? releaseIdentity.repository;
  if (repository !== BINARY_CONTRACT.repository) {
    throw new BinaryVerificationError("invalid-binary-repository", "Binary Distribution Repository is fixed.");
  }
  if (!downloadDir) {
    throw new BinaryVerificationError("missing-download-dir", "Binary download directory is missing.");
  }
  if (!statePath) {
    throw new BinaryVerificationError("missing-state-path", "Binary verification state path is missing.");
  }

  rmSync(downloadDir, { recursive: true, force: true });
  mkdirSync(downloadDir, { recursive: true });

  const release = await client.getRelease(repository, releaseIdentity.tag);
  validateRelease(release, releaseIdentity);
  await client.verifyRelease(repository, releaseIdentity.tag);

  const archiveAsset = findRequiredAsset(release, releaseIdentity.archiveName);
  const manifestAsset = findRequiredAsset(release, releaseIdentity.manifestName);
  const archivePath = join(downloadDir, releaseIdentity.archiveName);
  const manifestPath = join(downloadDir, releaseIdentity.manifestName);
  await client.downloadAsset(repository, releaseIdentity.tag, releaseIdentity.archiveName, archivePath);
  await client.downloadAsset(repository, releaseIdentity.tag, releaseIdentity.manifestName, manifestPath);
  await client.verifyReleaseAsset(repository, releaseIdentity.tag, archivePath);
  await client.verifyReleaseAsset(repository, releaseIdentity.tag, manifestPath);

  const archiveDigest = sha256File(archivePath);
  if (typeof input.onArchiveDigest === "function") {
    input.onArchiveDigest(archiveDigest);
  }
  const manifestDigest = sha256File(manifestPath);
  assertDigestEqual(archiveDigest, assetDigest(archiveAsset), "archive GitHub metadata");
  assertDigestEqual(manifestDigest, assetDigest(manifestAsset), "manifest GitHub metadata");

  const manifest = parseManifest(manifestPath);
  validateManifest(manifest, releaseIdentity, version);
  assertDigestEqual(archiveDigest, manifest.archive_sha256, "archive manifest");

  const extractRoot = mkdtempSync(join(tmpdir(), "docx-binary-extract-"));
  try {
    validateArchiveEntries(archivePath, releaseIdentity);
    run("tar", ["-xzf", archivePath, "-C", extractRoot]);
    const executablePath = join(extractRoot, releaseIdentity.rootDirectory, releaseIdentity.executableName);
    if (!existsSync(executablePath) || !statSync(executablePath).isFile()) {
      throw new BinaryVerificationError("missing-executable", "Verified archive does not contain executable.");
    }
    chmodSync(executablePath, 0o755);
    const executableDigest = sha256File(executablePath);
    assertDigestEqual(executableDigest, manifest.executable_sha256, "executable manifest");
    writeVerificationState(statePath, {
      version,
      executable_path: executablePath,
      executable_sha256: executableDigest,
    });
    return {
      verified: true,
      code: "verified",
      message: "Prebuilt DocX Binary verified.",
      executablePath,
      statePath,
      verifiedArchiveDigest: archiveDigest,
    };
  } catch (error) {
    rmSync(extractRoot, { recursive: true, force: true });
    throw error;
  }
}

export async function verifyPrebuiltBinaryAttempt(input, client = new GhReleaseClient(input.token)) {
  const version = input.version ?? "";
  const identity = deriveBinaryRelease(version);
  let verifiedArchiveDigest = "";
  const startedAt = input.time ?? new Date().toISOString();
  try {
    const verification = await verifyPrebuiltBinary({
      ...input,
      onArchiveDigest: (digest) => {
        verifiedArchiveDigest = digest;
      },
    }, client);
    if (input.recordPath) {
      const record = buildBinaryDownloadRecord({
        consumerRepository: input.consumerRepository,
        workflowRunId: input.workflowRunId,
        workflowRunAttempt: input.workflowRunAttempt,
        commitSha: input.commitSha,
        docxVersion: version,
        releaseTag: identity.tag,
        assetName: identity.archiveName,
        time: startedAt,
        result: "verified",
        safeFailureCode: "",
        verifiedArchiveDigest: verification.verifiedArchiveDigest || verifiedArchiveDigest,
      });
      writeJsonRecord(input.recordPath, record);
    }
    return verification;
  } catch (error) {
    const code = error instanceof BinaryVerificationError ? error.code : "binary-verification-failed";
    if (input.recordPath) {
      const record = buildBinaryDownloadRecord({
        consumerRepository: input.consumerRepository,
        workflowRunId: input.workflowRunId,
        workflowRunAttempt: input.workflowRunAttempt,
        commitSha: input.commitSha,
        docxVersion: version,
        releaseTag: identity.tag,
        assetName: identity.archiveName,
        time: startedAt,
        result: "failed",
        safeFailureCode: code,
        verifiedArchiveDigest,
      });
      writeJsonRecord(input.recordPath, record);
    }
    throw error;
  }
}

export function confirmVerifiedExecutable(input) {
  const statePath = input.statePath ?? "";
  if (!statePath || !existsSync(statePath)) {
    throw new BinaryVerificationError("missing-verification-state", "Binary verification state is missing.");
  }
  const state = JSON.parse(readFileSync(statePath, "utf8"));
  if (typeof state.executable_path !== "string" || typeof state.executable_sha256 !== "string") {
    throw new BinaryVerificationError("invalid-verification-state", "Binary verification state is invalid.");
  }
  if (!existsSync(state.executable_path) || !statSync(state.executable_path).isFile()) {
    throw new BinaryVerificationError("missing-executable", "Verified executable is missing.");
  }
  assertDigestEqual(sha256File(state.executable_path), state.executable_sha256, "executable pre-run");
  return {
    executablePath: state.executable_path,
    version: state.version,
  };
}

export function buildPullRequestAuditArtifactName(input) {
  const repository = sanitizeArtifactNamePart(input.repository ?? "");
  const pullRequestNumber = String(input.pullRequestNumber ?? "");
  const headSha = input.headSha ?? "";
  const reportFormat = normalizeReportFormat(input.reportFormat);

  if (!repository) {
    throw new Error("Repository is missing.");
  }
  if (!/^[1-9]\d*$/.test(pullRequestNumber)) {
    throw new Error("Pull request number is invalid.");
  }
  if (!isFullSha(headSha)) {
    throw new Error("Audited commit SHA is invalid.");
  }
  if (!SUPPORTED_REPORT_FORMATS.has(reportFormat)) {
    throw new Error("Report format must be html or json.");
  }

  return `${repository}-pr-${pullRequestNumber}-${headSha.slice(0, 8)}-${reportFormat}`;
}

export function validatePullRequestAuditReportFile(input) {
  const reportDir = input.reportDir ?? "";
  const reportPath = input.reportPath ?? "";
  const privateTempDir = input.privateTempDir ?? "";
  const reportFormat = normalizeReportFormat(input.reportFormat);
  if (!SUPPORTED_REPORT_FORMATS.has(reportFormat)) {
    return rejectReport("unsupported-report-format", "Report format must be html or json.");
  }
  if (!reportDir || !existsSync(reportDir)) {
    return rejectReport("missing-report", "Report directory is missing.");
  }
  if (!reportPath || !existsSync(reportPath)) {
    return rejectReport("missing-report", "Pull Request Audit Report is missing.");
  }
  if (!privateTempDir || !existsSync(privateTempDir)) {
    return rejectReport("missing-private-temp", "Private temporary directory is missing.");
  }

  const tempRealPath = realpathSync(privateTempDir);
  const reportDirRealPath = realpathSync(reportDir);
  const reportRealPath = realpathSync(reportPath);
  if (!isInsideRoot(tempRealPath, reportDirRealPath) || !isInsideRoot(tempRealPath, reportRealPath)) {
    return rejectReport("outside-private-temp", "Pull Request Audit Report is outside private temporary directory.");
  }
  if (!isInsideRoot(reportDirRealPath, reportRealPath)) {
    return rejectReport("outside-report-dir", "Pull Request Audit Report is outside selected report directory.");
  }

  const entries = readdirSync(reportDirRealPath);
  if (entries.length !== 1 || basename(reportRealPath) !== entries[0]) {
    return rejectReport("multiple-report-files", "Exactly one selected report file must exist.");
  }
  if (extname(reportRealPath).toLowerCase() !== `.${reportFormat}`) {
    return rejectReport("wrong-report-format", "Pull Request Audit Report file format does not match request.");
  }
  const stats = statSync(reportRealPath);
  if (!stats.isFile() || stats.size === 0) {
    return rejectReport("incomplete-report", "Pull Request Audit Report is incomplete.");
  }

  return {
    accepted: true,
    code: "accepted",
    message: "Pull Request Audit Report accepted.",
    reportPath: reportRealPath,
    size: stats.size,
  };
}

export function publishPullRequestAuditArtifactMetadata(input) {
  const uploadOutcome = input.uploadOutcome ?? "";
  const artifactUrl = input.artifactUrl ?? "";
  const artifactId = String(input.artifactId ?? "");
  const artifactName = input.artifactName ?? "";
  const repository = input.repository ?? "";
  const pullRequestNumber = Number(input.pullRequestNumber ?? 0);
  const headSha = input.headSha ?? "";
  const reportFormat = normalizeReportFormat(input.reportFormat);

  if (uploadOutcome !== "success" || !artifactUrl || !artifactId) {
    const failedUpload = uploadOutcome === "failure" || uploadOutcome === "cancelled";
    return {
      reportUrl: "",
      artifactId: "",
      metadataJson: "",
      code: failedUpload ? "report-upload-failed" : "report-not-published",
      message: failedUpload
        ? "Pull Request Audit Artifact upload failed."
        : "Pull Request Audit Report was not published.",
    };
  }
  if (!isFullSha(headSha)) {
    throw new Error("Audited commit SHA is invalid.");
  }
  if (!/^\d+$/.test(artifactId)) {
    throw new Error("GitHub artifact ID is invalid.");
  }
  if (!SUPPORTED_REPORT_FORMATS.has(reportFormat)) {
    throw new Error("Report format must be html or json.");
  }
  assertHttpsUrl(artifactUrl);

  const metadata = {
    repository,
    pull_request_number: pullRequestNumber,
    audited_commit_sha: headSha,
    report_format: reportFormat,
    artifact_name: artifactName,
    github_artifact_id: artifactId,
    report_url: artifactUrl,
  };

  return {
    reportUrl: artifactUrl,
    artifactId,
    metadataJson: JSON.stringify(metadata),
    code: "published",
    message: "Pull Request Audit Report published.",
  };
}

export function removePartialPullRequestAuditReport(input) {
  const reportDir = input.reportDir ?? "";
  const privateTempDir = input.privateTempDir ?? "";
  if (!reportDir || !privateTempDir || !existsSync(reportDir) || !existsSync(privateTempDir)) {
    return {
      removed: false,
      code: "partial-report-not-found",
      message: "Partial Pull Request Audit Report was not found.",
    };
  }

  const tempRealPath = realpathSync(privateTempDir);
  const reportDirRealPath = realpathSync(reportDir);
  if (!isInsideRoot(tempRealPath, reportDirRealPath)) {
    return {
      removed: false,
      code: "partial-report-outside-temp",
      message: "Partial Pull Request Audit Report cleanup stayed inside temporary storage.",
    };
  }

  rmSync(reportDirRealPath, { recursive: true, force: true });
  return {
    removed: true,
    code: "partial-report-removed",
    message: "Partial Pull Request Audit Report removed.",
  };
}

export function buildPullRequestAuditCommentBody(input) {
  const docxVersion = input.docxVersion ?? "";
  const auditedSha = input.auditedSha ?? "";
  const reportFormat = normalizeReportFormat(input.reportFormat);
  const reportUrl = input.reportUrl ?? "";

  const versionError = validateDocxVersion(docxVersion);
  if (versionError) {
    throw new Error(versionError);
  }
  if (!isFullSha(auditedSha)) {
    throw new Error("Audited commit SHA is invalid.");
  }
  if (!SUPPORTED_REPORT_FORMATS.has(reportFormat)) {
    throw new Error("Report format must be html or json.");
  }
  assertHttpsUrl(reportUrl);

  return `${DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER}
## DocX Pull Request Audit

Current successful audit:

| Field | Value |
| --- | --- |
| DocX version | \`${docxVersion}\` |
| Audited commit SHA | \`${auditedSha}\` |
| Report format | \`${reportFormat}\` |
| Report link | [Open Pull Request Audit Report](${reportUrl}) |
`;
}

export async function updatePullRequestAuditComment(input, client = new GhPullRequestAuditClient(input.token)) {
  const repository = input.repository ?? "";
  const pullRequestNumber = String(input.pullRequestNumber ?? "");
  const docxVersion = input.docxVersion ?? "";
  const auditedSha = input.auditedSha ?? "";
  const reportFormat = normalizeReportFormat(input.reportFormat);
  const reportUrl = input.reportUrl ?? "";

  validateRepository(repository);
  validatePullRequestNumber(pullRequestNumber);
  const body = buildPullRequestAuditCommentBody({
    docxVersion,
    auditedSha,
    reportFormat,
    reportUrl,
  });

  const currentHeadSha = await client.getPullRequestHeadSha(repository, pullRequestNumber);
  if (currentHeadSha !== auditedSha) {
    return {
      updated: false,
      code: "stale-head",
      message: "Current pull request head does not match audited commit.",
      commentId: "",
      currentHeadSha,
      duplicateCommentCount: 0,
    };
  }

  const comments = await client.listIssueComments(repository, pullRequestNumber);
  const markedBotComments = comments
    .filter((comment) => isMarkedGitHubActionsComment(comment))
    .sort((left, right) => Number(left.id) - Number(right.id));
  let commentId;
  let action;
  if (markedBotComments.length > 0) {
    commentId = String(markedBotComments[0].id);
    await client.updateIssueComment(repository, commentId, body);
    action = "updated";
  } else {
    const created = await client.createIssueComment(repository, pullRequestNumber, body);
    commentId = String(created.id);
    action = "created";
  }

  const duplicateCommentIds = markedBotComments
    .slice(1)
    .map((comment) => String(comment.id));
  for (const duplicateCommentId of duplicateCommentIds) {
    await client.deleteIssueComment(repository, duplicateCommentId);
  }

  return {
    updated: true,
    code: action,
    message: `Pull Request Audit comment ${action}.`,
    commentId,
    currentHeadSha,
    duplicateCommentCount: duplicateCommentIds.length,
  };
}

export async function deleteOlderPullRequestAuditArtifacts(input, client = new GhPullRequestAuditClient(input.token)) {
  const repository = input.repository ?? "";
  const artifactName = input.artifactName ?? "";
  const currentArtifactId = String(input.currentArtifactId ?? "");

  validateRepository(repository);
  if (!artifactName) {
    throw new Error("Pull Request Audit Artifact name is missing.");
  }
  if (!/^\d+$/.test(currentArtifactId)) {
    throw new Error("Current artifact ID is invalid.");
  }

  const artifacts = await client.listArtifactsByName(repository, artifactName);
  const olderArtifacts = artifacts.filter((artifact) => {
    return artifact.name === artifactName && String(artifact.id) !== currentArtifactId;
  });
  for (const artifact of olderArtifacts) {
    await client.deleteArtifact(repository, String(artifact.id));
  }

  return {
    deleted: olderArtifacts.length,
    keptArtifactId: currentArtifactId,
  };
}

export function parsePullRequestAuditArtifactName(input) {
  const repository = input.repository ?? "";
  const artifactName = input.artifactName ?? "";
  validateRepository(repository);
  const repositoryPart = sanitizeArtifactNamePart(repository);
  const pattern = new RegExp(`^${escapeRegExpString(repositoryPart)}-pr-([1-9]\\d*)-([0-9a-fA-F]{8})-(html|json)$`);
  const match = artifactName.match(pattern);
  if (!match) {
    return rejectMaintenance("invalid-artifact-name", "Pull Request Audit Artifact name is invalid.");
  }
  return {
    accepted: true,
    code: "accepted",
    message: "Pull Request Audit Artifact name accepted.",
    pullRequestNumber: Number(match[1]),
    shortSha: match[2].toLowerCase(),
    reportFormat: match[3],
  };
}

export function validateMaintenanceArtifactIdentity(input) {
  const repository = input.repository ?? "";
  const artifact = input.artifact ?? {};
  const workflowRun = input.workflowRun ?? {};
  const pullRequest = input.pullRequest ?? {};
  validateRepository(repository);

  const parsedName = parsePullRequestAuditArtifactName({
    repository,
    artifactName: artifact.name,
  });
  if (!parsedName.accepted) {
    return parsedName;
  }

  const artifactRunId = String(artifact.workflow_run?.id ?? artifact.workflow_run_id ?? "");
  const workflowRunId = String(workflowRun.id ?? "");
  const artifactId = String(artifact.id ?? "");
  if (!/^\d+$/.test(artifactId)) {
    return rejectMaintenance("invalid-artifact-id", "Pull Request Audit Artifact ID is invalid.");
  }
  if (!artifactRunId || artifactRunId !== workflowRunId) {
    return rejectMaintenance("workflow-run-mismatch", "Producing workflow run does not match artifact.");
  }
  if (workflowRun.event !== "pull_request") {
    return rejectMaintenance("unsupported-workflow-run", "Producing workflow run must be pull_request.");
  }
  const fullHeadSha = workflowRun.head_sha ?? "";
  if (!isFullSha(fullHeadSha) || fullHeadSha.slice(0, 8).toLowerCase() !== parsedName.shortSha) {
    return rejectMaintenance("artifact-head-mismatch", "Producing workflow run head SHA does not match artifact name.");
  }

  const runPullRequestNumbers = (workflowRun.pull_requests ?? [])
    .map((candidate) => Number(candidate.number))
    .filter((number) => Number.isInteger(number));
  if (!runPullRequestNumbers.includes(parsedName.pullRequestNumber)) {
    return rejectMaintenance("pull-request-mismatch", "Producing workflow run does not match pull request.");
  }
  if (Number(pullRequest.number) !== parsedName.pullRequestNumber) {
    return rejectMaintenance("pull-request-mismatch", "Pull request does not match artifact name.");
  }
  if (pullRequest.state !== "open" && pullRequest.state !== "closed") {
    return rejectMaintenance("pull-request-state-invalid", "Pull request state is invalid.");
  }

  return {
    accepted: true,
    code: "accepted",
    message: "Pull Request Audit Artifact identity accepted.",
    artifactId,
    artifactName: artifact.name,
    producingWorkflowRunId: workflowRunId,
    pullRequestNumber: parsedName.pullRequestNumber,
    auditedSha: fullHeadSha,
    reportFormat: parsedName.reportFormat,
    isCurrentReport: pullRequest.head?.sha === fullHeadSha,
    pullRequestState: pullRequest.state,
  };
}

export function shouldRefreshPullRequestAuditArtifact(input) {
  const now = parseTime(input.now ?? new Date());
  const expiresAt = parseTime(input.expiresAt);
  if (!now || !expiresAt) {
    return false;
  }
  return expiresAt.getTime() - now.getTime() <= MAINTENANCE_REFRESH_WINDOW_MS;
}

export function planMaintenanceAction(input) {
  const now = parseTime(input.now ?? new Date());
  const expiresAt = parseTime(input.expiresAt);
  const pullRequest = input.pullRequest ?? {};
  const auditedSha = input.auditedSha ?? "";
  if (!now || !expiresAt) {
    return rejectMaintenance("invalid-maintenance-time", "Pull Request Audit Maintenance time is invalid.");
  }
  if (!isFullSha(auditedSha)) {
    return rejectMaintenance("invalid-audited-sha", "Audited commit SHA is invalid.");
  }

  if (pullRequest.state === "open") {
    return {
      accepted: true,
      operation: shouldRefreshPullRequestAuditArtifact({ now, expiresAt }) ? "refresh" : "keep",
      lifecycle: "open",
      deletionTime: "",
      code: "open-lifecycle",
    };
  }

  if (pullRequest.state !== "closed") {
    return rejectMaintenance("pull-request-state-invalid", "Pull request state is invalid.");
  }

  const isMerged = pullRequest.merged === true || Boolean(pullRequest.merged_at);
  const closedBasis = isMerged ? parseTime(pullRequest.merged_at) : parseTime(pullRequest.closed_at);
  if (!closedBasis) {
    return rejectMaintenance("missing-closed-time", "Pull request close time is missing.");
  }
  const deletionTime = new Date(closedBasis.getTime() + CLOSED_PULL_REQUEST_RETENTION_MS);

  if (isMerged && pullRequest.head?.sha !== auditedSha) {
    return {
      accepted: true,
      operation: "delete",
      lifecycle: "merged-non-final",
      deletionTime: deletionTime.toISOString(),
      code: "merged-non-final",
    };
  }

  if (now.getTime() >= deletionTime.getTime()) {
    return {
      accepted: true,
      operation: "delete",
      lifecycle: isMerged ? "merged-final-expired" : "closed-expired",
      deletionTime: deletionTime.toISOString(),
      code: isMerged ? "merged-final-expired" : "closed-expired",
    };
  }

  const mustRefreshForClosedRetention = expiresAt.getTime() <= deletionTime.getTime()
    && shouldRefreshPullRequestAuditArtifact({ now, expiresAt });
  return {
    accepted: true,
    operation: mustRefreshForClosedRetention ? "refresh" : "keep",
    lifecycle: isMerged ? "merged-final-retained" : "closed-retained",
    deletionTime: deletionTime.toISOString(),
    code: isMerged ? "merged-final-retained" : "closed-retained",
  };
}

export function validateMaintenanceUpload(input) {
  const uploadOutcome = input.uploadOutcome ?? "";
  const oldArtifactId = String(input.oldArtifactId ?? "");
  const newArtifactId = String(input.newArtifactId ?? "");
  const artifactName = input.artifactName ?? "";
  const artifactUrl = input.artifactUrl ?? "";
  if (uploadOutcome !== "success") {
    return rejectMaintenance("replacement-upload-failed", "Replacement Pull Request Audit Artifact upload failed.");
  }
  if (!/^\d+$/.test(oldArtifactId) || !/^\d+$/.test(newArtifactId) || oldArtifactId === newArtifactId) {
    return rejectMaintenance("replacement-artifact-invalid", "Replacement Pull Request Audit Artifact ID is invalid.");
  }
  if (!artifactName) {
    return rejectMaintenance("replacement-artifact-invalid", "Replacement Pull Request Audit Artifact name is missing.");
  }
  try {
    assertHttpsUrl(artifactUrl);
  } catch {
    return rejectMaintenance("replacement-artifact-invalid", "Replacement Pull Request Audit Artifact URL is invalid.");
  }
  return {
    accepted: true,
    code: "accepted",
    message: "Replacement Pull Request Audit Artifact accepted.",
    artifactId: newArtifactId,
    reportUrl: artifactUrl,
  };
}

export function shouldDeleteOldMaintenanceArtifact(input) {
  if (input.operation === "delete") {
    return true;
  }
  if (input.uploadAccepted !== true) {
    return false;
  }
  if (input.isCurrentReport === true) {
    return input.commentUpdated === true;
  }
  return true;
}

export async function planPullRequestAuditMaintenance(input, client = new GhPullRequestAuditClient(input.token)) {
  const repository = input.repository ?? "";
  const now = input.now ?? new Date();
  validateRepository(repository);
  const artifacts = await client.listArtifacts(repository);
  const items = [];
  const failures = [];

  for (const artifact of artifacts) {
    try {
      const name = parsePullRequestAuditArtifactName({ repository, artifactName: artifact.name });
      if (!name.accepted) {
        continue;
      }
      const workflowRunId = String(artifact.workflow_run?.id ?? artifact.workflow_run_id ?? "");
      const workflowRun = await client.getWorkflowRun(repository, workflowRunId);
      const pullRequest = await client.getPullRequest(repository, name.pullRequestNumber);
      const identity = validateMaintenanceArtifactIdentity({
        repository,
        artifact,
        workflowRun,
        pullRequest,
      });
      if (!identity.accepted) {
        failures.push({ artifact_id: String(artifact.id ?? ""), code: identity.code });
        continue;
      }
      const action = planMaintenanceAction({
        now,
        expiresAt: artifact.expires_at,
        pullRequest,
        auditedSha: identity.auditedSha,
      });
      if (!action.accepted) {
        failures.push({ artifact_id: String(artifact.id ?? ""), code: action.code });
        continue;
      }
      if (action.operation === "keep") {
        continue;
      }
      items.push({
        operation: action.operation,
        lifecycle: action.lifecycle,
        required_deletion_time: action.deletionTime,
        old_artifact_id: String(artifact.id),
        artifact_name: identity.artifactName,
        producing_workflow_run_id: identity.producingWorkflowRunId,
        pull_request_number: identity.pullRequestNumber,
        audited_sha: identity.auditedSha,
        report_format: identity.reportFormat,
        is_current_report: identity.isCurrentReport,
      });
    } catch {
      failures.push({ artifact_id: String(artifact.id ?? ""), code: "maintenance-item-failed" });
    }
  }

  return { items, failures };
}

export async function refreshCurrentPullRequestAuditComment(input, client = new GhPullRequestAuditClient(input.token)) {
  const repository = input.repository ?? "";
  const pullRequestNumber = String(input.pullRequestNumber ?? "");
  const auditedSha = input.auditedSha ?? "";
  const reportFormat = normalizeReportFormat(input.reportFormat);
  const reportUrl = input.reportUrl ?? "";
  validateRepository(repository);
  validatePullRequestNumber(pullRequestNumber);
  if (!isFullSha(auditedSha)) {
    throw new Error("Audited commit SHA is invalid.");
  }
  if (!SUPPORTED_REPORT_FORMATS.has(reportFormat)) {
    throw new Error("Report format must be html or json.");
  }
  assertHttpsUrl(reportUrl);

  const currentHeadSha = await client.getPullRequestHeadSha(repository, pullRequestNumber);
  if (currentHeadSha !== auditedSha) {
    return {
      updated: false,
      code: "stale-head",
      message: "Current pull request head does not match audited commit.",
      commentId: "",
      currentHeadSha,
    };
  }

  const comments = await client.listIssueComments(repository, pullRequestNumber);
  const markedBotComments = comments
    .filter((comment) => isMarkedGitHubActionsComment(comment))
    .sort((left, right) => Number(left.id) - Number(right.id));
  if (markedBotComments.length === 0) {
    return {
      updated: false,
      code: "missing-current-comment",
      message: "Current Pull Request Audit comment is missing.",
      commentId: "",
      currentHeadSha,
    };
  }

  const docxVersion = extractCommentDocxVersion(markedBotComments[0].body);
  if (!docxVersion) {
    return {
      updated: false,
      code: "invalid-current-comment",
      message: "Current Pull Request Audit comment is invalid.",
      commentId: String(markedBotComments[0].id),
      currentHeadSha,
    };
  }

  const body = buildPullRequestAuditCommentBody({
    docxVersion,
    auditedSha,
    reportFormat,
    reportUrl,
  });
  await client.updateIssueComment(repository, String(markedBotComments[0].id), body);
  return {
    updated: true,
    code: "updated",
    message: "Pull Request Audit comment refreshed.",
    commentId: String(markedBotComments[0].id),
    currentHeadSha,
  };
}

export async function downloadMaintenanceArtifact(input, client = new GhPullRequestAuditClient(input.token)) {
  const repository = input.repository ?? "";
  const artifactId = String(input.artifactId ?? "");
  const outputDir = input.outputDir ?? "";
  validateRepository(repository);
  if (!/^\d+$/.test(artifactId)) {
    throw new Error("Pull Request Audit Artifact ID is invalid.");
  }
  if (!outputDir) {
    throw new Error("Artifact output directory is missing.");
  }
  rmSync(outputDir, { recursive: true, force: true });
  mkdirSync(outputDir, { recursive: true });
  const archivePath = join(outputDir, "artifact.zip");
  const contentDir = join(outputDir, "content");
  mkdirSync(contentDir, { recursive: true });
  await client.downloadArtifactZip(repository, artifactId, archivePath);
  run("unzip", ["-q", archivePath, "-d", contentDir]);
  return { contentDir };
}

export class BinaryVerificationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = "BinaryVerificationError";
    this.code = code;
  }
}

export class GhPullRequestAuditClient {
  constructor(token) {
    this.token = token ?? process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? "";
  }

  async getPullRequestHeadSha(repository, pullRequestNumber) {
    const pullRequest = JSON.parse(this.#ghApi(["repos", repository, "pulls", pullRequestNumber].join("/")));
    const headSha = pullRequest?.head?.sha ?? "";
    if (!isFullSha(headSha)) {
      throw new Error("Current pull request head SHA is missing.");
    }
    return headSha;
  }

  async listIssueComments(repository, pullRequestNumber) {
    const output = this.#ghApi([
      "repos",
      repository,
      "issues",
      pullRequestNumber,
      "comments",
      "--paginate",
      "--slurp",
    ]);
    return parseConcatenatedJsonArrays(output);
  }

  async createIssueComment(repository, pullRequestNumber, body) {
    const output = this.#ghApi([
      "-X",
      "POST",
      ["repos", repository, "issues", pullRequestNumber, "comments"].join("/"),
      "-f",
      `body=${body}`,
    ]);
    return JSON.parse(output);
  }

  async updateIssueComment(repository, commentId, body) {
    const output = this.#ghApi([
      "-X",
      "PATCH",
      ["repos", repository, "issues", "comments", commentId].join("/"),
      "-f",
      `body=${body}`,
    ]);
    return JSON.parse(output);
  }

  async deleteIssueComment(repository, commentId) {
    this.#ghApi([
      "-X",
      "DELETE",
      ["repos", repository, "issues", "comments", commentId].join("/"),
    ]);
  }

  async listArtifactsByName(repository, artifactName) {
    const output = this.#ghApi([
      "repos",
      repository,
      "actions",
      "artifacts",
      "-f",
      `name=${artifactName}`,
      "--paginate",
      "--slurp",
    ]);
    return parseArtifactList(output);
  }

  async listArtifacts(repository) {
    const output = this.#ghApi([
      "repos",
      repository,
      "actions",
      "artifacts",
      "--paginate",
      "--slurp",
    ]);
    return parseArtifactList(output);
  }

  async getWorkflowRun(repository, runId) {
    if (!/^\d+$/.test(String(runId))) {
      throw new Error("Workflow run ID is invalid.");
    }
    const output = this.#ghApi([
      "repos",
      repository,
      "actions",
      "runs",
      String(runId),
    ]);
    return JSON.parse(output);
  }

  async getPullRequest(repository, pullRequestNumber) {
    validatePullRequestNumber(String(pullRequestNumber));
    const output = this.#ghApi([
      "repos",
      repository,
      "pulls",
      String(pullRequestNumber),
    ]);
    return JSON.parse(output);
  }

  async downloadArtifactZip(repository, artifactId, outputPath) {
    if (!/^\d+$/.test(String(artifactId))) {
      throw new Error("Pull Request Audit Artifact ID is invalid.");
    }
    mkdirSync(dirname(outputPath), { recursive: true });
    this.#ghApi([
      "repos",
      repository,
      "actions",
      "artifacts",
      String(artifactId),
      "zip",
      "--output",
      outputPath,
    ]);
  }

  async deleteArtifact(repository, artifactId) {
    this.#ghApi([
      "-X",
      "DELETE",
      ["repos", repository, "actions", "artifacts", artifactId].join("/"),
    ]);
  }

  #ghApi(args) {
    if (!this.token) {
      throw new Error("GitHub token is missing.");
    }
    const result = spawnSync("gh", ["api", ...args], {
      encoding: "utf8",
      env: { ...process.env, GH_TOKEN: this.token },
      maxBuffer: 1024 * 1024,
    });
    if (result.status !== 0) {
      throw new Error("GitHub API request failed.");
    }
    return result.stdout;
  }
}

export class GhReleaseClient {
  constructor(token) {
    this.token = token ?? "";
  }

  async getRelease(repository, tag) {
    const output = this.#gh([
      "release",
      "view",
      tag,
      "--repo",
      repository,
      "--json",
      "tagName,isDraft,isPrerelease,isImmutable,assets",
    ], "missing-exact-release");
    return JSON.parse(output);
  }

  async downloadAsset(repository, tag, assetName, outputPath) {
    mkdirSync(dirname(outputPath), { recursive: true });
    const tmpDir = mkdtempSync(join(tmpdir(), "docx-binary-download-"));
    try {
      this.#gh([
        "release",
        "download",
        tag,
        "--repo",
        repository,
        "--pattern",
        assetName,
        "--dir",
        tmpDir,
      ], "missing-release-asset");
      const downloadedPath = join(tmpDir, assetName);
      if (!existsSync(downloadedPath)) {
        throw new BinaryVerificationError("missing-release-asset", "Required release asset was not downloaded.");
      }
      copyFileSync(downloadedPath, outputPath);
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  }

  async verifyRelease(repository, tag) {
    this.#gh(["release", "verify", tag, "--repo", repository, "--format", "json"], "wrong-release-attestation");
  }

  async verifyReleaseAsset(repository, tag, assetPath) {
    this.#gh(["release", "verify-asset", tag, assetPath, "--repo", repository, "--format", "json"], "wrong-attestation");
  }

  #gh(args, defaultFailureCode = "github-request-failed") {
    if (!this.token) {
      throw new BinaryVerificationError("missing-token", "Binary Download Token is missing.");
    }
    const result = spawnSync("gh", args, {
      encoding: "utf8",
      env: { ...process.env, GH_TOKEN: this.token },
      maxBuffer: 1024 * 1024,
    });
    if (result.status !== 0) {
      const failureText = `${result.stderr}\n${result.stdout}`;
      const code = /bad credentials|http 401|http 403|resource not accessible/i.test(failureText)
        ? "invalid-token"
        : defaultFailureCode;
      throw new BinaryVerificationError(code, "GitHub release verification request failed.");
    }
    return result.stdout;
  }
}

function validateDocxVersion(version) {
  if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/.test(version)) {
    return "DocX version must be one stable semantic version.";
  }
  return "";
}

function validateRelease(release, identity) {
  if (release?.tagName !== identity.tag) {
    throw new BinaryVerificationError("missing-exact-release", "Exact immutable release is missing.");
  }
  if (release.isDraft === true || release.isPrerelease === true) {
    throw new BinaryVerificationError("unapproved-release-state", "Release state is not approved.");
  }
  if (release.isImmutable !== true) {
    throw new BinaryVerificationError("mutable-release", "Release is not immutable.");
  }
}

function findRequiredAsset(release, name) {
  const asset = (release.assets ?? []).find((candidate) => candidate.name === name);
  if (!asset) {
    throw new BinaryVerificationError("missing-release-asset", "Required release asset is missing.");
  }
  return asset;
}

function assetDigest(asset) {
  if (typeof asset.digest !== "string" || asset.digest.trim() === "") {
    throw new BinaryVerificationError("missing-github-digest", "GitHub release asset digest is missing.");
  }
  return asset.digest.replace(/^sha256:/i, "");
}

function parseManifest(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new BinaryVerificationError("invalid-release-manifest", "DocX Release Manifest is invalid.");
  }
}

function validateManifest(manifest, identity, version) {
  for (const field of REQUIRED_MANIFEST_FIELDS) {
    if (!Object.prototype.hasOwnProperty.call(manifest, field)) {
      throw new BinaryVerificationError("invalid-release-manifest", "DocX Release Manifest is incomplete.");
    }
  }

  assertManifestValue(manifest.manifest_schema_version, BINARY_CONTRACT.manifestSchemaVersion);
  assertManifestValue(manifest.docx_version, version);
  assertManifestValue(manifest.rust_target, BINARY_CONTRACT.target);
  assertManifestValue(manifest.minimum_ubuntu_version, BINARY_CONTRACT.minimumUbuntu);
  assertManifestValue(manifest.archive_name, identity.archiveName);
  assertManifestValue(manifest.archive_root_directory, `${identity.rootDirectory}/`);
  assertManifestValue(manifest.executable_name, identity.executableName);
  assertManifestValue(manifest.release_workflow_file, BINARY_CONTRACT.releaseWorkflowFile);
  assertManifestValue(manifest.approval_status, "approved");
  assertSha256(manifest.archive_sha256);
  assertSha256(manifest.executable_sha256);
  assertNonEmptyString(manifest.reviewer);
  assertNonEmptyString(manifest.approval_time);
}

function assertManifestValue(actual, expected) {
  if (actual !== expected) {
    throw new BinaryVerificationError("invalid-release-manifest", "DocX Release Manifest does not match request.");
  }
}

function assertNonEmptyString(value) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new BinaryVerificationError("invalid-release-manifest", "DocX Release Manifest is incomplete.");
  }
}

function assertSha256(value) {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/i.test(value)) {
    throw new BinaryVerificationError("invalid-release-manifest", "DocX Release Manifest digest is invalid.");
  }
}

function assertDigestEqual(actual, expected, label) {
  assertSha256(actual);
  assertSha256(expected);
  if (actual.toLowerCase() !== expected.toLowerCase()) {
    throw new BinaryVerificationError("digest-mismatch", `${label} digest does not match.`);
  }
}

function validateArchiveEntries(archivePath, identity) {
  const entries = run("tar", ["-tzf", archivePath])
    .trim()
    .split("\n")
    .filter(Boolean);
  const expected = [`${identity.rootDirectory}/`, `${identity.rootDirectory}/${identity.executableName}`];
  if (entries.length !== expected.length || entries.some((entry, index) => entry !== expected[index])) {
    throw new BinaryVerificationError("invalid-archive-layout", "Prebuilt DocX Binary archive layout is invalid.");
  }
}

function sha256File(path) {
  const hash = createHash("sha256");
  hash.update(readFileSync(path));
  return hash.digest("hex");
}

function writeVerificationState(path, state) {
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(state)}\n`, { mode: 0o600 });
}

function normalizeReportFormat(value) {
  return (value || "html").toLowerCase();
}

function isDependabot(login) {
  return login === "dependabot[bot]" || login === "dependabot-preview[bot]";
}

function isFullSha(value) {
  return /^[0-9a-f]{40}$/i.test(value);
}

function hasMultiplePathValues(value) {
  return /[\n\r,]/.test(value);
}

function isUrl(value) {
  return /^[a-z][a-z0-9+.-]*:\/\//i.test(value);
}

function hasGlobSyntax(value) {
  return /[*?\[\]{}]/.test(value);
}

function isInsideRoot(rootRealPath, candidateRealPath) {
  return candidateRealPath === rootRealPath || candidateRealPath.startsWith(`${rootRealPath}/`);
}

function skip(code, message) {
  return {
    shouldRun: false,
    shouldUseSecret: false,
    code,
    message,
    headSha: "",
    reportFormat: "html",
  };
}

function acceptBundle(path, kind) {
  return {
    accepted: true,
    code: "accepted",
    message: "Bundle path accepted.",
    path,
    kind,
  };
}

function rejectBundle(code, message) {
  return {
    accepted: false,
    code,
    message,
    path: "",
    kind: "",
  };
}

function rejectArtifact(code, message) {
  return {
    accepted: false,
    code,
    message,
  };
}

function rejectReport(code, message) {
  return {
    accepted: false,
    code,
    message,
    reportPath: "",
    size: 0,
  };
}

function rejectMaintenance(code, message) {
  return {
    accepted: false,
    code,
    message,
  };
}

function sanitizeArtifactNamePart(value) {
  return value
    .trim()
    .replace(/[\\/:<>|*?\r\n]+/g, "-")
    .replace(/\s+/g, "-")
    .replace(/^-+|-+$/g, "");
}

function escapeRegExpString(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseTime(value) {
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value;
  }
  if (typeof value !== "string" || value.trim() === "") {
    return null;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function extractCommentDocxVersion(body) {
  const match = String(body ?? "").match(/\| DocX version \| `([^`]+)` \|/);
  if (!match) {
    return "";
  }
  return validateDocxVersion(match[1]) ? "" : match[1];
}

function assertHttpsUrl(value) {
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    throw new Error("GitHub artifact URL is invalid.");
  }
  if (parsed.protocol !== "https:") {
    throw new Error("GitHub artifact URL must use HTTPS.");
  }
}

function validateRepository(repository) {
  if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository)) {
    throw new Error("Repository is invalid.");
  }
}

function validatePullRequestNumber(pullRequestNumber) {
  if (!/^[1-9]\d*$/.test(pullRequestNumber)) {
    throw new Error("Pull request number is invalid.");
  }
}

function isMarkedGitHubActionsComment(comment) {
  return comment?.user?.login === GITHUB_ACTIONS_BOT_LOGIN
    && typeof comment.body === "string"
    && comment.body.includes(DOCX_PULL_REQUEST_AUDIT_COMMENT_MARKER);
}

function parseConcatenatedJsonArrays(output) {
  const trimmed = output.trim();
  if (!trimmed) {
    return [];
  }
  const parsed = JSON.parse(trimmed);
  if (Array.isArray(parsed) && parsed.every((page) => Array.isArray(page))) {
    return parsed.flat();
  }
  if (Array.isArray(parsed)) {
    return parsed;
  }
  return [];
}

function parseArtifactList(output) {
  const trimmed = output.trim();
  if (!trimmed) {
    return [];
  }
  const parsed = JSON.parse(trimmed);
  if (Array.isArray(parsed?.artifacts)) {
    return parsed.artifacts;
  }
  if (Array.isArray(parsed)) {
    return parsed.flatMap((page) => page.artifacts ?? []);
  }
  return [];
}

function readJsonEnv(name) {
  const value = process.env[name];
  return value ? JSON.parse(value) : {};
}

function writeGitHubOutput(values) {
  const outputPath = process.env.GITHUB_OUTPUT;
  const lines = Object.entries(values)
    .map(([key, value]) => `${key}=${String(value)}`)
    .join("\n");
  if (outputPath) {
    appendFileSync(outputPath, `${lines}\n`);
  } else {
    console.log(lines);
  }
}

function writeGitHubWarning(code, message) {
  console.log(buildSafeWorkflowWarning(code, message));
}

export function buildSafeWorkflowWarning(code, message) {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(code)) {
    throw new Error("Safe failure code is invalid.");
  }
  return `::warning::DocX Pull Request Audit stopped: ${code}. ${message}`;
}

export function buildBinaryDownloadRecord(input) {
  const record = {
    consumer_repository: safeRecordString(input.consumerRepository, "Consumer Repository is missing."),
    workflow_run_id: safeDecimalString(input.workflowRunId, "Workflow run ID is invalid."),
    workflow_run_attempt: safeDecimalString(input.workflowRunAttempt, "Workflow run attempt is invalid."),
    commit_sha: safeFullSha(input.commitSha, "Commit SHA is invalid."),
    docx_version: safeDocxVersion(input.docxVersion),
    release_tag: safeReleaseTag(input.releaseTag, input.docxVersion),
    asset_name: safeAssetName(input.assetName),
    time: safeRecordTime(input.time),
    result: safeRecordResult(input.result),
    safe_failure_code: safeFailureCode(input.safeFailureCode),
  };
  if (input.verifiedArchiveDigest) {
    record.verified_archive_digest = safeSha256(input.verifiedArchiveDigest, "Verified archive digest is invalid.");
  }
  return record;
}

export function buildDocXExecutionReceipt(input) {
  return {
    consumer_repository: safeRecordString(input.consumerRepository, "Consumer Repository is missing."),
    workflow_run_id: safeDecimalString(input.workflowRunId, "Workflow run ID is invalid."),
    requested_docx_version: safeDocxVersion(input.requestedDocxVersion),
    docx_exit_code: safeExitCode(input.docxExitCode),
  };
}

function writeJsonRecord(path, value) {
  if (!path) {
    return;
  }
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600 });
}

function safeRecordString(value, message) {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(message);
  }
  return value;
}

function safeDecimalString(value, message) {
  const text = String(value ?? "");
  if (!/^\d+$/.test(text)) {
    throw new Error(message);
  }
  return text;
}

function safeFullSha(value, message) {
  if (!isFullSha(value)) {
    throw new Error(message);
  }
  return value.toLowerCase();
}

function safeDocxVersion(value) {
  const text = String(value ?? "");
  const error = validateDocxVersion(text);
  if (error) {
    throw new Error(error);
  }
  return text;
}

function safeReleaseTag(value, version) {
  const expected = `v${safeDocxVersion(version)}`;
  if (value !== expected) {
    throw new Error("Release tag is invalid.");
  }
  return value;
}

function safeAssetName(value) {
  if (typeof value !== "string" || !/^DocX-v\d+\.\d+\.\d+-x86_64-unknown-linux-gnu\.tar\.gz$/.test(value)) {
    throw new Error("Asset name is invalid.");
  }
  return value;
}

function safeRecordTime(value) {
  const text = String(value ?? "");
  const parsed = new Date(text);
  if (!text || Number.isNaN(parsed.getTime())) {
    throw new Error("Record time is invalid.");
  }
  return text;
}

function safeRecordResult(value) {
  if (value !== "verified" && value !== "failed") {
    throw new Error("Record result is invalid.");
  }
  return value;
}

function safeFailureCode(value) {
  const text = String(value ?? "");
  if (text !== "" && !/^[a-z0-9][a-z0-9-]*$/.test(text)) {
    throw new Error("Safe failure code is invalid.");
  }
  return text;
}

function safeSha256(value, message) {
  const text = String(value ?? "");
  if (!/^[0-9a-f]{64}$/i.test(text)) {
    throw new Error(message);
  }
  return text.toLowerCase();
}

function safeExitCode(value) {
  const text = String(value ?? "");
  if (!/^\d+$/.test(text)) {
    throw new Error("DocX exit code is invalid.");
  }
  const number = Number(text);
  if (!Number.isSafeInteger(number) || number < 0 || number > 255) {
    throw new Error("DocX exit code is invalid.");
  }
  return number;
}

function run(command, commandArgs) {
  const result = spawnSync(command, commandArgs, { encoding: "utf8" });
  if (result.status !== 0) {
    throw new BinaryVerificationError("tool-failed", "Required archive verification tool failed.");
  }
  return result.stdout;
}

async function main(argv) {
  const command = argv[2];
  if (command === "validate-request") {
    const result = evaluateAuditRequest({
      eventName: process.env.GITHUB_EVENT_NAME,
      action: process.env.GITHUB_EVENT_ACTION,
      actor: process.env.GITHUB_ACTOR,
      event: readJsonEnv("DOCX_EVENT_JSON"),
      docxVersion: process.env.DOCX_VERSION,
      reportFormat: process.env.REPORT_FORMAT,
      checkedOutSha: process.env.CHECKED_OUT_SHA,
    });
    writeGitHubOutput({
      should_run: result.shouldRun,
      should_use_secret: result.shouldUseSecret,
      code: result.code,
      message: result.message,
      head_sha: result.headSha,
      report_format: result.reportFormat,
    });
    if (!result.shouldRun) {
      if (QUIET_REQUEST_SKIP_CODES.has(result.code)) {
        console.log(`DocX Pull Request Audit skipped: ${result.code}. ${result.message}`);
      } else {
        writeGitHubWarning(result.code, result.message);
      }
    }
    return;
  }

  if (command === "validate-bundle") {
    const result = validateBundlePath({
      artifactRoot: process.env.ARTIFACT_ROOT,
      bundlePath: process.env.BUNDLE_PATH,
    });
    writeGitHubOutput({
      accepted: result.accepted,
      code: result.code,
      message: result.message,
      bundle_path: result.path,
      bundle_kind: result.kind,
    });
    if (!result.accepted) {
      writeGitHubWarning(result.code, result.message);
      return;
    }
    console.log(`DocX bundle accepted: ${result.kind}`);
    return;
  }

  if (command === "validate-artifact-head") {
    const result = validateArtifactHead({
      expectedHeadSha: process.env.EXPECTED_HEAD_SHA,
      artifactHeadSha: process.env.ARTIFACT_HEAD_SHA,
    });
    writeGitHubOutput({
      accepted: result.accepted,
      code: result.code,
      message: result.message,
    });
    if (!result.accepted) {
      writeGitHubWarning(result.code, result.message);
      return;
    }
    console.log("DocX artifact head accepted.");
    return;
  }

  if (command === "download-binary") {
    try {
      await verifyPrebuiltBinaryAttempt({
        token: process.env.GH_TOKEN,
        version: process.env.DOCX_VERSION,
        downloadDir: process.env.BINARY_DOWNLOAD_DIR,
        statePath: process.env.BINARY_VERIFICATION_STATE,
        recordPath: process.env.BINARY_DOWNLOAD_RECORD_PATH,
        consumerRepository: process.env.CONSUMER_REPOSITORY,
        workflowRunId: process.env.WORKFLOW_RUN_ID,
        workflowRunAttempt: process.env.WORKFLOW_RUN_ATTEMPT,
        commitSha: process.env.COMMIT_SHA,
        time: process.env.RECORD_TIME,
      });
      writeGitHubOutput({
        verified: true,
        code: "verified",
      });
      console.log("Prebuilt DocX Binary verified.");
    } catch (error) {
      const code = error instanceof BinaryVerificationError ? error.code : "binary-verification-failed";
      const message = error instanceof BinaryVerificationError
        ? error.message
        : "Prebuilt DocX Binary verification failed.";
      writeGitHubOutput({
        verified: false,
        code,
      });
      writeGitHubWarning(code, `${message} No fallback was used.`);
    }
    return;
  }

  if (command === "write-execution-receipt") {
    const receipt = buildDocXExecutionReceipt({
      consumerRepository: process.env.CONSUMER_REPOSITORY,
      workflowRunId: process.env.WORKFLOW_RUN_ID,
      requestedDocxVersion: process.env.DOCX_VERSION,
      docxExitCode: process.env.DOCX_EXIT_CODE,
    });
    writeJsonRecord(process.env.DOCX_EXECUTION_RECEIPT_PATH, receipt);
    writeGitHubOutput({
      receipt_written: Boolean(process.env.DOCX_EXECUTION_RECEIPT_PATH),
      docx_exit_code: receipt.docx_exit_code,
    });
    console.log("DocX Execution Receipt written.");
    return;
  }

  if (command === "confirm-executable") {
    const result = confirmVerifiedExecutable({
      statePath: process.env.BINARY_VERIFICATION_STATE,
    });
    writeGitHubOutput({
      executable_path: result.executablePath,
    });
    return;
  }

  if (command === "resolve-executable") {
    const result = confirmVerifiedExecutable({
      statePath: process.env.BINARY_VERIFICATION_STATE,
    });
    console.log(result.executablePath);
    return;
  }

  if (command === "artifact-name") {
    const artifactName = buildPullRequestAuditArtifactName({
      repository: process.env.REPOSITORY,
      pullRequestNumber: process.env.PULL_REQUEST_NUMBER,
      headSha: process.env.HEAD_SHA,
      reportFormat: process.env.REPORT_FORMAT,
    });
    writeGitHubOutput({ artifact_name: artifactName });
    console.log(`Pull Request Audit Artifact name: ${artifactName}`);
    return;
  }

  if (command === "validate-report") {
    const result = validatePullRequestAuditReportFile({
      reportDir: process.env.REPORT_DIR,
      reportPath: process.env.REPORT_PATH,
      privateTempDir: process.env.RUNNER_TEMP,
      reportFormat: process.env.REPORT_FORMAT,
    });
    writeGitHubOutput({
      accepted: result.accepted,
      code: result.code,
      message: result.message,
      report_path: result.reportPath,
      report_size: result.size,
    });
    if (!result.accepted) {
      writeGitHubWarning(result.code, result.message);
      return;
    }
    console.log("Pull Request Audit Report accepted.");
    return;
  }

  if (command === "cleanup-report") {
    const result = removePartialPullRequestAuditReport({
      reportDir: process.env.REPORT_DIR,
      privateTempDir: process.env.RUNNER_TEMP,
    });
    writeGitHubOutput({
      removed: result.removed,
      code: result.code,
      message: result.message,
    });
    if (result.removed) {
      console.log(result.message);
    }
    return;
  }

  if (command === "publish-report-output") {
    const result = publishPullRequestAuditArtifactMetadata({
      uploadOutcome: process.env.UPLOAD_OUTCOME,
      artifactUrl: process.env.UPLOAD_ARTIFACT_URL,
      artifactId: process.env.UPLOAD_ARTIFACT_ID,
      artifactName: process.env.ARTIFACT_NAME,
      repository: process.env.REPOSITORY,
      pullRequestNumber: process.env.PULL_REQUEST_NUMBER,
      headSha: process.env.HEAD_SHA,
      reportFormat: process.env.REPORT_FORMAT,
    });
    writeGitHubOutput({
      report_url: result.reportUrl,
      artifact_id: result.artifactId,
      artifact_name: process.env.ARTIFACT_NAME ?? "",
      audited_sha: process.env.HEAD_SHA ?? "",
      report_format: normalizeReportFormat(process.env.REPORT_FORMAT),
      metadata_json: result.metadataJson,
    });
    if (!result.reportUrl) {
      writeGitHubWarning(result.code, result.message);
    }
    return;
  }

  if (command === "update-comment") {
    try {
      const result = await updatePullRequestAuditComment({
        repository: process.env.REPOSITORY,
        pullRequestNumber: process.env.PULL_REQUEST_NUMBER,
        docxVersion: process.env.DOCX_VERSION,
        auditedSha: process.env.AUDITED_SHA,
        reportFormat: process.env.REPORT_FORMAT,
        reportUrl: process.env.REPORT_URL,
      });
      writeGitHubOutput({
        updated: result.updated,
        code: result.code,
        message: result.message,
        comment_id: result.commentId,
        current_head_sha: result.currentHeadSha,
        duplicate_comment_count: result.duplicateCommentCount,
      });
      if (!result.updated) {
        writeGitHubWarning(result.code, result.message);
      } else {
        console.log(result.message);
      }
    } catch (error) {
      writeGitHubOutput({
        updated: false,
        code: "comment-update-failed",
        message: "Pull Request Audit comment update failed.",
        comment_id: "",
        current_head_sha: "",
        duplicate_comment_count: 0,
      });
      writeGitHubWarning("comment-update-failed", "Pull Request Audit comment update failed.");
    }
    return;
  }

  if (command === "delete-older-artifacts") {
    try {
      const result = await deleteOlderPullRequestAuditArtifacts({
        repository: process.env.REPOSITORY,
        artifactName: process.env.ARTIFACT_NAME,
        currentArtifactId: process.env.CURRENT_ARTIFACT_ID,
      });
      writeGitHubOutput({
        deleted: result.deleted,
        kept_artifact_id: result.keptArtifactId,
      });
      console.log(`Older Pull Request Audit Artifacts deleted: ${result.deleted}`);
    } catch (error) {
      writeGitHubOutput({
        deleted: 0,
        kept_artifact_id: process.env.CURRENT_ARTIFACT_ID ?? "",
      });
      writeGitHubWarning("artifact-cleanup-failed", "Older Pull Request Audit Artifact cleanup failed.");
    }
    return;
  }

  if (command === "plan-maintenance") {
    const result = await planPullRequestAuditMaintenance({
      repository: process.env.GITHUB_REPOSITORY,
      now: process.env.DOCX_MAINTENANCE_NOW || new Date(),
    });
    writeGitHubOutput({
      items_json: JSON.stringify(result.items),
      failure_count: result.failures.length,
    });
    console.log(`Pull Request Audit Maintenance items: ${result.items.length}`);
    if (result.failures.length > 0) {
      writeGitHubWarning("maintenance-item-failed", "One or more Pull Request Audit Maintenance items failed.");
    }
    return;
  }

  if (command === "download-maintenance-artifact") {
    try {
      const result = await downloadMaintenanceArtifact({
        repository: process.env.GITHUB_REPOSITORY,
        artifactId: process.env.OLD_ARTIFACT_ID,
        outputDir: process.env.ARTIFACT_DOWNLOAD_DIR,
      });
      writeGitHubOutput({
        downloaded: true,
        content_dir: result.contentDir,
      });
      console.log("Pull Request Audit Artifact downloaded.");
    } catch {
      writeGitHubOutput({
        downloaded: false,
        content_dir: "",
      });
      writeGitHubWarning("maintenance-download-failed", "Pull Request Audit Artifact download failed.");
      throw new Error("Pull Request Audit Artifact download failed.");
    }
    return;
  }

  if (command === "validate-maintenance-upload") {
    const result = validateMaintenanceUpload({
      uploadOutcome: process.env.UPLOAD_OUTCOME,
      oldArtifactId: process.env.OLD_ARTIFACT_ID,
      newArtifactId: process.env.NEW_ARTIFACT_ID,
      artifactName: process.env.ARTIFACT_NAME,
      artifactUrl: process.env.NEW_ARTIFACT_URL,
    });
    writeGitHubOutput({
      accepted: result.accepted,
      code: result.code,
      message: result.message,
      new_artifact_id: result.artifactId ?? "",
      report_url: result.reportUrl ?? "",
    });
    if (!result.accepted) {
      writeGitHubWarning(result.code, result.message);
      throw new Error(`${result.code}: ${result.message}`);
    }
    console.log("Replacement Pull Request Audit Artifact accepted.");
    return;
  }

  if (command === "refresh-maintenance-comment") {
    try {
      const result = await refreshCurrentPullRequestAuditComment({
        repository: process.env.GITHUB_REPOSITORY,
        pullRequestNumber: process.env.PULL_REQUEST_NUMBER,
        auditedSha: process.env.AUDITED_SHA,
        reportFormat: process.env.REPORT_FORMAT,
        reportUrl: process.env.REPORT_URL,
      });
      writeGitHubOutput({
        updated: result.updated,
        code: result.code,
        message: result.message,
        comment_id: result.commentId,
        current_head_sha: result.currentHeadSha,
      });
      if (!result.updated) {
        writeGitHubWarning(result.code, result.message);
      } else {
        console.log(result.message);
      }
    } catch {
      writeGitHubOutput({
        updated: false,
        code: "maintenance-comment-failed",
        message: "Pull Request Audit Maintenance comment update failed.",
        comment_id: "",
        current_head_sha: "",
      });
      writeGitHubWarning("maintenance-comment-failed", "Pull Request Audit Maintenance comment update failed.");
      throw new Error("Pull Request Audit Maintenance comment update failed.");
    }
    return;
  }

  if (command === "delete-maintenance-artifact") {
    try {
      const uploadAccepted = process.env.UPLOAD_ACCEPTED === "true";
      const isCurrentReport = process.env.IS_CURRENT_REPORT === "true";
      const commentUpdated = process.env.COMMENT_UPDATED === "true";
      const operation = process.env.MAINTENANCE_OPERATION ?? "";
      if (!shouldDeleteOldMaintenanceArtifact({ operation, uploadAccepted, isCurrentReport, commentUpdated })) {
        writeGitHubOutput({ deleted: false });
        console.log("Old Pull Request Audit Artifact kept for retry.");
        return;
      }
      const client = new GhPullRequestAuditClient(process.env.GITHUB_TOKEN);
      await client.deleteArtifact(process.env.GITHUB_REPOSITORY, process.env.OLD_ARTIFACT_ID);
      writeGitHubOutput({ deleted: true });
      console.log("Old Pull Request Audit Artifact deleted.");
    } catch {
      writeGitHubOutput({ deleted: false });
      writeGitHubWarning("maintenance-delete-failed", "Old Pull Request Audit Artifact deletion failed.");
      throw new Error("Old Pull Request Audit Artifact deletion failed.");
    }
    return;
  }

  throw new Error("expected command: validate-request, validate-bundle, validate-artifact-head, download-binary, write-execution-receipt, confirm-executable, resolve-executable, artifact-name, validate-report, cleanup-report, publish-report-output, update-comment, delete-older-artifacts, plan-maintenance, download-maintenance-artifact, validate-maintenance-upload, refresh-maintenance-comment, or delete-maintenance-artifact");
}

const isDirectRun = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isDirectRun) {
  main(process.argv).catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
