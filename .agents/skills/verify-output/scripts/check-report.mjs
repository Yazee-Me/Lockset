#!/usr/bin/env node
// Mechanical gate for a verification report.
//
//   node check-report.mjs [--spec <path>]... [--json] <report.md>
//
// Exit codes: 0 valid, 1 invalid, 2 usage or parse error.

import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const SOURCE_KINDS = new Set([
	"observed",
	"external",
	"differential",
	"invariant",
	"research",
	"prior",
	"declared",
]);
const CHECK_VERDICTS = new Set([
	"validated",
	"corroborated",
	"spec-echo",
	"contradicted",
	"unverified",
	"not-applicable",
]);
const OVERALL_VERDICTS = new Set([
	"validated",
	"blocked",
	"unverified",
	"not-applicable",
]);
const SEVERITIES = new Set(["high", "medium", "low"]);

function usage(message) {
	if (message) process.stderr.write(`error: ${message}\n\n`);
	process.stderr.write(
		"usage: check-report.mjs [--spec <path>]... [--json] <report.md>\n",
	);
	process.exit(2);
}

function normalize(value) {
	return String(value)
		.replace(/`/g, "")
		.replace(/\s+/g, " ")
		.trim()
		.toLowerCase();
}

function extractRequirements(specPath) {
	const text = readFileSync(specPath, "utf8");
	const requirements = [];
	let inFence = false;
	let fenceMarker = "";
	for (const rawLine of text.split(/\r?\n/)) {
		const line = rawLine.trimEnd();
		const fence = line.match(/^\s*(```+|~~~+)/);
		if (fence) {
			if (!inFence) {
				inFence = true;
				fenceMarker = fence[1][0];
			} else if (fence[1][0] === fenceMarker) {
				inFence = false;
				fenceMarker = "";
			}
			continue;
		}
		if (inFence) continue;
		const match = line.match(/^###\s+Requirement:\s*(.+?)\s*$/);
		if (match) requirements.push(match[1].trim());
	}
	return requirements;
}

function extractJsonBlock(markdown) {
	const match = markdown.match(/```json\s*\r?\n([\s\S]*?)\r?\n```/);
	if (!match) return null;
	return JSON.parse(match[1]);
}

function isNonEmptyString(value) {
	return typeof value === "string" && value.trim().length > 0;
}

function checkReport(report, specRequirements) {
	const errors = [];
	const warnings = [];

	if (!report || typeof report !== "object" || Array.isArray(report)) {
		errors.push("report JSON must be an object");
		return { errors, warnings };
	}

	for (const key of [
		"change",
		"date",
		"artifact",
		"surface",
		"environment",
		"verdict",
	]) {
		if (!isNonEmptyString(report[key]))
			errors.push(`missing or empty string: ${key}`);
	}
	if (!/^\d{4}-\d{2}-\d{2}$/.test(report.date ?? ""))
		errors.push(`date must be YYYY-MM-DD, got ${JSON.stringify(report.date)}`);
	if (!OVERALL_VERDICTS.has(report.verdict))
		errors.push(`invalid overall verdict: ${JSON.stringify(report.verdict)}`);

	const sources = Array.isArray(report.sources) ? report.sources : [];
	if (!Array.isArray(report.sources)) errors.push("sources must be an array");
	const sourceById = new Map();
	for (const source of sources) {
		if (!isNonEmptyString(source?.id)) {
			errors.push("source without an id");
			continue;
		}
		if (sourceById.has(source.id))
			errors.push(`duplicate source id: ${source.id}`);
		sourceById.set(source.id, source);
		if (!SOURCE_KINDS.has(source.kind))
			errors.push(
				`source ${source.id} has invalid kind: ${JSON.stringify(source.kind)}`,
			);
		if (!isNonEmptyString(source.ref))
			errors.push(`source ${source.id} has no ref`);
	}
	if (sources.length === 0) errors.push("sources must not be empty");
	if (
		sources.length > 0 &&
		!sources.some((source) => source.kind && source.kind !== "declared")
	)
		errors.push("at least one source must be independent of the declared rules");

	const checks = Array.isArray(report.checks) ? report.checks : [];
	if (!Array.isArray(report.checks)) errors.push("checks must be an array");
	if (checks.length === 0) errors.push("checks must not be empty");
	const checkIds = new Set();
	let validatedCount = 0;
	let independentCount = 0;
	let hasUnverified = false;
	let hasBlockingVerdict = false;
	let hasFailedFlip = false;
	let notApplicableCount = 0;

	for (const check of checks) {
		if (!isNonEmptyString(check?.id)) {
			errors.push("check without an id");
			continue;
		}
		const label = `check ${check.id}`;
		if (checkIds.has(check.id)) errors.push(`duplicate check id: ${check.id}`);
		checkIds.add(check.id);
		if (!CHECK_VERDICTS.has(check.verdict))
			errors.push(`${label} has invalid verdict: ${JSON.stringify(check.verdict)}`);
		if (!isNonEmptyString(check.requirement))
			errors.push(`${label} has no requirement`);
		if (!Array.isArray(check.origin) || check.origin.length === 0) {
			errors.push(`${label} has no origin`);
		} else {
			for (const sourceId of check.origin) {
				if (!sourceById.has(sourceId))
					errors.push(`${label} cites unknown source: ${sourceId}`);
			}
			const independent = check.origin.some(
				(sourceId) => sourceById.get(sourceId)?.kind !== "declared",
			);
			if (independent) independentCount += 1;
			if (check.verdict === "validated" || check.verdict === "corroborated") {
				if (!independent)
					errors.push(
						`${label} is ${check.verdict} but its only origins are declared rules`,
					);
			}
		}
		if (check.verdict !== "not-applicable") {
			for (const key of ["probe", "expected", "observed"]) {
				if (!isNonEmptyString(check[key]))
					errors.push(`${label} has no ${key}`);
			}
		}
		if (check.verdict === "validated") {
			validatedCount += 1;
			const flip = check.flip;
			if (!flip || typeof flip !== "object") {
				errors.push(`${label} is validated without a flip`);
			} else {
				if (!isNonEmptyString(flip.perturbation))
					errors.push(`${label} flip has no perturbation`);
				if (!isNonEmptyString(flip.observed))
					errors.push(`${label} flip has no observed result`);
				if (flip.result !== "pass")
					errors.push(
						`${label} is validated but its flip result is ${JSON.stringify(flip.result)}`,
					);
			}
		}
		if (check.flip && check.flip.result === "fail") {
			hasFailedFlip = true;
			if (check.verdict === "validated")
				errors.push(`${label} cannot be validated: the probe did not detect the perturbation`);
		}
		if (check.verdict === "spec-echo" || check.verdict === "contradicted") {
			hasBlockingVerdict = true;
		}
		if (check.verdict === "unverified") {
			hasUnverified = true;
			if (!isNonEmptyString(check.reason))
				errors.push(`${label} is unverified without a reason`);
		}
		if (check.verdict === "not-applicable") {
			notApplicableCount += 1;
			if (!isNonEmptyString(check.reason))
				errors.push(`${label} is not-applicable without a reason`);
		}
	}

	const circularity = Array.isArray(report.circularity) ? report.circularity : [];
	if (!Array.isArray(report.circularity))
		errors.push("circularity must be an array");
	for (const item of circularity) {
		if (!isNonEmptyString(item?.finding))
			errors.push("circularity entry without a finding");
		if (!isNonEmptyString(item?.evidence))
			errors.push("circularity entry without evidence");
		if (!SEVERITIES.has(item?.severity))
			errors.push(
				`circularity entry has invalid severity: ${JSON.stringify(item?.severity)}`,
			);
	}
	const hasHighCircularity = circularity.some((item) => item?.severity === "high");

	const ruleTrace = Array.isArray(report.rule_trace) ? report.rule_trace : [];
	if (!Array.isArray(report.rule_trace))
		errors.push("rule_trace must be an array");
	if (ruleTrace.length === 0)
		warnings.push(
			"rule_trace is empty; if the change enforces any threshold, date, authorization, or state rule, trace it",
		);
	for (const entry of ruleTrace) {
		if (!isNonEmptyString(entry?.rule))
			errors.push("rule_trace entry without a rule");
		if (!Array.isArray(entry?.enforcement) || entry.enforcement.length === 0)
			errors.push(
				`rule_trace entry has no enforcement point: ${JSON.stringify(entry?.rule)}`,
			);
	}

	if (specRequirements && specRequirements.length > 0) {
		const covered = new Set();
		for (const check of checks) {
			if (isNonEmptyString(check?.requirement))
				covered.add(normalize(check.requirement));
			if (Array.isArray(check?.covers))
				for (const extra of check.covers)
					if (isNonEmptyString(extra)) covered.add(normalize(extra));
		}
		const missing = specRequirements.filter(
			(requirement) => !covered.has(normalize(requirement)),
		);
		for (const requirement of missing)
			errors.push(`requirement has no check: ${requirement}`);
		if (missing.length > 0) hasBlockingVerdict = true;

		const known = new Set(specRequirements.map(normalize));
		for (const item of covered)
			if (!known.has(item))
				warnings.push(
					`check names a requirement not found in the supplied spec: ${item}`,
				);
	}

	if (report.verdict === "validated") {
		if (hasBlockingVerdict)
			errors.push("overall verdict is validated but a check is spec-echo or contradicted");
		if (hasHighCircularity)
			errors.push("overall verdict is validated despite high-severity circularity");
		if (hasUnverified)
			errors.push("overall verdict is validated but a check is unverified");
		if (hasFailedFlip)
			errors.push("overall verdict is validated but a flip failed");
		if (validatedCount === 0)
			errors.push("overall verdict is validated but no check is validated");
		if (checks.length > 0 && notApplicableCount === checks.length)
			errors.push("overall verdict is validated but every check is not-applicable");
	}
	if (report.verdict === "not-applicable") {
		if (notApplicableCount !== checks.length || checks.length === 0)
			errors.push("overall verdict is not-applicable but some check is applicable");
	}
	if (report.verdict === "unverified" && !hasUnverified)
		warnings.push("overall verdict is unverified but no check is unverified");
	if (
		report.verdict === "blocked" &&
		!hasBlockingVerdict &&
		!hasHighCircularity &&
		!hasFailedFlip
	)
		warnings.push("overall verdict is blocked but no check or circularity finding explains it");

	if (independentCount === 0 && checks.length > 0)
		errors.push("no check uses an independent source");

	return { errors, warnings };
}

const args = process.argv.slice(2);
if (args.length === 0) usage("missing report path");
const specPaths = [];
let reportPath = null;
let jsonOutput = false;
for (let index = 0; index < args.length; index += 1) {
	const arg = args[index];
	if (arg === "--spec") {
		const value = args[index + 1];
		if (!value) usage("--spec needs a path");
		specPaths.push(value);
		index += 1;
	} else if (arg === "--json") {
		jsonOutput = true;
	} else if (arg.startsWith("-")) {
		usage(`unknown option: ${arg}`);
	} else if (reportPath) {
		usage(`unexpected argument: ${arg}`);
	} else {
		reportPath = arg;
	}
}
if (!reportPath) usage("missing report path");

let markdown;
try {
	markdown = readFileSync(reportPath, "utf8");
} catch (error) {
	usage(`cannot read report: ${error.message}`);
}

let report;
try {
	report = extractJsonBlock(markdown);
} catch (error) {
	usage(`report JSON is invalid: ${error.message}`);
}
if (!report) usage("report has no fenced ```json block");

let specRequirements = null;
const specProblems = [];
for (const specPath of specPaths) {
	try {
		const requirements = extractRequirements(specPath);
		if (requirements.length === 0) {
			specProblems.push(`no requirements found in ${specPath}`);
			continue;
		}
		specRequirements = [...(specRequirements ?? []), ...requirements];
	} catch (error) {
		specProblems.push(`cannot read spec ${specPath}: ${error.message}`);
	}
}
if (specProblems.length > 0) {
	for (const problem of specProblems) process.stderr.write(`error: ${problem}\n`);
	process.exit(2);
}

const { errors, warnings } = checkReport(report, specRequirements);
const summary = {
	report: resolve(reportPath),
	change: report.change,
	verdict: report.verdict,
	checks: Array.isArray(report.checks) ? report.checks.length : 0,
	sources: Array.isArray(report.sources) ? report.sources.length : 0,
	errors,
	warnings,
};

if (jsonOutput) {
	process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
} else {
	for (const warning of warnings) process.stdout.write(`warning: ${warning}\n`);
	for (const error of errors) process.stdout.write(`error: ${error}\n`);
	if (errors.length === 0) {
		process.stdout.write(
			`OK ${reportPath} — ${summary.checks} checks, verdict ${report.verdict}\n`,
		);
	}
}

process.exit(errors.length === 0 ? 0 : 1);
