---
title: Supply Chain Auditor Env
emoji: 🛡️
colorFrom: blue
colorTo: indigo
sdk: docker
pinned: false
app_port: 7860
tags:
  - openenv
---

# Supply Chain Auditor Env

## 1. Overview & Motivation

In March 2024, a backdoor in XZ Utils nearly compromised SSH authentication across every major Linux distribution. Log4Shell affected 35,000+ Java packages. SolarWinds breached 18,000 organizations including US federal agencies. The common thread: software supply chain attacks that turn trusted dependencies into weapons.

This environment puts AI agents in the seat of a supply chain security engineer — the human defender who hunts these threats daily. Agents must inspect package manifests, query CVE databases, trace transitive dependency trees to find hidden vulnerabilities, detect typosquatted package names, generate SBOMs, and propose minimal-upgrade remediation plans. Grading is fully deterministic and reproducible, enabling rigorous evaluation of agent security reasoning.

## 2. Environment Design

### Action Space

| Action | Purpose | Required Inputs |
| --- | --- | --- |
| `inspect_package` | Fetch package metadata from registry | `package_name`, `version` |
| `check_cve` | Query CVE records for package@version | `package_name`, `version` |
| `trace_deps` | Return dependency tree up to depth | `package_name`, `version`, `depth` |
| `flag_package` | Mark package as risky | `package_name`, `version`, `reason` |
| `unflag_package` | Remove a previous flag | `package_name`, `version` |
| `generate_sbom` | Build software bill of materials | none |
| `remediate` | Propose upgrade target | `package_name`, `version`, `target_version` |
| `submit_report` | End episode and trigger grading | optional `report` |

### Observation Space

| Field | Type | Description |
| --- | --- | --- |
| `task_id` | `str` | Active task identifier |
| `step` | `int` | Current episode step |
| `max_steps` | `int` | Step budget for task |
| `requirements` | `list[str]` | Starting manifest (`name==version`) |
| `objective` | `str` | Human-readable task objective |
| `last_action_result` | `dict \| null` | Structured result payload |
| `flags` | `list[FlagEntry]` | Risk flags currently set |
| `remediations` | `list[RemediationEntry]` | Proposed upgrade actions |
| `sbom` | `list[dict] \| null` | Generated package inventory |
| `message` | `str` | Feedback message |
| `done` | `bool` | Episode completion flag |

## 3. Task Descriptions

### Easy: Flat Dependency Audit (`flat_audit`)

- Difficulty: easy
- Objective: identify vulnerable direct dependencies in a fixed requirements manifest.
- Grading: F1 over gold vulnerable package/version pairs with false-positive impact through precision.

### Medium: Typosquatting + Transitive CVE (`typosquat_transitive`)

- Difficulty: medium
- Objective: detect typosquats and one transitive CVE hidden behind dependency traversal.
- Grading: weighted typosquat hit score + transitive CVE hit score, minus capped false-positive penalty.

### Hard: Full SBOM + Remediation (`full_sbom_remediation`)

- Difficulty: hard
- Objective: detect direct/transitive CVEs, generate SBOM coverage, and propose minimal valid remediation.
- Grading: weighted blend of CVE coverage, SBOM completeness, remediation validity, and upgrade parsimony.

## 4. Reward Function

| Event | Reward |
| --- | --- |
| `correct_cve_flagged` | +0.12 |
| `typosquat_detected` | +0.18 |
| `transitive_dep_traced` | +0.08 |
| `false_positive_flag` | -0.08 |
| `valid_remediation` | +0.08 |
| `invalid_remediation` | -0.05 |
| `sbom_generated` | +0.05 |
| `redundant_action` | -0.02 |
| `step_penalty` | -0.01 |
| `report_submitted_complete` | +0.20 |
| `report_submitted_partial` | +0.10 |

Step rewards are in `[-1.0, 1.0]`. Cumulative reward state is clamped to `[0.0, 1.0]`.

## 5. Setup & Usage

```bash
# Clone
git clone <your-repo-url>
cd supply-chain-auditor-env

# Virtual environment (recommended)
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1

# Install deps
pip install -r requirements.txt

# OpenEnv validation (must pass)
openenv validate

# Run inference (required root script)
# Required env vars:
# API_BASE_URL (default provided in script)
# MODEL_NAME (default provided in script)
# HF_TOKEN (required)
HF_TOKEN=<your-token> API_BASE_URL=https://router.huggingface.co/v1 MODEL_NAME=meta-llama/Llama-3.1-8B-Instruct python inference.py

# Build and run container
docker build -t supply-chain-auditor .
docker run -p 7860:7860 supply-chain-auditor

# Health check
curl http://localhost:7860/health
```

## 6. Baseline Performance

Current workspace baseline was generated from reproducible local runs using OpenAI client with Hugging Face OpenAI-compatible routing:

- API_BASE_URL: [https://router.huggingface.co/v1](https://router.huggingface.co/v1)
- MODEL_NAME: meta-llama/Llama-3.1-8B-Instruct

| Task | Score |
| --- | --- |
| Flat audit (easy) | 0.67 |
| Typosquat + transitive (medium) | 0.90 |
| Full SBOM + remediation (hard) | 0.96 |
| **Mean** | **0.84** |

## 7. Why This Environment Matters

Supply chain attacks are the dominant security threat of this decade:

- **XZ Utils (2024)**: A backdoor planted in a compression library nearly compromised SSH authentication across millions of Linux systems.
- **Log4Shell (2021)**: A single vulnerability in Log4j affected over 35,000 Java packages and cost organizations billions in remediation.
- **SolarWinds (2020)**: Malicious code injected into a software update pipeline compromised 18,000+ organizations including US federal agencies.

This environment trains agents on the exact workflow security engineers perform daily: inspecting dependencies, identifying CVEs, tracing transitive risks, and proposing minimal remediations. Unlike toy benchmarks, this directly addresses a $10B+ annual problem.

## 8. Hugging Face Space

- **Deployment URL:** [https://huggingface.co/spaces/LuciferMrng/Supply-Chain-Auditor-ENV](https://huggingface.co/spaces/LuciferMrng/Supply-Chain-Auditor-ENV)
- Space is tagged with `openenv` via README frontmatter
- Health check: `GET /health` returns `{"status": "healthy"}`

