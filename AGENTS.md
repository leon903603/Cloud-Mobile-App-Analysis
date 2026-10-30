# AGENTS.md

## Communication & Language Rules
- Respond and explain in Traditional Chinese (繁體中文).
- Write all code, variable names, and code comments in English.

## Project Role & Engineering Scope

### 1. Core Mission
- **Cloud Platform Engineering & Operations**:
  - Focus on CMAA cloud infrastructure (AWS EC2 / S3 / Lambda / IAM), web services (React frontend & Express backend), visitor/member authentication systems, transactional atomic credit deduction, payment workflows, and security guardrails.
  - Architect and maintain integration adapters and seams bridging various analysis engines to the cloud platform.

### 2. Scope Boundaries

#### ✅ In-Scope (Cloud Integration & Adapters)
- **Cloud Integration & Adapters**:
  - Interface refactoring, protocol conversions, and containerized wrappers designed to integrate static engines, dynamic sandboxes, and PDF generators into the cloud platform (e.g., HTTP/Queue API wrappers, S3 streaming I/O, Redis/Celery task queues, Docker/Compose setups).
  - AWS EC2 sandbox instance lifecycle management (startup, shutdown, watchdog timeout protection, socket health checks).
  - AWS Lambda invocations, S3 object lifecycle and path schema governance, and IAM principle of least privilege enforcement.
  - Full-stack business logic, visitor session auth, atomic credit deduction against race conditions/overspending, payment integration, and defensive security measures (Cloudflare Turnstile, rate limiting, IDOR prevention).

#### ❌ Out-of-Scope (Core Engine Algorithm & Internal Functional Optimization)
- **Static Analysis Engine Internals (`android-static`)**:
  - Evaluation rules across the 80 MAST criteria, Androguard decompilation pipelines, and packer/shell signature detection logic.
- **Dynamic Sandbox Exploration & Hooking Internals (`android-detection-system`)**:
  - Frida hooking scripts (`Code.js`) decision rules, UI exploration state machines (`CmdServer.py`), and automated fuzzing heuristics.
- **PDF Generator Internal Layout & Design (`pdf-generator`)**:
  - Security audit report typesetting, styling, font rendering algorithms, and statutory compliance document formatting.

> **Seam Discipline**: Strictly avoid altering the core detection rules, heuristic algorithms, or internal layout engines. However, all architectural adapters, S3/AWS integration, API wrapping, lifecycle orchestration, and cloud hardening required to connect these engines into the platform remain strictly **in-scope**.

### 3. Production Code & Engine Protection Guardrails
- **Production Code Freeze**: All existing, deployed code operating on AWS EC2, S3, or Lambda represents a frozen baseline. Agents must never refactor, delete, or rewrite existing production endpoints, database schemas, or cloud adapters unless explicitly requested by the user.
- **Engine Interface Immutability**: All communication contracts bridging the platform to the engines (JSON schemas, S3 path keys, Lambda invocation payload signatures, and CLI exit codes) are strictly immutable. Any modification must maintain 100% backward compatibility.
- **Pre-Flight Blast Radius Verification**: Before proposing or committing any code changes that touch shared adapters, storage logic, or credentials, agents must execute the regression test suite (`npm run test:unit`) to prove zero regression.

### 4. AWS Credential Governance
- **AWS CLI Authentication Standard**:
  - Local development and automated operations must exclusively rely on the **AWS CLI Default Credential Provider Chain** (`~/.aws/credentials` / local IAM profile) rather than hardcoded static access keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) in `.env` files.
  - `.env` files must strictly manage resource identifiers and regions (`AWS_REGION`, `S3_BUCKET`) without embedding sensitive access keys.
  - Deprecate standalone static local IAM accounts (such as `cmaa-local-admin`) in favor of centralized AWS CLI profiles.

## Development & Review Workflow
- **Authoring Focus**: Focus on delivering working, testable implementations conforming to the originating issue or specification (Red-Green phase).
- **Standards & Review**: Detailed coding standards, deep module principles, anti-tautological test rules, and smell criteria are governed separately in `CODING_STANDARDS.md` and enforced during the review phase (`/code-review`).
- **Context Guardrail**: **Do not proactively read `CODING_STANDARDS.md` during implementation.** It will be loaded automatically during the review phase.
- **Worktree Isolation SOP**: When implementing new features, modifying API endpoints, or performing parallel verification on `Cloud-Mobile-App-Analysis`, agents must use the `/worktree` skill (`ops/worktree_spawn.ps1` and `ops/worktree_clean.ps1`) to avoid SQLite WAL locks (`SQLITE_BUSY`) and port collisions.
- **Branch & Pull Request Discipline**:
  - **No Direct Push/Merge to Main**: Agents are strictly forbidden from directly pushing or merging changes into the `main` branch. All features, refactoring, and fixes must be developed on a dedicated branch and submitted via GitHub Pull Request (`gh pr create` or web PR), requiring GitHub Actions CI green checks before merging.
- **Package Manifest & Lockfile Synchronization**:
  - **Never Blindly Overwrite `package.json`**: Agents must NEVER overwrite `package.json` with `write_file`. Use surgical edits (`edit_file`) only.
  - **Strict Lockfile Parity**: Any dependency change (add, remove, bump) in `package.json` must be immediately followed by `npm install --package-lock-only` to keep `package-lock.json` 100% in sync, preventing GitHub Actions CI `npm ci` failures (`EUSAGE`).
- **Patch & Artifact Hygiene**:
  - Never commit temporary `.patch` or `.diff` files into the repository. Branches and PRs must be used for sharing work-in-progress across workspaces.
- **Engine Deployment & Cloud Sync**: When deploying static analysis updates or syncing code to AWS, never push blindly. Always run pre-flight diff inspection and validation first (`python ops/compare_aws_static.py` or use `/deploy-static`). See `docs/SOP_ANDROID_STATIC_DEPLOYMENT.md`.
