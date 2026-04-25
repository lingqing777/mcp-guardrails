## ADDED Requirements

### Requirement: WAF2 image must include runnable RAG assets
The WAF2 Docker image MUST contain all runtime files required for RAG request enrichment.

#### Scenario: Fresh clone + one-click startup
- **WHEN** a teammate runs `./start.sh` (or `start.bat`) on a fresh environment
- **THEN** `docker-compose up -d --build` produces a WAF2 container with RAG runtime assets available
- **AND** `/waf2/rag/info` reports RAG enabled with non-zero knowledge base size

### Requirement: One-click startup behavior must be reproducible across teammates
RAG availability MUST NOT depend on developer-local untracked files.

#### Scenario: Team member B reproduces environment from git + docker build
- **WHEN** teammate B pulls latest `master` and rebuilds WAF2 image
- **THEN** WAF2 RAG behavior is functionally equivalent to teammate A's environment
- **AND** no manual post-start copy into container is required
