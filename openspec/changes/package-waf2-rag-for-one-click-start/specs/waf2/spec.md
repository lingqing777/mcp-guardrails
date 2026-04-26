## ADDED Requirements

### Requirement: WAF2 image must include runnable RAG assets
The WAF2 Docker image MUST contain all runtime files required for RAG request enrichment.

#### Scenario: Fresh clone + one-click startup
- **WHEN** a teammate runs `./start.sh` (or `start.bat`) on a fresh environment
- **THEN** `docker-compose up -d --build` produces a WAF2 container with RAG runtime assets available
- **AND** `/waf2/rag/info` reports RAG enabled with non-zero knowledge base size
- **AND** the WAF2 request pipeline can inject RAG evidence into the ReAct/COT request-analysis prompt

### Requirement: One-click startup behavior must be reproducible across teammates
RAG availability MUST NOT depend on developer-local untracked files.

#### Scenario: Team member B reproduces environment from git + docker build
- **WHEN** teammate B pulls latest `master` and rebuilds WAF2 image
- **THEN** WAF2 RAG behavior is functionally equivalent to teammate A's environment
- **AND** no manual post-start copy into container is required

### Requirement: RAG confidence gate must preserve useful evidence for ReAct
The default RAG confidence gate MUST allow moderately similar evidence into ReAct/COT reasoning when the vector retriever already passed its retrieval threshold.

#### Scenario: ReAct evidence review uses RAG context
- **WHEN** WAF2 starts with default RAG configuration
- **THEN** `RAG_CONFIDENCE_THRESHOLD` defaults to `0.50`
- **AND** RAG results above the retriever threshold are not prematurely removed before ReAct evidence review
