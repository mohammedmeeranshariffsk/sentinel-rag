# SentinelRAG Project State

## Current Day

Day 1

## Current Phase

Project Foundation

## Current Milestone

Create the initial project structure and CLI.

## Completed

- [x] Repository created
- [x] Python environment created
- [x] Project structure created
- [x] APKContext created
- [x] APK SHA256 implemented
- [x] Workspace manager implemented
- [x] APK inspection tests added
- [x] Real APK inspection verified with AndroGoat

## Currently Working On

- [ ] CLI integration

## Next

- [ ] Create `sentinel inspect`
- [ ] Add CLI → APKInspector integration
- [ ] Add human-readable inspection output
- [ ] Add APK metadata extraction

## Known Issues

None

## Next

- [ ] APKContext
- [ ] APK SHA256
- [ ] Workspace manager
- [ ] `sentinel inspect`

## Known Issues

None

## Architectural Decisions

- Build from scratch
- Prototype first
- Five initial vulnerability classes
- Deterministic detection before LLM reasoning
- Evidence required for every finding
- RAG provides security knowledge, not vulnerability proof
- LLM is not the primary static analyzer

## Out of Scope for Week 1

- Full call graph
- Full taint analysis
- Dynamic analysis
- 50 vulnerability rules
- Production dashboard
- Kubernetes
- Multi-agent architecture