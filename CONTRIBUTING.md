# Contributing

Thanks for contributing to claims.

## Setup

1. Fork and clone the repository.
2. `go mod download`
3. `go test ./...`

## Pull requests

- Run `go fmt ./...` and `go vet ./...`.
- Add tests for `claims` and `jwtkit` changes.
- Update `docs/` when APIs or JWT behavior changes.
- Do not commit secrets or test keys.

## Changelog

Note changes under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).
