```text
░▒▓█ SECGATE · CONTRIBUTING █▓▒░
```

# Contributing to SecGate

Thanks for your interest. SecGate is a security engine — contributions that improve detection fidelity, reduce false positives, or extend CI integration are especially welcome.

## Ground rules

- Be respectful — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Report security issues privately — see [SECURITY.md](SECURITY.md). Never open a public issue for a vulnerability.
- Open an issue before large changes so we can align on scope.

## Development setup

```bash
git clone https://github.com/Stelnyx/SecGate.git
cd SecGate
npm install
node secgate.js --help
```

## Pull request checklist

- [ ] Branch name describes the change (`feat/<slug>`, `fix/<slug>`, `docs/<slug>`)
- [ ] Commit messages follow Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:`, `refactor:`, `test:`)
- [ ] New detectors or remediations include a short test fixture
- [ ] No secrets, tokens, or real scan artifacts committed
- [ ] README updated if CLI flags or output shape changed

## Releases

SecGate publishes through npm trusted publishing from GitHub Actions. Do not
store `NPM_TOKEN` / `NODE_AUTH_TOKEN` secrets for release publishing, and do not
publish from a local machine with a `--provenance=false` workaround.

Trusted Publisher settings on npmjs.com for `@stelnyx/secgate`:

- Publisher: GitHub Actions
- Organization/user: `Stelnyx`
- Repository: `secgate`
- Workflow filename: `publish.yml`
- Environment: leave blank
- Allowed action: `npm publish`

The repository must remain public for npm to show provenance. The package's
`repository` field must keep matching the GitHub repository exactly.

Release flow:

1. Bump `package.json` and `package-lock.json` to the next semver version.
2. Run `npm ls @stelnyx/report-theme` and confirm it shows `0.1.4` without a
   local `-> ../report-theme` symlink.
3. Run `npm run check:deps`, `npm test`, `npm run lint`, and `npm pack --dry-run`.
   The dependency guard fails publish if any `file:`, `link:`, `workspace:`,
   `resolved: "../..."`, or `link: true` dependency entry is present.
4. Confirm `npm pack --dry-run` includes `CHANGELOG.md`.
5. Commit the version bump and push `main`.
6. Create and push a matching tag, for example `git tag v0.2.15 && git push origin v0.2.15`.
7. Create a GitHub Release from that tag.
8. Confirm the `Publish` workflow runs green.
9. Confirm the new npm version shows provenance, then run `npm audit signatures`.

## Commit message format

```
<type>(<scope>): <short description>

<optional body explaining why, not what>
```

Types: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`, `security`, `perf`.

## Questions

Open a [discussion](https://github.com/Stelnyx/SecGate/discussions) or a regular issue. Security matters go through private advisory only.
