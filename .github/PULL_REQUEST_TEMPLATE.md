## Summary

<!-- What does this change do, and why? Link related issues with "Fixes #123". -->

## Type of change

- [ ] Bug fix
- [ ] New capability
- [ ] Documentation
- [ ] Refactor or test-only change
- [ ] Packaging or CI

## Checklist

- [ ] `./scripts/test.sh` passes locally.
- [ ] `node scripts/check-web.js` passes when web assets or docs changed.
- [ ] New user-visible strings are in English by default and have a Chinese
      translation in `src/lsec/web/i18n.js`.
- [ ] Docs are updated, with a `.zh-CN.md` counterpart for long-lived documents.
- [ ] `CHANGELOG.md` and `CHANGELOG.zh-CN.md` are updated for user-visible changes.
- [ ] No tokens, private keys, host data, or scan evidence are included.
- [ ] The change does not add automatic remediation, auto-installation, or any
      capability the README lists as unsupported.

## Testing

<!-- Commands run and their results. -->
