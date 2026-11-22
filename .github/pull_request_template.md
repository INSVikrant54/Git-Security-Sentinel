## Summary

<!-- What changes, and why? Link the issue if one exists. -->

## Type of change

- [ ] Bug fix
- [ ] New detection rule
- [ ] CLI / developer experience
- [ ] Output format
- [ ] Documentation
- [ ] CI / packaging

## Testing

<!-- Paste the commands you ran and their result. -->

```bash
python -m unittest discover -s tests -p "test_*.py"
git scan --all --no-color
```

## Checklist

- [ ] Tests added or updated for the change
- [ ] Documentation updated (README / SKILL.md / CHANGELOG)
- [ ] No new runtime dependencies (standard library only)
- [ ] No real secrets, tokens, or personal data in code, tests, or fixtures
- [ ] Self-scan is clean (`git scan --all`)
- [ ] Backwards compatibility preserved (existing flags and exit codes)
