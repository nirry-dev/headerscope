# Contributing to headerscope

Thanks for taking a look. headerscope is small on purpose — fetch a URL, grade
its headers — and the aim is for the grades to be fair and the advice correct.

## Good contributions

A check that's wrong (a header graded too harshly or too kindly), a missing
header worth checking, or clearer fix-it advice. A real response that headerscope
scores wrong, with the headers and the grade you'd expect.

## Ground rules

- **Standard library only.** No runtime dependencies. Tests use `unittest`.
- **Every change comes with a test.** Each check is a small function tested with
  synthetic headers (`tests/test_audit.py`); the fetch path is tested against a
  local server that returns chosen headers (`tests/test_fetch.py`), so the suite
  needs no network.
- **Advice, not dogma.** A "warn" should be genuinely worth doing, and a "fail"
  should be a real hole. Keep the grading defensible.

## Running the tests

```bash
python -m unittest discover -s tests -t .
```

No install needed — the tests import the package from the repo root.

## Scope

In: response-header hygiene. Out: crawling, fuzzing, application testing, and full
CSP analysis — see "What it is not" in the README. Security reports go to
**info@nirry.net** — see [SECURITY.md](SECURITY.md).
