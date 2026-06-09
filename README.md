# depwise

dependency health scanner — no account, no api key, no config

```
$ depwise scan ~/netbox-test

depwise — dependency health scanner

  dir      ~/netbox-test
  reading  requirements.txt, pyproject.toml

  scanning 45 packages...

  Django@6.0.5   high  5 CVEs  fix: 5.2.15
    An issue was discovered in Django 6.0 before 6.0.6 and 5.2 before 5.2.15
    PYSEC-2026-200, PYSEC-2026-198 +3 more

  colorama@0.4.6   abandoned
    No updates in 3 years

  django-graphiql-debug-toolbar@0.2.0   abandoned
    No updates in 4 years

  1 vulnerable, 2 abandoned, 42 ok

  to fix:
    pip install Django==5.2.15
```

that's a real scan of [NetBox](https://github.com/netbox-community/netbox) — used in production by NVIDIA, Cloudflare, and thousands of others.

## the problem with existing tools

`pip-audit` and `npm audit` exist. but:

- they audit the wrong environment when you're inside a venv
- they show 40 CVEs with no context — developers learn to ignore them
- they don't know if a package is abandoned (no CVE required to be dangerous)
- they're single-language — mixed projects need multiple tools

depwise fixes all of this.

## install

```bash
pip install depheal
```

no account. no api key. no config file. works immediately.

## usage

```bash
# scan current directory
depwise

# scan any directory from anywhere
depwise scan ./myproject
depwise scan ~/anyproject

# explain a specific package
depwise why requests
depwise why flask --version 2.2.0

# list all packages found
depwise list

# use in CI/CD — exits with code 1 if issues found
depwise scan --strict
```

works with:
- `requirements.txt`
- `pyproject.toml`
- `package.json`

## what makes it different

**detects abandoned packages** — a package with no CVE but no maintainer is still a risk. depwise checks last commit dates and deprecation notices. existing tools don't.

**right environment** — automatically detects your active venv and scans that. pip-audit scans the wrong python when you're inside a venv.

**one output** — python and javascript in the same project, one scan, one report.

**zero noise** — shows what matters. one line per package. plain english.

**zero dependencies** — pure python stdlib. nothing to break. works everywhere python works.

## how it works

- reads your dependency files
- detects your active virtual environment automatically
- queries [OSV](https://osv.dev) for known CVEs — free, no key needed
- checks PyPI and npm registry for abandoned/deprecated packages
- shows you what matters, not everything

## license

MIT
