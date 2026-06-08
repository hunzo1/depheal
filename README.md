# depwise

dependency health scanner — cross-language, offline-first, no account needed

```
depwise scan

  flask        2.2.0   high     fix: 2.3.2   open redirect
  requests     2.25.0  medium   fix: 2.31.0  proxy auth header leak
  request      2.88.2  abandoned              deprecated since 2020

  2 vulnerable, 1 abandoned, 14 ok
```

## why

`npm audit` and `pip-audit` exist. the problems:

- they audit the wrong environment when you're in a venv
- they show 40 CVEs with no explanation of what actually matters
- they don't know if a package is abandoned (no CVE required to be dangerous)
- they're single-language — mixed projects need multiple tools

depwise fixes all of this. one command. any project. any language.

## install

```bash
pip install depwise
```

that's it. no account. no api key. no config file.

## usage

```bash
# scan current directory
depwise

# scan a specific directory  
depwise scan ./myproject

# explain one package
depwise why flask
depwise why requests --version 2.25.0

# list all packages found
depwise list

# use in CI/CD (exits with code 1 if issues found)
depwise scan --strict
```

works with:
- `requirements.txt`
- `pyproject.toml`
- `package.json`

## how it works

- reads your dependency files
- detects your active virtual environment automatically
- queries [OSV](https://osv.dev) for known CVEs (free, no key needed)
- checks PyPI and npm registry for abandoned/deprecated packages
- shows you what matters, not everything

zero external dependencies. pure python stdlib.

## license

MIT
