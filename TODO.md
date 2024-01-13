# TODO

## General project / repo
- [ ] README.md
  - [ ] badges?
- [ ] CONTRIBUTING.md
- [/] releases / tags
- [ ] address code TODOs
- [ ] docstrings (write, review all, autodoc)
- [ ] more logging messages
- [ ] fix `__all__`, check for hooks about it
- [x] add pre-commit
  - [x] pylint -> ruff
  - [x] black -> ruff
  - [x] isort -> ruff
  - [x] mypy
  - [x] conventional commit
  - [x] check if there's a hook/lint to auto-separate typing only imports etc. 
  - [x] other common hooks
  - [ ] check/fix from-package relative imports that should be from sub-modules
- [ ] improve tests
  - [ ] more unit tests on functions/methods
  - [ ] concrete end-to-end test with real test SIP server
- [ ] add github actions
  - [ ] check pre-commit
  - [ ] run tests
  - [ ] check coverage
- [ ] docs
  - [ ] look into RTD 
- [ ] make installable: setup.py / pyproject.toml
- [ ] add to pypi
- [ ] PR/issue template with checklist

## Features
- [ ] handle more than one call at the same time
