# hostveil Python Prototype

This directory contains the Python CLI prototype for `hostveil`.

- Purpose: preserve the validated reference behavior for Compose parsing, rules, scoring, and fix flows.
- Status: frozen reference implementation; new product work should happen in `src/` unless a task explicitly says otherwise.
- Scope: prototype only; not intended for end-user distribution.
- Entry point: `python -m hostveil scan path/to/docker-compose.yml`
