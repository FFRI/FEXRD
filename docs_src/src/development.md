# Development

## Required

- Python 3.12
- Poetry

To install dependencies, execute `poetry install --with dev`.
If you need to edit the documentation as well, use `poetry install --with dev,docs`.

Next, install the Git hook scripts by running `poetry run pre-commit install`. This command will activate the pre-commit hook during git commit.

To execute tests, use `poetry run pytest`.

For editing the documentation, modify the markdown files located in docs_src and then execute `poetry run mkdocs build` from within the docs_src directory.
