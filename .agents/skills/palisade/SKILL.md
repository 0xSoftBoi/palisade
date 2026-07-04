```markdown
# palisade Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the core development patterns and conventions used in the `palisade` Python codebase. You'll learn about file organization, import/export styles, commit message practices, and how to approach testing—even in the absence of a formal workflow system or framework. This guide will help you contribute code that fits seamlessly with the existing repository standards.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `data_processor.py`, `user_utils.py`

### Import Style
- Use **relative imports** within the package.
  - Example:
    ```python
    from .utils import parse_config
    from .models import User
    ```

### Export Style
- Use **named exports** (i.e., explicitly define what is exported).
  - Example:
    ```python
    __all__ = ['User', 'parse_config']
    ```

### Commit Messages
- Freeform commit messages, no enforced prefixes.
- Average commit message length: ~62 characters.
  - Example:  
    ```
    Fix bug in data processing when input is empty
    ```

## Workflows

_No automated workflows detected in this repository._

## Testing Patterns

- **Framework:** Unknown (not detected)
- **Test File Pattern:** Files named with the `.test.ts` suffix (suggests some TypeScript testing, possibly for a frontend or integration).
  - Example: `user_service.test.ts`
- **Note:** No Python testing framework detected. If adding tests, consider using `pytest` and naming test files as `test_*.py`.

## Commands

| Command      | Purpose                                 |
|--------------|-----------------------------------------|
| /format      | Format code according to conventions    |
| /test        | Run all test files                      |
| /lint        | Lint code for style and import issues   |
| /commit      | Commit changes with a descriptive message|
```
