"""Allow running the tool as ``python -m jwt_tool``."""

from jwt_tool.cli import main

raise SystemExit(main())
