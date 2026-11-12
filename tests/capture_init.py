"""Run the real Tutor CLI, capturing rendered tasks instead of starting Docker.

A separate process preserves Tutor's normal plugin-loading context.
"""

import json
from unittest.mock import patch

from tutor.commands.cli import main
from tutor.commands.compose import ComposeTaskRunner


def capture_task(self, service, command):
    print("TASK:" + json.dumps([service, command]))
    return 0


if __name__ == "__main__":
    with patch.object(ComposeTaskRunner, "run_task", capture_task):
        main()
