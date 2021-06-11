# Copyright (C) 2016 Cuckoo Foundation.
# This file is part of Cuckoo Sandbox - http://www.cuckoosandbox.org
# See the file 'docs/LICENSE' for copying permission.

import logging

from lib.common.abstracts import Package

log = logging.getLogger(__name__)

class Reboot(Package):
    """Reboot analysis package."""
    PATHS = [
        ("System32", "rundll32.exe"),
    ]
    def _handle_create_process(self, filepath, command_line, source):
        if filepath == "rundll32.exe":
            filepath = self.get_path("rundll32.exe")
        if not isinstance(command_line, list):
            command_line = [command_line]
        pid = self.execute(filepath, command_line)
        self.pids.append(pid)

    def start(self, path):
        for category, args in self.analyzer.reboot:
            if not hasattr(self, "_handle_%s" % category):
                log.warning("Unhandled reboot command: %s", category)
                continue

            getattr(self, "_handle_%s" % category)(*args)
        return self.pids
