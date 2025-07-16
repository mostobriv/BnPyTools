import binaryninja

from .actions import PyToolsPluginCommand, bn_action_manager

import subprocess
import platform
import os


class OpenFileLocation(PyToolsPluginCommand):
    full_name = "Open file location"
    description = "Open file location in os-explorer"
    desired_hotkey = ""
    type = binaryninja.PluginCommandType.DefaultPluginCommand

    def __init__(self):
        super().__init__()

    def activate(self, bv):
        path = bv.file.filename
        if not os.path.isabs(path):
            print("For some reason path of file isn't in absolute format, can't open it")
            print("path: %s" % path)
            return
        
        subprocess.run(["open", "-R", os.path.dirname(path)])

    def is_valid(self, bv):
        # TODO: add support for other platforms?
        return platform.system() == "Darwin"


bn_action_manager.register(OpenFileLocation())