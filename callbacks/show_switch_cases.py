import binaryninja
from binaryninja import HighLevelILOperation

from binaryninjaui import UIContext

from .actions import PyToolsPluginCommand, bn_action_manager

from ..core.PyQtTemplateCollection.widgets import ChooseDialog


class ShowSwitchCases(PyToolsPluginCommand):
    full_name = "Show cases of switch"
    description = "Show cases of switch instruction"
    desired_hotkey = ""
    type = binaryninja.PluginCommandType.HighLevelILInstructionPluginCommand

    def __init__(self):
        super().__init__()

    def activate(self, bv, instr):
        current_instr = instr
        while current_instr.operation != HighLevelILOperation.HLIL_SWITCH:
            current_instr = current_instr.parent

            if current_instr is None:
                return

        switch_instr = current_instr

        self.logger.log_debug("Found switch instruction: %s" % (current_instr))

        cases = [(str(case), case.address) for case in switch_instr.cases]

        if (
            default := switch_instr.default
        ).operation != binaryninja.HighLevelILOperation.HLIL_NOP:
            cases.append(("default", default.address))

        chooser = ChooseDialog(
            f"Cases of switch {switch_instr} ({switch_instr.address:#x})",
            ["case", "address"],
            cases,
            parent=UIContext.activeContext().getCurrentView().widget(),
        )

        chooser.data[1][2] = 0x1337

        def goto_case(index):
            bv.offset = chooser.data[index][1]

        chooser.chosen.connect(goto_case)

        chooser.show()
        chooser.activateWindow()

    def is_valid(self, bv, instr):
        if UIContext.activeContext() is None:
            return False
        return True


bn_action_manager.register(ShowSwitchCases())
