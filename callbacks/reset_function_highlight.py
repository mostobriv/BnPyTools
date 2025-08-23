import binaryninja
from binaryninja import FunctionGraphType
from binaryninjaui import UIActionContext

from .bnplugintools import PyToolsUIAction, get_action_manager
from ..core import utils


class ResetFunctionHighlight(PyToolsUIAction):
	display_name = "Reset function highlight"
	description = "Reset highlight of all blocks and instructions in function"
	desired_hotkey = ""

	def __init__(self):
		super().__init__()

	def activate(self, context: UIActionContext):
		bv: binaryninja.BinaryView = context.binaryView

		function = utils.get_current_il_function(context)
		with bv.undoable_transaction():
			for block in function.basic_blocks:
				block.set_user_highlight(binaryninja.HighlightStandardColor.NoHighlightColor)
				# for ins in block:
				# 	function.set_user_instr_highlight(
				# 		ins.address, binaryninja.HighlightStandardColor.NoHighlightColor
				# 	)

	@PyToolsUIAction.do_basic_context_checks
	def is_valid(self, context: UIActionContext):
		return True


get_action_manager().register(ResetFunctionHighlight())
