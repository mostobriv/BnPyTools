import binaryninja
from binaryninja import HighLevelILInstruction, HighLevelILOperation
from binaryninjaui import UIActionContext, UIActionHandler, HighlightTokenState

from .bnplugintools import PyToolsUIAction, get_action_manager
from ..core import utils


class ShowOutgoingFunctionCalls(PyToolsUIAction):
	display_name = "Show outgoing calls"
	description = "Scrap and show function calls outgoing from the current function"
	desired_hotkey = ""

	def __init__(self):
		super().__init__()

	def activate(self, context: UIActionContext):
		bv: binaryninja.BinaryView = context.binaryView
		il_func = utils.get_current_il_function(context)

		def is_call_expression(expr: HighLevelILInstruction) -> HighLevelILInstruction | None:
			match expr.operation:
				case HighLevelILOperation.HLIL_CALL:
					return expr

				case HighLevelILOperation.HLIL_TAILCALL:
					return expr

				case _:
					return

		for expr in il_func.traverse(is_call_expression):
			print(f"{expr.address:#x}: {expr}")

	@PyToolsUIAction.do_basic_context_checks
	def is_valid(self, context: UIActionContext):
		return utils.get_current_il_function(context) is not None


get_action_manager().register(ShowOutgoingFunctionCalls())
