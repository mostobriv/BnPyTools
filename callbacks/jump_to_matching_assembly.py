import binaryninja
from binaryninja import FunctionGraphType
from binaryninjaui import UIActionContext, UIActionHandler, HighlightTokenState

from .bnplugintools import PyToolsUIAction, get_action_manager
from ..core import utils


class JumpToMatchingAssembly(PyToolsUIAction):
	display_name = "Jump to matching assembly"
	description = "Jump to matching assembly"
	desired_hotkey = "J"

	def __init__(self):
		super().__init__()

	def activate(self, context: UIActionContext):
		bv: binaryninja.BinaryView = context.binaryView

		token_state: HighlightTokenState = context.token
		if token_state is None:
			return

		if token_state.tokenIndex == 0xFFFFFFFF:
			return

		token: binaryninja.InstructionTextToken = token_state.token
		il_expr_index: int = token.il_expr_index
		il_expr: binaryninja.ILInstructionType | None = utils.get_current_il_function(
			context
		).get_expr(il_expr_index)

		if il_expr is None:
			self.logger.log_info("No il expression selected")
			return

		view = context.view
		if not view.viewType().startswith("Linear:") and not view.viewType().startwsith("Graph:"):
			return

		ah = UIActionHandler().actionHandlerFromWidget(view.widget())

		def switch_to_disassembly():
			ah.executeAction("Toggle Disassembly View")
			bv.offset = il_expr.address

		binaryninja.execute_on_main_thread(switch_to_disassembly)

	@PyToolsUIAction.do_basic_context_checks
	def is_valid(self, context: UIActionContext):
		return utils.get_current_il_function(context) is not None


get_action_manager().register(JumpToMatchingAssembly())
