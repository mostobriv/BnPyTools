from binaryninjaui import LinearView  # type: ignore
import binaryninja
from binaryninja import InstructionTextTokenType, BackgroundTaskThread, Type

from .bnplugintools import PyToolsUIAction, get_action_manager


class ConstFliperTask(BackgroundTaskThread):
	def __init__(self, bv: binaryninja.BinaryView, variables: list[binaryninja.Variable]):
		BackgroundTaskThread.__init__(self, "Running", True)
		self.bv: binaryninja.BinaryView = bv
		self.variables = variables

	def run(self):
		with self.bv.undoable_transaction():
			for var in self.variables:
				mut_t = var.type.mutable_copy()
				mut_t.const = False if mut_t.const else True
				var.type = mut_t.immutable_copy()

		self.bv.update_analysis_and_wait()


class Constantine(PyToolsUIAction):
	display_name = "Toggle constancy"
	description = "Toggle constancy of the data variable"
	desired_hotkey = "Shift+C"

	def __init__(self):
		super().__init__()

	def activate(self, context):
		token_state = context.token
		binary_view = context.binaryView

		if not token_state.focused:
			raise NotImplementedError("Can't handle not-focused cases")

		match token_state.type:
			case InstructionTextTokenType.DataSymbolToken:
				token = token_state.token
				var_addr = token.value
				var = binary_view.get_data_var_at(var_addr)
				assert var is not None and var.type != Type.void(), (
					"Failed to get data variable at %#x" % (var_addr)
				)

				task = ConstFliperTask(binary_view, [var])
				task.start()

			case InstructionTextTokenType.LocalVariableToken:
				if not token_state.localVarValid:
					raise RuntimeError(
						"LocalVariableToken selected, however localVarValid is False"
					)

				core_var = token_state.localVar
				var = binaryninja.Variable.from_core_variable(context.function, core_var)
				assert var is not None, "Failed to get local variable: %s" % (core_var)

				task = ConstFliperTask(binary_view, [var])
				task.start()

			case InstructionTextTokenType.TextToken:
				if context.function is not None:
					return

				start, end = sorted(context.view.getSelectionOffsets())

				variables = set([binary_view.get_data_var_at(addr) for addr in range(start, end)])

				# assert var is not None and var.type != Type.void(), "Failed to get data variable at %#x" % (context.address)

				task = ConstFliperTask(binary_view, variables)
				task.start()

			case _:
				raise RuntimeError("Idk wtf is this case: %s" % (token_state.type))

		return

	@PyToolsUIAction.do_basic_context_checks
	def is_valid(self, context):
		return isinstance(context.widget, LinearView)


get_action_manager().register(Constantine())
