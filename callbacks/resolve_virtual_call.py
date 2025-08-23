import binaryninja
from binaryninja import HighLevelILOperation
import binaryninjaui

from .bnplugintools import PyToolsUIAction, get_action_manager

from ..core import virtualtable
from ..core import utils

import re


def is_function_pointer_type(t: binaryninja.Type) -> bool:
	assert isinstance(t, binaryninja.Type)
	if not isinstance(t, binaryninja.types.PointerType):
		return False

	return isinstance(t.target, binaryninja.types.FunctionType)


# 1 - get the name and try to extract suffix with address
# 2 - else query the metadata storage
class ResolveVirtualCall(PyToolsUIAction):
	display_name = "Resolve virtual call"
	description = "Trying to resolve virtual call and jump to callee address"
	desired_hotkey = "Shift+F"

	def __init__(self):
		super().__init__()

	def activate(self, context):
		token_state = context.token
		bv = context.binaryView

		expr_index = token_state.token.il_expr_index
		expr = context.highLevelILFunction.get_expr(expr_index)

		match expr.operation:
			case HighLevelILOperation.HLIL_DEREF_FIELD:
				if not is_function_pointer_type(expr.expr_type):
					print("Expression isn't a function pointer type")
					return

				vtable_candidate_type = expr.src
				vtable_type_name = vtable_candidate_type.expr_type.target.registered_name.name.name[
					0
				]
				vtable_address = virtualtable.extract_address_from_name(vtable_type_name)
				if vtable_address is None:
					# TODO: make the fallback to the second mechanic of address extraction
					self.logger.log_warn(
						"Failed to find address-suffix of %s" % (repr(vtable_type_name))
					)
					return

				member_function_offset = expr.offset
				target_address = bv.read_pointer(vtable_address + member_function_offset)
				assert bv.get_function_at(target_address) is not None, (
					"Failed to get function at the address: %#x" % (target_address)
				)
				bv.offset = target_address

			case HighLevelILOperation.HLIL_STRUCT_FIELD:
				raise NotImplementedError

			case _:
				raise ValueError("How did we get here?")

	@PyToolsUIAction.do_basic_context_checks
	def is_valid(self, context):
		if not isinstance(context.widget, binaryninjaui.LinearView):
			return False

		token_state = context.token

		if not token_state.focused:
			return False

		if (
			utils.get_il_view_type(context)
			!= binaryninja.FunctionGraphType.HighLevelILFunctionGraph
		):
			return False

		expr_index = token_state.token.il_expr_index
		# There is realy no named const for this, just uint64(-1)
		if expr_index == 0xFFFFFFFFFFFFFFFF:
			return False

		expr = context.highLevelILFunction.get_expr(expr_index)

		return expr.operation in (
			HighLevelILOperation.HLIL_DEREF_FIELD,
			HighLevelILOperation.HLIL_STRUCT_FIELD,
		)


get_action_manager().register(ResolveVirtualCall())
