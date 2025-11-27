from binaryninja import *
from typing import Any


def _get_rva(instance: PythonScriptingInstance) -> int | None:
	if not instance.interpreter.active_view:
		return None
	binary_view = instance.interpreter.active_view
	return binary_view.offset - binary_view.start


def _set_rva(instance: PythonScriptingInstance, old_value: int | None, new_value: Any):
	if instance.interpreter.active_view is None:
		return

	if isinstance(new_value, str):
		raise NotImplementedError
		# new_value = instance.interpreter.active_view.parse_expression(
		# 	new_value,
		# 	instance.interpreter.active_addr
		# )

	if (vt := type(new_value)) is not int:
		raise TypeError(f"RVA can't be assigned with value of type: {vt.__qualname__}")

	if not instance.interpreter.active_view.file.navigate(
		instance.interpreter.active_view.file.view,
		instance.interpreter.active_view.start + new_value,
	):
		mainthread.execute_on_main_thread(
			lambda: instance.interpreter.locals["current_ui_context"].navigateForBinaryView(
				instance.interpreter.active_view,
				instance.interpreter.active_view.start + new_value,
			)
		)


PythonScriptingProvider.register_magic_variable(
	"rva",
	get_value=_get_rva,
	set_value=_set_rva,
	depends_on=["current_ui_context"],
)
