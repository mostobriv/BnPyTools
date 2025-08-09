import binaryninja
from binaryninja import BackgroundTaskThread, Type

from .bnplugintools import PyToolsPluginCommand, get_action_manager


class RemoveReturnTypeTask(BackgroundTaskThread):
	def __init__(self, bv: binaryninja.BinaryView, function: binaryninja.Function):
		BackgroundTaskThread.__init__(self, "Running", True)
		self.bv = bv
		self.function = function

	def run(self):
		self.function.return_type = Type.void()
		self.bv.update_analysis_and_wait()


class RemoveReturnType(PyToolsPluginCommand):
	display_name = "Remove return type"
	description = "Remove return type of function"
	desired_hotkey = "V"
	type = binaryninja.PluginCommandType.FunctionPluginCommand

	def __init__(self):
		super().__init__()

	def activate(self, bv, function):
		rtype = function.return_type
		if rtype == Type.void():
			return

		self.logger.log_info("Removing return type of %s" % function.name)

		task = RemoveReturnTypeTask(bv, function)
		task.start()

	def is_valid(self, bv, function):
		return function.return_type != Type.void()


get_action_manager().register(RemoveReturnType())
