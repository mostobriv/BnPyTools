import binaryninja
from binaryninja import DeadStoreElimination

from .bnplugintools import PyToolsPluginCommand, get_action_manager

import subprocess
import platform
import os


class SetDeadstoreElimination(PyToolsPluginCommand):
	display_name = "Enable DSE for current function"
	description = "Goes through all HLIL vars and set DSE to enabled"
	desired_hotkey = ""
	type = binaryninja.PluginCommandType.HighLevelILFunctionPluginCommand

	def __init__(self):
		super().__init__()

	def activate(self, bv: binaryninja.BinaryView, hlil: binaryninja.HighLevelILFunction):
		with bv.undoable_transaction():
			for var in hlil.vars:
				var.dead_store_elimination = DeadStoreElimination.AllowDeadStoreElimination

		bv.update_analysis()

	def is_valid(self, bv, hlil):
		return True


get_action_manager().register(SetDeadstoreElimination())
