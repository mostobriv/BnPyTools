import binaryninja

from .bnplugintools import PyToolsPluginCommand, get_action_manager

from ..core import virtualtable


class VirtualTableCreator(PyToolsPluginCommand):
	display_name = "Create virtual table"
	description = "Create virtual table at pointed address"
	desired_hotkey = "Shift+V"
	type = binaryninja.PluginCommandType.AddressPluginCommand

	def __init__(self):
		super().__init__()

	def activate(self, bv, address):
		vtable = virtualtable.VirtualTable(bv, address)
		with bv.undoable_transaction():
			bv.define_user_type(vtable.name, vtable.type)
			bv.define_user_data_var(address, vtable.name)

		bv.update_analysis_and_wait()
		self.logger.log_info("Defined %s type" % (vtable.name))

	def is_valid(self, bv, address):
		return True


get_action_manager().register(VirtualTableCreator())
