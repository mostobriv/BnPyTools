import binaryninja
import binaryninjaui
from binaryninja import SymbolType, SymbolBinding

from PySide6.QtWidgets import (
	QVBoxLayout,
	QHBoxLayout,
	QTableView,
	QPushButton,
	QDialog,
	QHeaderView,
	QAbstractItemView,
	QStyledItemDelegate,
)
from PySide6.QtCore import QAbstractTableModel, QSortFilterProxyModel, QModelIndex, Qt
from PySide6.QtGui import QKeySequence, QShortcut

from ..core.PyQtTemplateCollection.widgets import ChooseDialog

from .bnplugintools import PyToolsUIAction, get_action_manager

import itertools
import dataclasses


@dataclasses.dataclass
class ExportedEntity:
	full_name: str
	address: int
	size: int


def gather_exported_entities(bv: binaryninja.BinaryView) -> list[ExportedEntity]:
	exports = list()
	function_symbols = bv.get_symbols_of_type(SymbolType.FunctionSymbol)
	data_symbols = bv.get_symbols_of_type(SymbolType.DataSymbol)

	for sym in itertools.chain(function_symbols, data_symbols):
		if sym.binding not in (SymbolBinding.GlobalBinding, SymbolBinding.WeakBinding):
			continue

		match sym.type:
			case SymbolType.FunctionSymbol:
				exports.append(
					ExportedEntity(sym.full_name, sym.address, size_of_function_at(bv, sym.address))
				)

			case SymbolType.DataSymbol:
				exports.append(
					ExportedEntity(
						sym.full_name, sym.address, bv.get_data_var_at(sym.address).type.width
					)
				)

			case _:
				raise NotImplementedError

	return exports


def size_of_function(function: binaryninja.Function) -> int:
	return sum([bb.end - bb.start for bb in function.basic_blocks])


def size_of_function_at(bv: binaryninja.BinaryView, address: int) -> int:
	return size_of_function(bv.get_function_at(address))


class ShowExports(PyToolsUIAction):
	display_name = "Show exports"
	description = "Show exported symbols"
	desired_hotkey = "Ctrl+Meta+E"

	def __init__(self):
		super().__init__()

	def activate(self, context):
		bv = context.binaryView or context.context.getCurrentView().getData()

		exports = gather_exported_entities(bv)

		chooser = ChooseDialog(
			"Exported symbols",
			["Name", "Address", "Size"],
			[(e.full_name, e.address, e.size) for e in exports],
			parent=context.context.getCurrentView().widget(),
		)

		def on_choice(index: int):
			bv.offset = chooser.data[index][1]

		chooser.chosen.connect(on_choice)

		chooser.show()
		chooser.activateWindow()

	def is_valid(self, context):
		if context is None or context.context is None:
			return False

		if context.binaryView is None:
			return False

		return True


get_action_manager().register(ShowExports())
