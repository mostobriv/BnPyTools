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


def gather_exported_symbols(bv: binaryninja.BinaryView):
	exports = list()
	function_symbols = bv.get_symbols_of_type(SymbolType.FunctionSymbol)
	data_symbols = bv.get_symbols_of_type(SymbolType.DataSymbol)

	for sym in itertools.chain(function_symbols, data_symbols):
		if sym.binding in (SymbolBinding.GlobalBinding, SymbolBinding.WeakBinding):
			exports.append(sym)

	return exports


class ShowExports(PyToolsUIAction):
	display_name = "Show exports"
	description = "Show exported symbols"
	desired_hotkey = "Ctrl+Meta+E"

	def __init__(self):
		super().__init__()

	def activate(self, context):
		bv = context.binaryView or context.context.getCurrentView().getData()

		symbols = gather_exported_symbols(bv)

		chooser = ChooseDialog(
			"Exported symbols",
			["Name", "Address"],
			[(sym.full_name, sym.address) for sym in symbols],
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
