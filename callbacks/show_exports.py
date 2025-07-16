import binaryninja
import binaryninjaui
from binaryninja import SymbolType, SymbolBinding

from PySide6.QtWidgets import (
        QVBoxLayout, QHBoxLayout, QTableView,
        QPushButton, QDialog, QHeaderView,
        QAbstractItemView, QStyledItemDelegate
)
from PySide6.QtCore import QAbstractTableModel, QSortFilterProxyModel, QModelIndex, Qt
from PySide6.QtGui import (
    QKeySequence, QShortcut
)

from ..core.PyQtTemplateCollection.widgets.search_bar import SearchBarWidget

from .actions import PyToolsUIAction, bn_action_manager

import itertools


def gather_exported_symbols(bv: binaryninja.BinaryView):
        exports = list()
        function_symbols = bv.get_symbols_of_type(SymbolType.FunctionSymbol)
        data_symbols = bv.get_symbols_of_type(SymbolType.DataSymbol)

        for sym in itertools.chain(function_symbols, data_symbols):
            if sym.binding in (SymbolBinding.GlobalBinding, SymbolBinding.WeakBinding):
                exports.append(sym)

        return exports

class HexDelegate(QStyledItemDelegate):
    def __init__(self, size_hint=8):
        super().__init__()
        self.size = size_hint

    def displayText(self, value, locale):
        if self.size == 4:
            return "%#8.8x" % value
        elif self.size == 8:
            return "%#16.16x" % value
        else:
            return "%#x" % value

class MyTableModel(QAbstractTableModel):
    def __init__(self, data, header_data: tuple = ("Name", "Address")):
        super().__init__()
        self._data = data
        self._header_data = header_data

    def rowCount(self, parent):
        return len(self._data)

    def columnCount(self, parent):
        return len(self._header_data)

    def data(self, index, role):
        if role == Qt.DisplayRole:
            return self._data[index.row()][index.column()]

    def headerData(self, section, orientation, role):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return self._header_data[section]

class ExportedSymbols(QDialog):
    def __init__(self, context, parent=None):
        super().__init__(parent)

        self.context = context
        self.binary_view = context.binaryView or context.context.getCurrentView().getData()
        assert isinstance(self.binary_view, binaryninja.BinaryView), "Can't extract binary view object"

        self.setWindowTitle('Exported symbols')
        self.resize(650, 350)
        self.setWindowModality(Qt.ApplicationModal)

        body_layout = QVBoxLayout()

        symbols = gather_exported_symbols(self.binary_view)
        data = [(sym.full_name, sym.address) for sym in symbols]
        self.model = QSortFilterProxyModel()
        self.model.setSourceModel(MyTableModel(data))

        self.table_view = QTableView()
        self.table_view.horizontalHeader().setStretchLastSection(True)
        self.table_view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table_view.setItemDelegateForColumn(1, HexDelegate(size_hint=self.binary_view.arch.address_size))
        self.table_view.setSortingEnabled(True)
        self.table_view.setModel(self.model)

        if len(data) > 0:
            self.table_view.selectRow(0)

        self.table_view.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table_view.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        self.table_view.horizontalHeader().setStretchLastSection(False)

        self.table_view.doubleClicked.connect(self.on_cell_doubleclicked)

        footer_layout = QHBoxLayout()

        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setDefault(False)
        self.cancel_button.clicked.connect(self.close)

        self.ok_button = QPushButton("OK")
        self.ok_button.setDefault(True)
        self.ok_button.setFocus()
        self.ok_button.clicked.connect(self.ok_clicked)

        footer_layout.addWidget(self.cancel_button)
        footer_layout.addWidget(self.ok_button)

        search_bar = SearchBarWidget()
        search_bar.hide()

        self.model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        search_bar.line_edit.textChanged.connect(self.model.setFilterFixedString)

        shortcut = QShortcut(QKeySequence("Ctrl+F"), self)

        def on_shortcut_presset():
            search_bar.show()
            search_bar.line_edit.setFocus()

        shortcut.activated.connect(on_shortcut_presset)

        body_layout.addWidget(self.table_view)
        body_layout.addWidget(search_bar)
        body_layout.setSpacing(0)

        layout = QVBoxLayout()
        layout.addLayout(body_layout)
        layout.addLayout(footer_layout)

        self.setLayout(layout)

    def ok_clicked(self, checked: bool):
        selection_model = self.table_view.selectionModel()
        assert selection_model.hasSelection(), "How is this even possible, nothing is selected!"

        indeces = selection_model.selectedRows()
        assert len(indeces) == 1, "Multiple rows selected"

        index = self.table_view.model().mapToSource(indeces[0])
        self.process_index(index)
        self.close()


    def on_cell_doubleclicked(self, index: QModelIndex):
        index = self.table_view.model().mapToSource(index)
        self.process_index(index)
        self.close()

    def process_index(self, index: QModelIndex):
        row = index.row()
        name, address = self.model.sourceModel()._data[row]
        self.binary_view.offset = address


class ShowExports(PyToolsUIAction):
    full_name = "Show exports"
    description = "Show exported symbols"
    desired_hotkey = "Ctrl+Meta+E"

    def __init__(self):
        super().__init__()

    def activate(self, context):
        if context is None or context.context is None:
            return

        exports = ExportedSymbols(context, parent=context.context.getCurrentView().widget())
        exports.show()
        exports.activateWindow()


    def is_valid(self, context):
        return True


bn_action_manager.register(ShowExports())