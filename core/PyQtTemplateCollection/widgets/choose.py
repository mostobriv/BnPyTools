import binaryninjaui
import binaryninja

from typing import Any, Optional

import sys
import os

from PySide6.QtWidgets import (
	QHBoxLayout,
	QWidget,
	QTableView,
	QVBoxLayout,
	QDialog,
	QPushButton,
	QAbstractItemView,
	QHeaderView,
	QStyledItemDelegate,
)
from PySide6.QtGui import (
	QIcon,
	QPixmap,
	QColor,
	QShortcut,
	QKeySequence,
	QStandardItemModel,
	QStandardItem,
)
from PySide6.QtCore import (
	Qt,
	QObject,
	QEvent,
	QAbstractTableModel,
	QSortFilterProxyModel,
	Property,
	Signal,
	Slot,
	QModelIndex,
)

from .search_bar import SearchBarWidget

from dataclasses import dataclass


import enum


class ColumnOpt(enum.IntFlag):
	def __with_base(val):
		return val << 16

	COL_HEX = __with_base(1)


# def populate_model(columns: int, data: list[tuple | str]) -> QStandardItemModel:
# 	model = QStandardItemModel(columns, len(data))

# 	for item in data:
# 		items: list[QStandardItem]
# 		if isinstance(item, str):
# 			assert columns == 1
# 			items = [QStandardItem(item)]
# 		else:
# 			assert len(item) == columns, (
# 				f"Got row {item} of size {len(item)}, when size {columns} expected"
# 			)
# 			items = [QStandardItem(i) for i in item]

# 		model.appendRow(items)

# 	return model


@dataclass
class ColumnHeader:
	options: int
	title: str


class ChooseWidget(QWidget):
	chosen = Signal(int)

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

	class _EmbeddedModel(QAbstractTableModel):
		def __init__(self, data, header_data):
			if data and len(header_data) != len(data[0]):
				raise ValueError(
					f"Number of headers and data items doesn't match, {len(header_data)} headers vs {len(data[0])} data items"
				)

			super().__init__()
			self._data = data
			self._header_data = header_data

		def rowCount(self, parent=QModelIndex()):
			return len(self._data)

		def columnCount(self, parent=QModelIndex()):
			return len(self._header_data)

		def data(self, index, role):
			if role == Qt.DisplayRole:
				return self._data[index.row()][index.column()]

		def headerData(self, section, orientation, role):
			if role == Qt.DisplayRole and orientation == Qt.Horizontal:
				return self._header_data[section]

	def __init__(self, columns: list[str], items: list[tuple | str], parent: QWidget = None):
		super().__init__(parent=parent)

		# inner_model = populate_model(len(columns), items)

		self.model = QSortFilterProxyModel()
		self.model.setSourceModel(self._EmbeddedModel(items, columns))
		# self.model.setSourceModel(inner_model)
		self.model.setFilterCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
		self.model.setDynamicSortFilter(False)

		self._search = SearchBarWidget()
		self._search.line_edit.textChanged.connect(self.model.setFilterFixedString)

		shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
		shortcut.activated.connect(self.on_search_bar_requested)

		self._table_view = QTableView()
		self._table_view.setSelectionMode(QAbstractItemView.SingleSelection)
		self._table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
		# self._table_view.setItemDelegateForColumn(1, self.HexDelegate(size_hint=8))
		self._table_view.setModel(self.model)

		self._table_view.setSortingEnabled(True)
		self._table_view.setModel(self.model)
		self._table_view.sortByColumn(-1, Qt.AscendingOrder)  # doesn't matter which order actually

		# TODO: if multichoice enabled, change this as well
		self._table_view.doubleClicked.connect(
			lambda index: self.chosen.emit(self.get_real_index(index).row())
		)

		if len(items) > 0:
			self._table_view.selectRow(0)

		# FIXME: fix the damn header
		self._table_view.horizontalHeader().resizeSections(QHeaderView.Stretch)
		for i in range(len(columns) - 1):
			self._table_view.horizontalHeader().setSectionResizeMode(i, QHeaderView.Interactive)
		self._table_view.horizontalHeader().setStretchLastSection(True)

		self._table_view.verticalHeader().hide()

		layout = QVBoxLayout()
		layout.setSpacing(0)
		layout.setContentsMargins(0, 0, 0, 0)
		layout.addWidget(self._table_view)
		layout.addWidget(self._search)

		self.setLayout(layout)

	def get_real_index(self, index: QModelIndex) -> QModelIndex:
		return self._table_view.model().mapToSource(index)

	def _get_model_data(self) -> list[Any]:
		# TODO: is it really should be copied explicitly?
		return self._table_view.model().sourceModel()._data[:]

	@Slot()
	def on_search_bar_requested(self):
		self._search.show()
		self._search.line_edit.setFocus()

	# TODO: should I add ability to set data?
	data = Property(list, _get_model_data)


class ChooseDialog(QDialog):
	chosen = Signal(int)

	def __init__(
		self,
		title: str,
		columns: list[str],
		items: Optional[list[Any]] = None,
		modality: Qt.WindowModality = Qt.ApplicationModal,
		parent: QWidget = None,
	):
		super().__init__(parent=parent)

		self._choose = ChooseWidget(columns, items, parent=parent)
		self._choose.chosen.connect(self.chosen)
		self.chosen.connect(self.close)

		self.setWindowTitle(title)
		self.resize(650, 350)
		self.setWindowModality(modality)

		cancel_button = QPushButton("Cancel")
		cancel_button.setDefault(False)
		cancel_button.clicked.connect(self.close)

		search_button = QPushButton("Search")
		search_button.setDefault(False)
		search_button.clicked.connect(self._choose.on_search_bar_requested)

		ok_button = QPushButton("OK")
		ok_button.setDefault(True)
		ok_button.setFocus()
		ok_button.clicked.connect(self._ok_clicked)

		body_layout = QVBoxLayout()
		body_layout.addWidget(self._choose)

		footer_layout = QHBoxLayout()
		footer_layout.addWidget(cancel_button)
		footer_layout.addWidget(search_button)
		footer_layout.addWidget(ok_button)

		layout = QVBoxLayout()
		layout.addLayout(body_layout)
		layout.addLayout(footer_layout)

		self.setLayout(layout)

	def _ok_clicked(self):
		# TODO: instead of accessing _XXX fields, add properties to the ChooseWidget
		selection_model = self._choose._table_view.selectionModel()
		assert selection_model.hasSelection(), "How is this even possible, nothing is selected!"

		# TODO: may be i should extend chooser, so it is will be possible
		# to choose multiple variants at once
		indeces = selection_model.selectedRows()
		if len(indeces) != 1:
			raise NotImplementedError("Multiple choice unsupported")

		index = self._choose.get_real_index(indeces[0])
		self._choose.chosen.emit(index.row())

	def _get_choose_data(self) -> list[Any]:
		return self._choose.data

	data = Property(list, _get_choose_data)
