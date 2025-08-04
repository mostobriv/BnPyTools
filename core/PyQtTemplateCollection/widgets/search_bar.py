import sys
import os

from PySide6.QtWidgets import QHBoxLayout, QWidget, QLineEdit, QToolButton
from PySide6.QtGui import QIcon, QPixmap, QColor, QShortcut, QKeySequence
from PySide6.QtCore import Qt, QObject, QEvent

from ..utils import get_colored_icon
from ..const import ICONS_DIRECTORY, Color


class SearchBarWidget(QWidget):
    def __init__(
        self,
        parent: QWidget = None,
        hidden: bool = True,
        button_color: QColor = Color.White,
    ):
        super().__init__(parent)

        close_icon = get_colored_icon(
            os.path.join(ICONS_DIRECTORY, "cancel.png"), button_color
        )
        self.close_button = QToolButton()
        self.close_button.setIcon(close_icon)
        self.close_button.clicked.connect(self.close_clicked)
        self.close_button.adjustSize()

        self.line_edit = QLineEdit()
        self.line_edit.installEventFilter(self)

        layout = QHBoxLayout()
        layout.addWidget(self.close_button)
        layout.addWidget(self.line_edit)

        self.setLayout(layout)

        if hidden:
            self.hide()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.line_edit and event.type() == QEvent.Type.KeyPress:
            key_event = event
            if key_event.key() == Qt.Key.Key_Escape:
                watched.clearFocus()
                self.close_clicked()
                return True
        return super().eventFilter(watched, event)

    def close_clicked(self):
        self.line_edit.clear()
        self.close()
