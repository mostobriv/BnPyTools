#from PySide6.QtWidgets import ()
from PySide6.QtGui import QIcon, QPixmap, QColor
from PySide6.QtCore import Qt

from .const import Color

__all__ = [
    "get_colored_icon"
]

def get_colored_icon(icon_path: str, color: QColor) -> QIcon:
    pixmap = QPixmap(icon_path)
    mask = pixmap.createMaskFromColor(Color.Black, Qt.MaskInColor)
    pixmap.fill(color)
    pixmap.setMask(mask)
    return QIcon(pixmap)