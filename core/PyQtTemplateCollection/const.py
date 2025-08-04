from PySide6.QtGui import QColor

import os


ICONS_DIRECTORY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "icons"
)

class Color:
    White:      QColor = QColor(255, 255, 255)
    Black:      QColor = QColor(0, 0, 0)
    Gray:       QColor = QColor(127, 127, 127)
    Red:        QColor = QColor(255, 0, 0)
    Green:      QColor = QColor(0, 255, 0)
    Blue:       QColor = QColor(0, 0, 255)
    Cyan:       QColor = QColor(0, 255, 255)
    Yellow:     QColor = QColor(255, 255, 0)
    Magenta:    QColor = QColor(255, 0, 255)