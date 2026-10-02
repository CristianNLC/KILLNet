import sys
import os
import ctypes

try:
    myappid = "killsystem.killnet.forensics.1.0"
    ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
except Exception:
    pass

# Asegurar que el directorio raíz de KILLNet esté en sys.path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from ui.main_window import KILLNetMainWindow

def main():
    app = KILLNetMainWindow()
    app.mainloop()

if __name__ == "__main__":
    main()
