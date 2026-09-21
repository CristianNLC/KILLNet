import sys
import os

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
