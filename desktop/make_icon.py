"""Genera desktop/assets/app.ico a partir de desktop/assets/logo-dentro.png.

Ese icono se usa en el .exe (escritorio) y en la ventana (barra de tareas).
Uso:  pip install pillow && python desktop/make_icon.py
"""

from pathlib import Path

from PIL import Image


ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "desktop" / "assets" / "logo-dentro.png"
TARGET = ROOT / "desktop" / "assets" / "app.ico"
SIZES = [(16, 16), (20, 20), (24, 24), (32, 32), (40, 40), (48, 48), (64, 64), (128, 128), (256, 256)]


def main() -> None:
    image = Image.open(SOURCE).convert("RGBA")
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    image.save(TARGET, format="ICO", sizes=SIZES)
    print(f"Icono generado: {TARGET}")


if __name__ == "__main__":
    main()
