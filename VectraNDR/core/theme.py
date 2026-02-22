import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import END

def add_theme_switcher(parent, style):
    """
    Add Darkly/Lumen theme switcher buttons to the parent widget.
    Accepts a ttk.Style instance.
    """
    frame = ttk.Frame(parent)
    frame.pack(fill="x", padx=10, pady=5, anchor="e")

    darkly = ttk.Label(frame, text="Darkly", cursor="hand2", bootstyle="primary")
    darkly.pack(side="right", padx=5)
    darkly.bind("<Button-1>", lambda e: style.theme_use("darkly"))

    lumen = ttk.Label(frame, text="Lumen", cursor="hand2", bootstyle="primary")
    lumen.pack(side="right", padx=5)
    lumen.bind("<Button-1>", lambda e: style.theme_use("lumen"))

def main():
    root = ttk.Window(themename="darkly")
    root.title("Code by alReaperz")
    style = ttk.Style("darkly")

    # Add theme switcher
    add_theme_switcher(root, style)

    # Main Code below

    root.mainloop()

if __name__ == "__main__":
    main()
