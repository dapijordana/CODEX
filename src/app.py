"""Minimalist portable UI for encrypting and decrypting files or folders."""
from __future__ import annotations

import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from PIL import Image, ImageTk

from crypto_core import ALG_MAP, decrypt_path, encrypt_path, is_encrypted

THEME_BG = "#f8f8f8"
THEME_FG = "#111111"
ACCENT = "#1f1f1f"


class EncryptorApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title("Portable Cipher Studio")
        self.configure(background=THEME_BG)
        self.geometry("720x560")
        self.resizable(False, False)

        self.selected_path: Optional[str] = None
        self.image_preview: Optional[ImageTk.PhotoImage] = None

        self.style = ttk.Style(self)
        self._configure_styles()

        self._build_layout()

    # ------------------ UI helpers ------------------
    def _configure_styles(self) -> None:
        self.style.theme_use("clam")
        self.style.configure(
            "TLabel",
            background=THEME_BG,
            foreground=THEME_FG,
            font=("Inter", 11),
        )
        self.style.configure(
            "TButton",
            font=("Inter", 11),
            padding=8,
            background="#e0e0e0",
            relief="flat",
        )
        self.style.map("TButton", background=[("active", "#d0d0d0")])
        self.style.configure("Card.TFrame", background="white", relief="flat")
        self.style.configure("TEntry", padding=6, relief="flat", font=("Inter", 11))
        self.style.configure("TRadiobutton", background=THEME_BG, foreground=THEME_FG, font=("Inter", 11))
        self.style.configure("TCombobox", padding=6, relief="flat", font=("Inter", 11))

    def _build_layout(self) -> None:
        top_frame = ttk.Frame(self, style="Card.TFrame")
        top_frame.place(x=30, y=30, width=660, height=320)

        self.preview_label = ttk.Label(top_frame, text="Preview file akan tampil di sini", anchor="center")
        self.preview_label.place(relx=0.5, rely=0.5, anchor="center")

        controls = ttk.Frame(self, style="Card.TFrame")
        controls.place(x=30, y=370, width=660, height=160)

        # Password row
        pw_label = ttk.Label(controls, text="Password")
        pw_label.grid(row=0, column=0, sticky="w", padx=(20, 8), pady=(16, 8))

        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(controls, textvariable=self.password_var, show="*")
        self.password_entry.grid(row=0, column=1, padx=(0, 8), pady=(16, 8), sticky="ew")

        self.toggle_state = tk.BooleanVar(value=False)
        toggle = ttk.Checkbutton(
            controls,
            text="Tampilkan",
            variable=self.toggle_state,
            command=self._toggle_password,
            style="TRadiobutton",
        )
        toggle.grid(row=0, column=2, padx=(0, 20), pady=(16, 8))

        # File chooser row
        choose_btn = ttk.Button(controls, text="Choose file/folder", command=self._open_path_dialog)
        choose_btn.grid(row=1, column=0, padx=(20, 8), pady=8, sticky="w")

        self.path_label = ttk.Label(controls, text="Belum ada berkas dipilih")
        self.path_label.grid(row=1, column=1, columnspan=2, padx=(0, 20), pady=8, sticky="w")

        # Mode row
        mode_frame = ttk.Frame(controls, style="Card.TFrame")
        mode_frame.grid(row=2, column=0, columnspan=2, padx=(20, 8), pady=8, sticky="w")
        self.mode_var = tk.StringVar(value="encrypt")
        ttk.Radiobutton(mode_frame, text="Enkripsi", value="encrypt", variable=self.mode_var, style="TRadiobutton").pack(side="left", padx=(0, 12))
        ttk.Radiobutton(mode_frame, text="Dekripsi", value="decrypt", variable=self.mode_var, style="TRadiobutton").pack(side="left")

        algo_label = ttk.Label(controls, text="Algoritma")
        algo_label.grid(row=2, column=2, padx=(0, 8), pady=8, sticky="e")
        self.algorithm_var = tk.StringVar(value="AES-256-GCM")
        algo_box = ttk.Combobox(controls, textvariable=self.algorithm_var, state="readonly", values=list(ALG_MAP.keys()))
        algo_box.grid(row=2, column=3, padx=(0, 20), pady=8, sticky="ew")

        go_btn = tk.Button(
            controls,
            text="GO",
            font=("Inter", 14, "bold"),
            bg=ACCENT,
            fg="white",
            activebackground="#444",
            activeforeground="white",
            relief="flat",
            command=self._execute,
            width=6,
            height=2,
        )
        go_btn.grid(row=0, column=3, padx=(0, 20), pady=12, sticky="e")

        self.status_var = tk.StringVar(value="Siap.")
        status = ttk.Label(controls, textvariable=self.status_var, foreground="#555")
        status.grid(row=3, column=0, columnspan=4, padx=20, pady=(12, 8), sticky="w")

        controls.columnconfigure(1, weight=1)
        controls.columnconfigure(3, weight=1)

    # ------------------ Actions ------------------
    def _toggle_password(self) -> None:
        self.password_entry.config(show="" if self.toggle_state.get() else "*")

    def _open_path_dialog(self) -> None:
        menu = tk.Menu(self, tearoff=0)
        menu.add_command(label="Pilih file", command=self._choose_file)
        menu.add_command(label="Pilih folder", command=self._choose_folder)
        try:
            menu.tk_popup(self.winfo_rootx() + 60, self.winfo_rooty() + 360)
        finally:
            menu.grab_release()

    def _choose_file(self) -> None:
        path = filedialog.askopenfilename()
        if not path:
            return
        self._after_path_selected(path)

    def _choose_folder(self) -> None:
        path = filedialog.askdirectory()
        if not path:
            return
        self._after_path_selected(path)

    def _after_path_selected(self, path: str) -> None:
        self.selected_path = path
        encrypted = is_encrypted(path)
        if encrypted:
            self.mode_var.set("decrypt")
            self.status_var.set("File terenkripsi terdeteksi, siap dekripsi.")
        else:
            self.mode_var.set("encrypt")
            self.status_var.set("Siap enkripsi.")
        self.path_label.config(text=path)
        self._render_preview(path)

    def _render_preview(self, path: str) -> None:
        if os.path.isdir(path):
            self.preview_label.config(text=f"Folder: {os.path.basename(path)}", image="")
            self.preview_label.image = None
            return

        lower = path.lower()
        if lower.endswith((".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp")):
            try:
                img = Image.open(path)
                img.thumbnail((620, 280))
                self.image_preview = ImageTk.PhotoImage(img)
                self.preview_label.config(image=self.image_preview, text="")
            except Exception:  # noqa: BLE001
                self.preview_label.config(text="Tidak dapat menampilkan preview gambar", image="")
                self.preview_label.image = None
            return

        # Text preview fallback
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as fh:
                snippet = fh.read(1200)
            snippet = snippet.strip() or "Berkas teks kosong"
            self.preview_label.config(text=snippet[:1200], justify="left", wraplength=620, image="")
            self.preview_label.image = None
        except Exception:
            self.preview_label.config(text="Preview tidak tersedia untuk tipe berkas ini", image="")
            self.preview_label.image = None

    def _validate_inputs(self) -> bool:
        if not self.selected_path:
            messagebox.showwarning("Pilih path", "Silakan pilih file atau folder terlebih dahulu.")
            return False
        if not self.password_var.get():
            messagebox.showwarning("Password kosong", "Password wajib diisi untuk enkripsi/dekripsi.")
            return False
        return True

    def _execute(self) -> None:
        if not self._validate_inputs():
            return
        mode = self.mode_var.get()
        try:
            if mode == "encrypt":
                out_path = encrypt_path(self.selected_path, self.password_var.get(), self.algorithm_var.get())
                self.status_var.set(f"Selesai enkripsi → {out_path}")
                messagebox.showinfo("Berhasil", f"Berkas disimpan sebagai {out_path}")
            else:
                out_path = decrypt_path(self.selected_path, self.password_var.get())
                self.status_var.set(f"Selesai dekripsi → {out_path}")
                messagebox.showinfo("Berhasil", f"Hasil dekripsi: {out_path}")
        except Exception as exc:  # noqa: BLE001
            messagebox.showerror("Gagal", str(exc))
            self.status_var.set("Terjadi kesalahan. Coba lagi.")


def main() -> None:
    app = EncryptorApp()
    app.mainloop()


if __name__ == "__main__":
    main()
