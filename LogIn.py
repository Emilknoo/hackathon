import hashlib
import os
import sqlite3
import tkinter as tk
from tkinter import messagebox
from pathlib import Path

DB_PATH = Path(__file__).with_name("usuarios.db")
ITERATIONS = 310_000


def conectar():
    con = sqlite3.connect(DB_PATH)
    con.execute("""
        CREATE TABLE IF NOT EXISTS usuarios (
            nombre TEXT PRIMARY KEY COLLATE NOCASE,
            salt BLOB NOT NULL,
            clave_hash BLOB NOT NULL
        )
    """)
    return con


def registrar():
    nombre = usuario_var.get().strip()
    clave = clave_var.get()

    if not nombre:
        messagebox.showwarning("Falta el usuario", "Escribe un nombre de usuario.")
        return

    if len(clave) < 8:
        messagebox.showwarning(
            "Contraseña corta",
            "La contraseña debe tener al menos 8 caracteres."
        )
        return

    salt = os.urandom(16)
    clave_hash = hashlib.pbkdf2_hmac(
        "sha256", clave.encode("utf-8"), salt, ITERATIONS
    )

    try:
        with conectar() as con:
            con.execute(
                "INSERT INTO usuarios (nombre, salt, clave_hash) VALUES (?, ?, ?)",
                (nombre, salt, clave_hash),
            )
        clave_var.set("")
        messagebox.showinfo(
            "Cuenta creada",
            "Ya puedes iniciar sesión con tu cuenta."
        )
    except sqlite3.IntegrityError:
        messagebox.showerror(
            "Usuario existente",
            "Ese nombre de usuario ya está registrado."
        )


def iniciar_sesion():
    nombre = usuario_var.get().strip()
    clave = clave_var.get()

    with conectar() as con:
        fila = con.execute(
            "SELECT salt, clave_hash FROM usuarios WHERE nombre = ?",
            (nombre,)
        ).fetchone()

    if fila:
        salt, hash_guardado = fila
        hash_ingresado = hashlib.pbkdf2_hmac(
            "sha256", clave.encode("utf-8"), salt, ITERATIONS
        )

        if hashlib.compare_digest(hash_ingresado, hash_guardado):
            clave_var.set("")
            messagebox.showinfo(
                "Bienvenido",
                f"¡Hola, {nombre}! Has iniciado sesión."
            )
            return

    messagebox.showerror(
        "No se pudo entrar",
        "Usuario o contraseña incorrectos."
    )


ventana = tk.Tk()
ventana.title("Mi login")
ventana.geometry("380x360")
ventana.resizable(False, False)
ventana.configure(bg="#f2f5f9")

usuario_var = tk.StringVar()
clave_var = tk.StringVar()

contenedor = tk.Frame(ventana, bg="white", padx=32, pady=28)
contenedor.pack(expand=True, padx=28, pady=24, fill="both")

tk.Label(
    contenedor,
    text="¡Qué bueno verte!",
    font=("Segoe UI", 20, "bold"),
    bg="white",
    fg="#172033"
).pack(anchor="w")

tk.Label(
    contenedor,
    text="Inicia sesión o crea una cuenta",
    font=("Segoe UI", 10),
    bg="white",
    fg="#687386"
).pack(anchor="w", pady=(4, 22))

tk.Label(
    contenedor,
    text="Usuario",
    font=("Segoe UI", 10, "bold"),
    bg="white",
    fg="#293449"
).pack(anchor="w")

usuario_entry = tk.Entry(
    contenedor,
    textvariable=usuario_var,
    font=("Segoe UI", 11),
    relief="solid",
    bd=1
)
usuario_entry.pack(fill="x", ipady=7, pady=(6, 14))

tk.Label(
    contenedor,
    text="Contraseña",
    font=("Segoe UI", 10, "bold"),
    bg="white",
    fg="#293449"
).pack(anchor="w")

clave_entry = tk.Entry(
    contenedor,
    textvariable=clave_var,
    show="●",
    font=("Segoe UI", 11),
    relief="solid",
    bd=1
)
clave_entry.pack(fill="x", ipady=7, pady=(6, 20))

botones = tk.Frame(contenedor, bg="white")
botones.pack(fill="x")

tk.Button(
    botones,
    text="Iniciar sesión",
    command=iniciar_sesion,
    bg="#4263eb",
    fg="white",
    activebackground="#3451c6",
    activeforeground="white",
    relief="flat",
    font=("Segoe UI", 10, "bold"),
    cursor="hand2",
    pady=9
).pack(fill="x")

tk.Button(
    botones,
    text="Crear cuenta",
    command=registrar,
    bg="white",
    fg="#4263eb",
    activebackground="#eef1ff",
    relief="flat",
    font=("Segoe UI", 10),
    cursor="hand2",
    pady=9
).pack(fill="x", pady=(5, 0))

ventana.bind("<Return>", lambda evento: iniciar_sesion())
usuario_entry.focus_set()
ventana.mainloop()

