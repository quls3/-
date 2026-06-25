import base64
import hashlib
import hmac
import json
import os
import secrets
import string
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog

# Файл создается рядом с программой. Если его удалить, программа начнет работу заново.
DATA_FILE = "passwords_data.json"

# Категории нужны просто для удобства, чтобы записи не были одним большим списком.
CATEGORIES = ["Личное", "Учеба", "Работа", "Почта", "Другое"]

# Небольшая строка для проверки мастер-пароля. Сам пароль в файл не записывается.
CHECK_TEXT = b"gudkov_password_manager_check"


def b64_encode(data):
    """Перевожу байты в обычную строку, чтобы их можно было положить в JSON."""
    return base64.b64encode(data).decode("utf-8")


def b64_decode(text):
    """Обратное действие для b64_encode."""
    return base64.b64decode(text.encode("utf-8"))


def make_key(master_password, salt):
    # Из мастер-пароля делается ключ. Соль нужна, чтобы одинаковые пароли не давали один результат.
    return hashlib.pbkdf2_hmac(
        "sha256",
        master_password.encode("utf-8"),
        salt,
        120000,
        dklen=32,
    )


def make_check_hash(key):
    # По этому значению программа понимает, правильно ли введен мастер-пароль.
    return hmac.new(key, CHECK_TEXT, hashlib.sha256).hexdigest()


def make_stream(key, nonce, size):
    # Это учебное преобразование текста. В реальных менеджерах паролей лучше использовать готовые библиотеки.
    result = bytearray()
    counter = 0
    while len(result) < size:
        block = hashlib.sha256(key + nonce + counter.to_bytes(4, "big")).digest()
        result.extend(block)
        counter += 1
    return bytes(result[:size])


def crypt_bytes(data, key, nonce):
    stream = make_stream(key, nonce, len(data))
    return bytes(a ^ b for a, b in zip(data, stream))


def encrypt_text(text, key):
    data = text.encode("utf-8")
    nonce = os.urandom(16)
    encrypted = crypt_bytes(data, key, nonce)
    tag = hmac.new(key, nonce + encrypted, hashlib.sha256).digest()[:16]
    return b64_encode(nonce + tag + encrypted)


def decrypt_text(text, key):
    raw = b64_decode(text)
    nonce = raw[:16]
    saved_tag = raw[16:32]
    encrypted = raw[32:]
    real_tag = hmac.new(key, nonce + encrypted, hashlib.sha256).digest()[:16]

    if not hmac.compare_digest(saved_tag, real_tag):
        raise ValueError("Данные повреждены или мастер-пароль неверный")

    decrypted = crypt_bytes(encrypted, key, nonce)
    return decrypted.decode("utf-8")


def load_json_file():
    with open(DATA_FILE, "r", encoding="utf-8") as file:
        return json.load(file)


def save_json_file(data):
    with open(DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=4)


def create_empty_storage(master_password):
    salt = os.urandom(16)
    key = make_key(master_password, salt)
    storage = {
        "salt": b64_encode(salt),
        "check_hash": make_check_hash(key),
        "next_id": 1,
        "items": [],
    }
    save_json_file(storage)
    return key, storage


def open_storage(root):
    # Сначала хотел сделать без мастер-пароля, но тогда JSON легко открыть блокнотом.
    if not os.path.exists(DATA_FILE):
        password = simpledialog.askstring(
            "Первый запуск",
            "Придумайте мастер-пароль:",
            parent=root,
            show="*",
        )
        if not password:
            return None, None

        repeat = simpledialog.askstring(
            "Первый запуск",
            "Повторите мастер-пароль:",
            parent=root,
            show="*",
        )
        if password != repeat:
            messagebox.showerror("Ошибка", "Пароли не совпали")
            return None, None
        if len(password) < 4:
            messagebox.showerror("Ошибка", "Мастер-пароль должен быть не короче 4 символов")
            return None, None

        return create_empty_storage(password)

    password = simpledialog.askstring(
        "Вход",
        "Введите мастер-пароль:",
        parent=root,
        show="*",
    )
    if not password:
        return None, None

    try:
        storage = load_json_file()
        salt = b64_decode(storage["salt"])
        key = make_key(password, salt)
        if not hmac.compare_digest(storage["check_hash"], make_check_hash(key)):
            messagebox.showerror("Ошибка", "Неверный мастер-пароль")
            return None, None
        return key, storage
    except Exception as error:
        messagebox.showerror("Ошибка", f"Не получилось открыть файл с данными:\n{error}")
        return None, None


class PasswordManagerApp:
    def __init__(self, root, key, storage):
        self.root = root
        self.key = key
        self.storage = storage
        self.items = []
        self.selected_id = None

        self.root.title("Менеджер паролей")
        self.root.geometry("820x520")
        self.root.resizable(False, False)

        self.load_items()
        self.make_window()
        self.refresh_table()

    def load_items(self):
        # В памяти записи уже обычные, чтобы с ними было проще работать.
        self.items = []
        for row in self.storage.get("items", []):
            try:
                self.items.append(
                    {
                        "id": row["id"],
                        "site": decrypt_text(row["site"], self.key),
                        "login": decrypt_text(row["login"], self.key),
                        "password": decrypt_text(row["password"], self.key),
                        "category": decrypt_text(row["category"], self.key),
                        "note": decrypt_text(row["note"], self.key),
                    }
                )
            except Exception:
                # Если одна запись испортилась, программа не должна падать целиком.
                pass

    def save_file(self):
        encrypted_items = []
        for item in self.items:
            encrypted_items.append(
                {
                    "id": item["id"],
                    "site": encrypt_text(item["site"], self.key),
                    "login": encrypt_text(item["login"], self.key),
                    "password": encrypt_text(item["password"], self.key),
                    "category": encrypt_text(item["category"], self.key),
                    "note": encrypt_text(item["note"], self.key),
                }
            )
        self.storage["items"] = encrypted_items
        save_json_file(self.storage)

    def make_window(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill="both", expand=True)

        top = ttk.Frame(main)
        top.pack(fill="x")

        title = ttk.Label(top, text="Менеджер паролей", font=("Arial", 17, "bold"))
        title.pack(side="left")

        ttk.Label(top, text="Поиск:").pack(side="left", padx=(250, 5))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(top, textvariable=self.search_var, width=24)
        search_entry.pack(side="left")
        search_entry.bind("<KeyRelease>", self.search_key_pressed)

        body = ttk.Frame(main)
        body.pack(fill="both", expand=True, pady=12)

        table_part = ttk.Frame(body)
        table_part.pack(side="left", fill="both", expand=True)

        columns = ("site", "login", "category")
        self.table = ttk.Treeview(table_part, columns=columns, show="headings", height=17)
        self.table.heading("site", text="Сайт / сервис")
        self.table.heading("login", text="Логин")
        self.table.heading("category", text="Категория")
        self.table.column("site", width=230)
        self.table.column("login", width=190)
        self.table.column("category", width=120)
        self.table.pack(side="left", fill="both", expand=True)
        self.table.bind("<<TreeviewSelect>>", self.select_from_table)

        scroll = ttk.Scrollbar(table_part, orient="vertical", command=self.table.yview)
        scroll.pack(side="right", fill="y")
        self.table.configure(yscrollcommand=scroll.set)

        form = ttk.LabelFrame(body, text="Запись", padding=10)
        form.pack(side="right", fill="y", padx=(12, 0))

        ttk.Label(form, text="Сайт / сервис").pack(anchor="w")
        self.site_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.site_var, width=31).pack(fill="x", pady=(2, 8))

        ttk.Label(form, text="Логин").pack(anchor="w")
        self.login_var = tk.StringVar()
        ttk.Entry(form, textvariable=self.login_var, width=31).pack(fill="x", pady=(2, 8))

        ttk.Label(form, text="Пароль").pack(anchor="w")
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(form, textvariable=self.password_var, width=31, show="*")
        self.password_entry.pack(fill="x", pady=(2, 5))

        self.password_is_open = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            form,
            text="показать пароль",
            variable=self.password_is_open,
            command=self.show_hide_password,
        ).pack(anchor="w", pady=(0, 8))

        ttk.Label(form, text="Категория").pack(anchor="w")
        self.category_var = tk.StringVar(value="Личное")
        ttk.Combobox(form, textvariable=self.category_var, values=CATEGORIES, state="readonly", width=28).pack(
            fill="x", pady=(2, 8)
        )

        ttk.Label(form, text="Заметка").pack(anchor="w")
        self.note_text = tk.Text(form, width=30, height=5, font=("Arial", 10))
        self.note_text.pack(fill="x", pady=(2, 8))

        ttk.Button(form, text="Сгенерировать пароль", command=self.make_password).pack(fill="x", pady=2)
        ttk.Button(form, text="Копировать пароль", command=self.copy_password).pack(fill="x", pady=2)
        ttk.Button(form, text="Добавить", command=self.add_item).pack(fill="x", pady=(10, 2))
        ttk.Button(form, text="Сохранить изменения", command=self.save_item).pack(fill="x", pady=2)
        ttk.Button(form, text="Удалить", command=self.delete_item).pack(fill="x", pady=2)
        ttk.Button(form, text="Очистить поля", command=self.clear_form).pack(fill="x", pady=2)

    def search_key_pressed(self, event=None):
        self.refresh_table()

    def filtered_items(self):
        query = self.search_var.get().strip().lower()
        if not query:
            return self.items

        result = []
        for item in self.items:
            # Для поиска беру несколько полей. Так проще найти запись, если забыл точное название сайта.
            line = f"{item['site']} {item['login']} {item['category']}".lower()
            if query in line:
                result.append(item)
        return result

    def refresh_table(self):
        # Treeview сам старые строки не убирает, поэтому сначала очищаю таблицу.
        for row in self.table.get_children():
            self.table.delete(row)

        for item in self.filtered_items():
            self.table.insert(
                "",
                "end",
                iid=str(item["id"]),
                values=(item["site"], item["login"], item["category"]),
            )

    def find_item(self, item_id):
        for item in self.items:
            if item["id"] == item_id:
                return item
        return None

    def select_from_table(self, event=None):
        selected = self.table.selection()
        if not selected:
            return

        self.selected_id = int(selected[0])
        item = self.find_item(self.selected_id)
        if item is None:
            return

        self.site_var.set(item["site"])
        self.login_var.set(item["login"])
        self.password_var.set(item["password"])
        self.category_var.set(item["category"])
        self.note_text.delete("1.0", "end")
        self.note_text.insert("1.0", item["note"])

    def check_form(self):
        site = self.site_var.get().strip()
        login = self.login_var.get().strip()
        password = self.password_var.get().strip()
        if not site or not login or not password:
            messagebox.showwarning("Ошибка", "Заполните сайт, логин и пароль")
            return None

        return {
            "site": site,
            "login": login,
            "password": password,
            "category": self.category_var.get().strip() or "Другое",
            "note": self.note_text.get("1.0", "end").strip(),
        }

    def add_item(self):
        data = self.check_form()
        if data is None:
            return

        data["id"] = self.storage.get("next_id", 1)
        self.storage["next_id"] = data["id"] + 1
        self.items.append(data)
        self.save_file()
        self.refresh_table()
        self.clear_form()
        messagebox.showinfo("Готово", "Запись добавлена")

    def save_item(self):
        if self.selected_id is None:
            messagebox.showwarning("Ошибка", "Сначала выберите запись в таблице")
            return

        data = self.check_form()
        if data is None:
            return

        item = self.find_item(self.selected_id)
        if item is not None:
            item.update(data)
            self.save_file()
            self.refresh_table()
            messagebox.showinfo("Готово", "Изменения сохранены")

    def delete_item(self):
        if self.selected_id is None:
            messagebox.showwarning("Ошибка", "Сначала выберите запись в таблице")
            return

        item = self.find_item(self.selected_id)
        if item is None:
            return

        answer = messagebox.askyesno("Удаление", f"Удалить запись '{item['site']}'?")
        if answer:
            self.items.remove(item)
            self.selected_id = None
            self.save_file()
            self.refresh_table()
            self.clear_form()

    def clear_form(self):
        self.selected_id = None
        self.table.selection_remove(self.table.selection())
        self.site_var.set("")
        self.login_var.set("")
        self.password_var.set("")
        self.category_var.set("Личное")
        self.note_text.delete("1.0", "end")

    def make_password(self):
        alphabet = string.ascii_letters + string.digits + "!@#$%&*?"
        password = "".join(secrets.choice(alphabet) for _ in range(14))
        self.password_var.set(password)

    def show_hide_password(self):
        if self.password_is_open.get():
            self.password_entry.configure(show="")
        else:
            self.password_entry.configure(show="*")

    def copy_password(self):
        password = self.password_var.get().strip()
        if not password:
            messagebox.showwarning("Ошибка", "В поле пароля пусто")
            return

        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Готово", "Пароль скопирован")


if __name__ == "__main__":
    window = tk.Tk()
    window.withdraw()

    user_key, user_storage = open_storage(window)
    if user_key is None:
        window.destroy()
    else:
        window.deiconify()
        PasswordManagerApp(window, user_key, user_storage)
        window.mainloop()
