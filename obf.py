#!/usr/bin/env python3
# multi_obfuscator_with_preview_dnd.py
# Расширенный обфускатор: preview одного метода + drag&drop (tkinterdnd2 fallback)
# Требует Python 3.8+. Для drag&drop рекомендую установить: pip install tkinterdnd2

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import os, re, base64, random, string, ast, textwrap, sys

# Try importing tkinterdnd2 for drag & drop; fallback with informative behavior
HAS_DND = False
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except Exception:
    HAS_DND = False

# -------------------------
# Utility helpers (same as before)
# -------------------------
def detect_lang(path: str) -> str:
    ext = os.path.splitext(path)[1].lower()
    if ext == ".py": return "python"
    if ext == ".ps1": return "powershell"
    if ext in (".js", ".mjs"): return "js"
    if ext == ".exe": return "exe"
    if ext in (".html", ".htm"): return "html"
    if ext in (".css",): return "css"
    return "universal"

def all_same_lang(files):
    langs = {detect_lang(f) for f in files}
    return len(langs) == 1, (list(langs)[0] if langs else "universal")

def gen_name(n=8):
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def read_text(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def write_text(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)

def read_bytes(path):
    with open(path, "rb") as f:
        return f.read()

def write_bytes(path, data: bytes):
    with open(path, "wb") as f:
        f.write(data)

# Basic placeholder string extractor to avoid changing inside strings when doing identifier rename
def extract_string_placeholders(text, lang="generic"):
    literals = []
    def _rep(m):
        literals.append(m.group(0))
        return f"__STR{len(literals)-1}__"
    if lang == "js":
        pattern = r'(`(?:\\`|\\.|[^`])*`)|("(?:\\.|[^"\\])*")|(\'(?:\\.|[^\'\\])*\')'
    else:
        pattern = r'("(?:\\.|[^"\\])*")|(\'(?:\\.|[^\'\\])*\')'
    new = re.sub(pattern, lambda m: _rep(m), text, flags=re.S)
    return new, literals

def restore_string_placeholders(text, literals):
    def _rep(m):
        idx = int(m.group(1))
        return literals[idx]
    return re.sub(r'__STR(\d+)__', _rep, text)

# -------------------------
# Methods implementations (safe educational)
# — many are adapted/simplified from the previously provided large file
# -------------------------
# PYTHON (AST-based safe transforms)
class PyRename(ast.NodeTransformer):
    def __init__(self):
        self.map = {}
    def fresh(self, orig):
        if orig not in self.map:
            self.map[orig] = gen_name(6)
        return self.map[orig]
    def visit_FunctionDef(self, node):
        if not (node.name.startswith("__") and node.name.endswith("__")):
            node.name = self.fresh(node.name)
        self.generic_visit(node)
        return node
    def visit_AsyncFunctionDef(self, node):
        return self.visit_FunctionDef(node)
    def visit_Call(self, node):
        if isinstance(node.func, ast.Name) and node.func.id in self.map:
            node.func.id = self.map[node.func.id]
        self.generic_visit(node)
        return node

def py_rename_functions(text: str) -> str:
    try:
        tree = ast.parse(text)
        tree = PyRename().visit(tree)
        ast.fix_missing_locations(tree)
        return ast.unparse(tree)
    except Exception:
        return text

class PyStringEncryptor(ast.NodeTransformer):
    def __init__(self):
        self.need_helper = False
    def visit_Constant(self, node):
        if isinstance(node.value, str):
            b64 = base64.b64encode(node.value.encode("utf-8")).decode("ascii")
            self.need_helper = True
            return ast.Call(func=ast.Name(id='_d', ctx=ast.Load()), args=[ast.Constant(b64)], keywords=[])
        return node

def py_encrypt_strings(text: str) -> str:
    try:
        tree = ast.parse(text)
        enc = PyStringEncryptor()
        tree = enc.visit(tree)
        ast.fix_missing_locations(tree)
        out = ast.unparse(tree)
        if enc.need_helper and "def _d(" not in out:
            helper = "import base64\n\ndef _d(s):\n    return base64.b64decode(s).decode('utf-8')\n\n"
            out = helper + out
        return out
    except Exception:
        return text

def py_hide_calls(text: str) -> str:
    return re.sub(r'\b([A-Za-z_]\w*)\s*\(', lambda m: f'globals().get("{m.group(1)}", {m.group(1)})(', text)

def py_confuse_flow(text: str) -> str:
    lines = text.splitlines()
    out = []
    for ln in lines:
        out.append(ln)
        if random.random() < 0.06:
            out.extend(["if False:", "    pass"])
    return "\n".join(out)

# POWERSHELL improved text-based
PS_RESERVED = {"if","else","function","foreach","for","return","param","begin","process","end","switch","trap","break"}

def ps_rename_functions(text: str) -> str:
    defs = re.findall(r'(^|\n)\s*function\s+([A-Za-z_]\w*)\b', text, flags=re.I)
    mapping = {}
    for _, name in defs:
        if name.lower() in PS_RESERVED:
            continue
        if name not in mapping:
            mapping[name] = "f_" + gen_name(6)
    if not mapping: return text
    text = re.sub(r'(^|\n)(\s*)function\s+([A-Za-z_]\w*)\b',
                  lambda m: f"{m.group(1)}{m.group(2)}function {mapping.get(m.group(3), m.group(3))}",
                  text, flags=re.I)
    text = re.sub(r'\b([A-Za-z_]\w*)\s*\(', lambda m: f'{mapping.get(m.group(1), m.group(1))}(', text)
    text = re.sub(r'\b([A-Za-z_]\w*)\b(?=\s+\S)', lambda m: mapping.get(m.group(1), m.group(1)), text)
    return text

def ps_encrypt_strings(text: str) -> str:
    def enc(m):
        inner = m.group(2)
        b64 = base64.b64encode(inner.encode("utf-8")).decode("ascii")
        return f'$([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String("{b64}")))' 
    return re.sub(r'([\'"])(.*?)\1', enc, text, flags=re.S)

def ps_hide_calls(text: str) -> str:
    text = re.sub(r'\b([A-Za-z_]\w*)\s*\(', lambda m: f'(&("{m.group(1)}"))(', text)
    text = re.sub(r'(^|[^\S\r\n])([A-Za-z_]\w*)(?=\s+[^\n])', lambda m: f'{m.group(1)}&("{m.group(2)}")', text)
    return text

def ps_confuse_flow(text: str) -> str:
    return text + '\nif ($false) { Write-Verbose "dead-branch" }\n'

# JAVASCRIPT improved
JS_RESERVED = {"window","document","console","Array","Object","Function","Math","String","Number","JSON","let","var","const","function","if","else","return","for","while","switch","case","new","this"}

def js_rename_identifiers(text: str) -> str:
    tmp, lits = extract_string_placeholders(text, lang="js")
    func_defs = re.findall(r'(^|\n)\s*function\s+([A-Za-z_]\w*)\s*\(', tmp)
    var_defs = re.findall(r'\b(?:var|let|const)\s+([A-Za-z_]\w*)', tmp)
    candidates = []
    for _, n in func_defs:
        candidates.append(n)
    for n in var_defs:
        candidates.append(n)
    mapping = {}
    for n in set(candidates):
        if n in JS_RESERVED or n.startswith("__") or n.isupper():
            continue
        mapping[n] = "j_" + gen_name(6)
    if not mapping:
        return text
    def repl_identifiers(s):
        for orig, new in mapping.items():
            s = re.sub(r'(?<![.\[\]\'"\/])\b' + re.escape(orig) + r'\b', new, s)
        return s
    tmp = repl_identifiers(tmp)
    tmp = restore_string_placeholders(tmp, lits)
    return tmp

def js_encrypt_strings(text: str) -> str:
    tmp, lits = extract_string_placeholders(text, lang="js")
    def enc_inner(s):
        b64 = base64.b64encode(s.encode("utf-8")).decode("ascii")
        return f'_d("{b64}")'
    new_tmp = re.sub(r'__STR(\d+)__', lambda m: enc_inner(lits[int(m.group(1))]), tmp)
    helper = ("function _d(s){try{if(typeof atob!=='undefined')return atob(s);}catch(e){}"
              "try{return Buffer.from(s,'base64').toString('utf8');}catch(e){return s;}};\n")
    if "_d(" in new_tmp and "function _d(" not in new_tmp:
        new_tmp = helper + new_tmp
    return new_tmp

def js_hide_calls(text: str) -> str:
    tmp, lits = extract_string_placeholders(text, lang="js")
    tmp = re.sub(r'\b([A-Za-z_]\w*)\s*\(', lambda m: f'globalThis["{m.group(1)}"](', tmp)
    tmp = restore_string_placeholders(tmp, lits)
    return tmp

def js_confuse_flow(text: str) -> str:
    return text + '\nif(false){/*dead-branch*/}\n'

# EXE methods (binary)
def exe_base64(data: bytes, *_args) -> bytes:
    return base64.b64encode(data)

def exe_xor(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return bytes(out)

def exe_shuffle(data: bytes, *_args) -> bytes:
    arr = list(data)
    random.shuffle(arr)
    return bytes(arr)

# HTML/CSS minifiers
def html_minify(text: str) -> str:
    t = re.sub(r'<!--.*?-->', '', text, flags=re.S)
    t = re.sub(r'>\s+<', '><', t)
    t = re.sub(r'\s+', ' ', t)
    return t.strip()

def css_minify(text: str) -> str:
    t = re.sub(r'/\*.*?\*/', '', text, flags=re.S)
    t = re.sub(r'\s+', ' ', t)
    t = re.sub(r'\s*([{}:;,])\s*', r'\1', t)
    return t.strip()

# Universal text methods
def uni_minify(text: str, *_args) -> str:
    return " ".join([ln.strip() for ln in text.splitlines() if ln.strip()])

def uni_base64(text: str, *_args) -> str:
    return base64.b64encode(text.encode("utf-8")).decode("ascii")

def uni_shuffle(text: str, *_args) -> str:
    arr = list(text)
    random.shuffle(arr)
    return "".join(arr)

def uni_xor_text(text: str, key: bytes) -> str:
    if not key:
        return text
    data = text.encode("utf-8")
    out = bytearray(len(data))
    for i, b in enumerate(data):
        out[i] = b ^ key[i % len(key)]
    return base64.b64encode(bytes(out)).decode("ascii")

# -------------------------
# Methods registries
# -------------------------
PYTHON_METHODS = {
    "PY · Переименование функций (AST, бережно)": py_rename_functions,
    "PY · Шифрование строк (base64 + _d)": py_encrypt_strings,
    "PY · Скрыть прямые вызовы (globals().get)": py_hide_calls,
    "PY · Запутать поток (dead-branches)": py_confuse_flow,
}
POWERSHELL_METHODS = {
    "PS · Переименование функций (f_... правило)": ps_rename_functions,
    "PS · Шифрование строк (PS base64 expr)": ps_encrypt_strings,
    "PS · Скрыть прямые вызовы (&(\"name\"))": ps_hide_calls,
    "PS · Запутать поток (dead-branch)": ps_confuse_flow,
}
JS_METHODS = {
    "JS · Переименование идентификаторов (var/let/const/function)": js_rename_identifiers,
    "JS · Шифрование строк (_d / base64)": js_encrypt_strings,
    "JS · Скрыть прямые вызовы (globalThis[...])": js_hide_calls,
    "JS · Запутать поток (dead-branch)": js_confuse_flow,
}
EXE_METHODS = {
    "EXE · Base64 (output text bytes)": exe_base64,
    "EXE · XOR (binary)": exe_xor,
    "EXE · Перемешать байты (destructive)": exe_shuffle,
}
UNIVERSAL_METHODS = {
    "UNI · Минификация": uni_minify,
    "UNI · Base64 (text)": uni_base64,
    "UNI · Перемешивание символов": uni_shuffle,
    "UNI · XOR -> base64": uni_xor_text,
}
LANG_TEXT_METHODS = {
    "python": PYTHON_METHODS,
    "powershell": POWERSHELL_METHODS,
    "js": JS_METHODS,
    "html": {"HTML · Минификация": html_minify},
    "css": {"CSS · Минификация": css_minify},
    "universal": UNIVERSAL_METHODS
}

# A flat list of all methods for preview combobox (name -> (callable, mode))
# mode: "text" or "binary"
ALL_METHODS = {}
for k,v in PYTHON_METHODS.items(): ALL_METHODS[k] = (v, "text")
for k,v in POWERSHELL_METHODS.items(): ALL_METHODS[k] = (v, "text")
for k,v in JS_METHODS.items(): ALL_METHODS[k] = (v, "text")
for k,v in EXE_METHODS.items(): ALL_METHODS[k] = (v, "binary")
for k,v in UNIVERSAL_METHODS.items(): ALL_METHODS[k] = (v, "text")
ALL_METHODS["HTML · Минификация"] = (html_minify, "text")
ALL_METHODS["CSS · Минификация"] = (css_minify, "text")

# -------------------------
# GUI App (with preview & DnD)
# -------------------------
class AppBase:
    """Base layout logic separate for DnD-capable or regular root"""
    def __init__(self, root):
        self.root = root
        self.files = []
        self.output_path = tk.StringVar()
        self.merge_files = tk.BooleanVar(value=False)
        self.process_each = tk.BooleanVar(value=False)
        self.generate_decoder = tk.BooleanVar(value=False)
        self.xor_key_str = tk.StringVar(value="")
        self.vars = {}
        for grp in ("python","powershell","js","exe","html","css","universal"):
            self.vars[grp] = {}
        self._build_ui()
        random.seed()

    def _build_ui(self):
        top = tk.Frame(self.root)
        top.pack(fill="x", padx=8, pady=6)

        btn_files = tk.Button(top, text="Выбрать файлы…", command=self.pick_files)
        btn_files.pack(side="left")
        tk.Checkbutton(top, text="Объединить файлы перед обфускацией", variable=self.merge_files, command=self._update_status).pack(side="left", padx=8)
        tk.Checkbutton(top, text="Обфусцировать каждый файл отдельно", variable=self.process_each, command=self._update_status).pack(side="left", padx=8)
        tk.Checkbutton(top, text="Сгенерировать декодер рядом", variable=self.generate_decoder).pack(side="left", padx=8)
        tk.Label(top, text="XOR ключ (строка или число 0-255):").pack(side="left", padx=8)
        tk.Entry(top, textvariable=self.xor_key_str, width=20).pack(side="left")

        out = tk.Frame(self.root)
        out.pack(fill="x", padx=8, pady=6)
        tk.Label(out, text="Выходной файл (для объединения):").pack(side="left")
        tk.Entry(out, textvariable=self.output_path, width=60).pack(side="left", padx=6)
        tk.Button(out, text="Выбрать…", command=self.pick_output).pack(side="left")

        # Notebook tabs
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill="both", expand=True, padx=8, pady=6)

        tabs_cfg = [
            ("Python", "python", list(PYTHON_METHODS.keys())),
            ("PowerShell", "powershell", list(POWERSHELL_METHODS.keys())),
            ("JavaScript", "js", list(JS_METHODS.keys())),
            ("HTML", "html", list(LANG_TEXT_METHODS["html"].keys())),
            ("CSS", "css", list(LANG_TEXT_METHODS["css"].keys())),
            ("EXE (бинарь)", "exe", list(EXE_METHODS.keys())),
            ("Универсальные", "universal", list(UNIVERSAL_METHODS.keys())),
        ]
        for title, key, methods in tabs_cfg:
            frame = tk.Frame(notebook)
            notebook.add(frame, text=title)
            for m in methods:
                var = tk.BooleanVar(value=False)
                cb = tk.Checkbutton(frame, text=m, variable=var, anchor="w", justify="left")
                cb.pack(fill="x", padx=8, pady=2)
                self.vars[key][m] = var

        # preview method combobox + button
        preview_frame = tk.Frame(self.root)
        preview_frame.pack(fill="x", padx=8, pady=6)
        tk.Label(preview_frame, text="Предпросмотреть метод:").pack(side="left")
        self.preview_combo = ttk.Combobox(preview_frame, values=list(ALL_METHODS.keys()), width=60)
        self.preview_combo.pack(side="left", padx=6)
        tk.Button(preview_frame, text="Предпросмотреть метод", command=self.preview_method).pack(side="left", padx=6)

        # Run button
        tk.Button(self.root, text="Обфусцировать (все выбранные методы)", command=self.run, bg="#1976D2", fg="white", font=("TkDefaultFont", 11, "bold")).pack(pady=6)

        # Status and preview
        self.status_lbl = tk.Label(self.root, text="Файлы не выбраны", fg="#aa5500", anchor="w", justify="left")
        self.status_lbl.pack(fill="x", padx=8)
        tk.Label(self.root, text="Предпросмотр (усечён для больших бинарей):").pack(anchor="w", padx=8)
        self.preview = scrolledtext.ScrolledText(self.root, wrap="word", font=("Courier New", 10))
        self.preview.pack(fill="both", expand=True, padx=8, pady=6)

    # file pickers
    def pick_files(self):
        files = filedialog.askopenfilenames(title="Выбрать файлы", filetypes=[("Все файлы", "*.*")])
        if files:
            self.files = list(files)
            self._update_status()
            self.preview.delete("1.0", "end")
            self.preview.insert("1.0", "Выбраны файлы:\n" + "\n".join(self.files) + "\n\n")

    def pick_output(self):
        fname = filedialog.asksaveasfilename(title="Выбрать выходной файл", filetypes=[("Все файлы", "*.*")])
        if fname:
            self.output_path.set(fname)

    def _update_status(self):
        if not self.files:
            self.status_lbl.config(text="Файлы не выбраны")
            return
        same, lang = all_same_lang(self.files)
        msgs = []
        if self.merge_files.get():
            if not same or lang == "exe":
                msgs.append("Объединение: разные типы (или EXE присутствует) — будут применены только «Универсальные» к текстам; EXE пропущены.")
            else:
                msgs.append(f"Объединение: все файлы одного языка: {lang} — применяются методы языка + универсальные.")
        if self.process_each.get():
            msgs.append("Режим: обфусцировать каждый файл отдельно (по типу).")
        if not (self.merge_files.get() or self.process_each.get()):
            msgs.append("Режим: обработать только первый выбранный файл.")
        self.status_lbl.config(text="\n".join(msgs))

    # parse xor key as bytes
    def _parse_xor_key(self):
        k = self.xor_key_str.get().strip()
        if not k:
            return b""
        try:
            ival = int(k)
            if 0 <= ival <= 255:
                return bytes([ival])
        except Exception:
            pass
        return k.encode("utf-8")

    # apply single method (for preview)
    def preview_method(self):
        method_name = self.preview_combo.get()
        if not method_name:
            messagebox.showwarning("Предпросмотр", "Выберите метод в списке для предпросмотра.")
            return
        if not self.files:
            messagebox.showwarning("Предпросмотр", "Сначала выберите файлы.")
            return
        fn, mode = ALL_METHODS.get(method_name, (None, None))
        if fn is None:
            messagebox.showerror("Предпросмотр", "Метод не найден.")
            return

        xor_key = self._parse_xor_key()
        # In merge mode and same-language, apply to merged text; else apply to first file
        if self.merge_files.get():
            same, lang = all_same_lang(self.files)
            if not same and mode == "text":
                # merged universal preview: join texts and apply only universal if method is universal
                merged = ""
                for f in self.files:
                    if detect_lang(f) == "exe":
                        continue
                    merged += read_text(f) + "\n"
                try:
                    if method_name.startswith("EXE"):
                        messagebox.showwarning("Предпросмотр", "Нельзя применить EXE-метод к текстам.")
                        return
                    # For XOR text method need key
                    if method_name == "UNI · XOR -> base64":
                        out = uni_xor_text(merged, xor_key)
                    else:
                        out = fn(merged)  # try apply
                except Exception as e:
                    out = f"<error applying preview: {e}>"
                self.preview.delete("1.0", "end")
                self.preview.insert("1.0", out[:200000])
                return
            else:
                # same lang: merge and apply
                merged = "\n".join(read_text(f) for f in self.files if detect_lang(f) != "exe")
                try:
                    if mode == "binary":
                        messagebox.showwarning("Предпросмотр", "Нельзя показать бинарный метод на тексте.")
                        return
                    if method_name == "UNI · XOR -> base64":
                        out = uni_xor_text(merged, xor_key)
                    else:
                        out = fn(merged)
                except Exception as e:
                    out = f"<error applying preview: {e}>"
                self.preview.delete("1.0", "end")
                # show first 20000 chars
                self.preview.insert("1.0", "=== BEFORE (first 10 lines) ===\n" + "\n".join(read_text(self.files[0]).splitlines()[:10]) + "\n\n")
                self.preview.insert("end", "=== AFTER (result first 20000 chars) ===\n" + (out[:200000] if isinstance(out, str) else str(out)[:200000]))
                return
        else:
            first = self.files[0]
            lang = detect_lang(first)
            if mode == "binary":
                # read bytes and apply
                try:
                    data = read_bytes(first)
                    res = fn(data, xor_key) if method_name.startswith("EXE · XOR") else fn(data)
                    # present base64 preview
                    b64 = base64.b64encode(res).decode("ascii")[:200000]
                    self.preview.delete("1.0", "end")
                    self.preview.insert("1.0", f"Binary preview (base64, truncated):\n{b64}")
                except Exception as e:
                    messagebox.showerror("Предпросмотр", f"Ошибка при применении метода: {e}")
            else:
                # text method on first file
                try:
                    text = read_text(first)
                    if method_name == "UNI · XOR -> base64":
                        out = uni_xor_text(text, xor_key)
                    else:
                        out = fn(text)
                    before = "\n".join(text.splitlines()[:10])
                    after = (out if isinstance(out, str) else str(out))[:200000]
                    self.preview.delete("1.0", "end")
                    self.preview.insert("1.0", "=== BEFORE (first 10 lines) ===\n" + before + "\n\n")
                    self.preview.insert("end", "=== AFTER (first 20000 chars) ===\n" + after)
                except Exception as e:
                    messagebox.showerror("Предпросмотр", f"Ошибка при применении метода: {e}")

    # apply all selected methods (run)
    def apply_text_methods(self, text: str, lang: str, xor_key: bytes) -> str:
        if lang in LANG_TEXT_METHODS and lang != "universal":
            methods = LANG_TEXT_METHODS[lang]
            for name, var in self.vars.get(lang, {}).items():
                if var.get():
                    fn = methods.get(name)
                    if fn:
                        try:
                            text = fn(text)
                        except Exception:
                            pass
        for name, var in self.vars.get("universal", {}).items():
            if var.get():
                fn = UNIVERSAL_METHODS.get(name)
                if fn:
                    try:
                        if name == "UNI · XOR -> base64":
                            text = uni_xor_text(text, xor_key)
                        else:
                            text = fn(text)
                    except Exception:
                        pass
        return text

    def apply_exe_methods(self, data: bytes, xor_key: bytes) -> bytes:
        res = data
        for name, var in self.vars.get("exe", {}).items():
            if var.get():
                fn = EXE_METHODS.get(name)
                if fn:
                    try:
                        if name.startswith("EXE · XOR"):
                            res = fn(res, xor_key)
                        else:
                            res = fn(res)
                    except Exception:
                        pass
        return res

    def _gen_decoder_for_text(self, obf_path: str, xor_key: bytes):
        base, ext = os.path.splitext(obf_path)
        decoder_path = base + "_decoder.py"
        code = textwrap.dedent(f"""\
            # decoder for {os.path.basename(obf_path)}
            import base64
            with open("{os.path.basename(obf_path)}", "r", encoding="utf-8", errors="ignore") as f:
                s = f.read()
        """)
        if xor_key:
            key_hex = xor_key.hex()
            code += textwrap.dedent(f"""
                b = base64.b64decode(s)
                key = bytes.fromhex("{key_hex}")
                out = bytearray(len(b))
                for i, c in enumerate(b):
                    out[i] = c ^ key[i % len(key)]
                with open("{os.path.basename(base)}_restored{ext}", "w", encoding="utf-8") as f:
                    f.write(out.decode('utf-8', errors='ignore'))
                print("Restored -> {os.path.basename(base)}_restored{ext}")
            """)
        else:
            code += textwrap.dedent(f"""
                try:
                    out = base64.b64decode(s).decode('utf-8')
                except Exception:
                    out = s
                with open("{os.path.basename(base)}_restored{ext}", "w", encoding="utf-8") as f:
                    f.write(out)
                print("Restored -> {os.path.basename(base)}_restored{ext}")
            """)
        try:
            write_text(os.path.join(os.path.dirname(obf_path) or ".", os.path.basename(decoder_path)), code)
        except Exception:
            pass

    def _gen_decoder_for_exe(self, obf_path: str, xor_key: bytes):
        base, ext = os.path.splitext(obf_path)
        decoder_path = base + "_exe_decoder.py"
        code = textwrap.dedent(f"""\
            # decoder for {os.path.basename(obf_path)}
            import base64
            data = None
            with open("{os.path.basename(obf_path)}", "rb") as f:
                data = f.read()
            try:
                raw = base64.b64decode(data)
            except Exception:
                raw = data
        """)
        if xor_key:
            key_hex = xor_key.hex()
            code += textwrap.dedent(f"""
                key = bytes.fromhex("{key_hex}")
                out = bytearray(len(raw))
                for i, b in enumerate(raw):
                    out[i] = b ^ key[i % len(key)]
            """)
        else:
            code += "out = raw\n"
        code += textwrap.dedent(f"""
            with open("{os.path.basename(base)}_restored{ext}", "wb") as f:
                f.write(bytes(out))
            print("Saved: {os.path.basename(base)}_restored{ext}")
        """)
        try:
            write_text(os.path.join(os.path.dirname(obf_path) or ".", os.path.basename(decoder_path)), code)
        except Exception:
            pass

    def _process_single(self, filepath, xor_key: bytes, preview_acc: list):
        lang = detect_lang(filepath)
        if lang == "exe":
            data = read_bytes(filepath)
            data_out = self.apply_exe_methods(data, xor_key)
            out = os.path.splitext(filepath)[0] + "_obf" + os.path.splitext(filepath)[1]
            write_bytes(out, data_out)
            try:
                b64 = base64.b64encode(data_out).decode("ascii")
            except Exception:
                b64 = "<binary preview not available>"
            preview_acc.append(f"--- {os.path.basename(filepath)} (exe) -> {out} ---\n{b64[:200000]}")
            if self.generate_decoder.get():
                self._gen_decoder_for_exe(out, xor_key)
        else:
            text = read_text(filepath)
            text_out = self.apply_text_methods(text, lang if lang in LANG_TEXT_METHODS else "universal", xor_key)
            out = os.path.splitext(filepath)[0] + "_obf" + os.path.splitext(filepath)[1]
            write_text(out, text_out)
            preview_acc.append(f"--- {os.path.basename(filepath)} -> {out} ---\n{text_out[:200000]}")
            if self.generate_decoder.get():
                self._gen_decoder_for_text(out, lang if lang in LANG_TEXT_METHODS else "universal", xor_key)

    def run(self):
        if not self.files:
            messagebox.showwarning("Внимание", "Сначала выберите файлы.")
            return
        xor_key = self._parse_xor_key()
        preview_acc = []
        if self.merge_files.get():
            same, lang = all_same_lang(self.files)
            if same and lang == "exe":
                messagebox.showwarning("Ограничение", "Объединение .exe не поддерживается. Будет обработан первый .exe.")
                self._process_single(self.files[0], xor_key, preview_acc)
            elif same:
                merged = "\n".join(read_text(f) for f in self.files)
                merged = self.apply_text_methods(merged, lang, xor_key)
                out = self.output_path.get() or (os.path.splitext(self.files[0])[0] + "_merged_obf" + os.path.splitext(self.files[0])[1])
                write_text(out, merged)
                preview_acc.append(f"== Объединённый файл -> {out} ==\n")
                preview_acc.append(merged[:200000])
                if self.generate_decoder.get():
                    self._gen_decoder_for_text(out, lang, xor_key)
                messagebox.showinfo("Готово", f"Сохранено: {out}")
            else:
                merged = ""
                for f in self.files:
                    if detect_lang(f) == "exe":
                        continue
                    merged += read_text(f) + "\n"
                for name, var in self.vars.get("universal", {}).items():
                    if var.get():
                        fn = UNIVERSAL_METHODS.get(name)
                        if fn:
                            if name == "UNI · XOR -> base64":
                                merged = uni_xor_text(merged, xor_key)
                            else:
                                merged = fn(merged)
                out = self.output_path.get() or (os.path.splitext(self.files[0])[0] + "_merged_obf.txt")
                write_text(out, merged)
                preview_acc.append(f"== Объединённый (универсальные) -> {out} ==\n")
                preview_acc.append(merged[:200000])
                if self.generate_decoder.get():
                    self._gen_decoder_for_text(out, "universal", xor_key)
                messagebox.showinfo("Готово", f"Сохранено: {out}")
        elif self.process_each.get():
            for f in self.files:
                self._process_single(f, xor_key, preview_acc)
            messagebox.showinfo("Готово", "Пофайловая обфускация завершена.")
        else:
            self._process_single(self.files[0], xor_key, preview_acc)
            messagebox.showinfo("Готово", "Обфускация первого файла завершена.")
        self.preview.delete("1.0", "end")
        self.preview.insert("1.0", "\n\n".join(preview_acc)[:500000])

# -------------------------
# DnD-capable Tk wrapper or fallback
# -------------------------
def main():
    if HAS_DND:
        # use TkinterDnD for drag & drop
        root = TkinterDnD.Tk()
        root.title("Обфускатор — drag&drop enabled")
        app = AppBase(root)
        # register drop target on preview area and root
        def drop_handler(event):
            # event.data may be a list of filenames separated by space/brace quoting
            data = event.data
            # parse paths
            files = []
            if data.startswith("{") and "}" in data:
                # split {path with spaces}...
                parts = re.findall(r'\{([^}]+)\}|([^ ]+)', data)
                for p in parts:
                    val = p[0] or p[1]
                    if val:
                        files.append(val)
            else:
                files = data.split()
            files = [f for f in files if os.path.exists(f)]
            if files:
                app.files = files
                app._update_status()
                app.preview.delete("1.0", "end")
                app.preview.insert("1.0", "Dropped files:\n" + "\n".join(files) + "\n\n")
        # bind DnD to root
        root.drop_target_register(DND_FILES)
        root.dnd_bind('<<Drop>>', drop_handler)
        root.mainloop()
    else:
        # fallback normal Tk with note
        root = tk.Tk()
        root.title("Обфускатор — drag&drop unavailable")
        app = AppBase(root)
        # add a small hint to install tkinterdnd2
        hint = "\nHint: to enable drag & drop, install tkinterdnd2 (pip install tkinterdnd2) and restart.\n"
        app.preview.insert("end", hint)
        root.mainloop()

if __name__ == "__main__":
    main()
