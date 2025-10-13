from random import choice
import string
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext


global symbol_list, symbol_list_len
symbol_list = list(string.printable)
symbol_list_len = len(symbol_list)

def password_maker():
    pass_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e']
    password = ''
    for i in range(16):
        password += choice(pass_list)
    return password

def key_file(n, i):
    file_path = f'D:\\school_project_2025\\vignere_shift_final\\cs_project_keys_files\\cs_project_keys\\{n}.txt'
    with open(file_path, 'r') as file:
        file.seek(i, 0)
        return file.read(1)

def key_maker(plain_text_length, password):
    t = plain_text_length // 16 + 1
    key = ''
    for i in range(t):
        for k in password:
            key += key_file(k, i)
    key = key[:plain_text_length] 
    return key
    
def encrypter(plain_text, password=False):
    p_len = len(plain_text)
    if not password:
        password = password_maker()
    key = key_maker(p_len, password)
    value = ''
    for a in range(p_len):
        try:
            sum_val = symbol_list.index(plain_text[a]) + symbol_list.index(key[a])
            value += symbol_list[sum_val % symbol_list_len]
        except ValueError:
            value += plain_text[a]
    del key
    return (value, password)

def decrypter(value, password):
    p_len = len(value)
    key = key_maker(p_len, password)
    plain_text = ''
    for a in range(p_len):
        try:
            diff = symbol_list.index(value[a]) - symbol_list.index(key[a])
            plain_text += symbol_list[diff % symbol_list_len]
        except ValueError:
            plain_text += value[a]
    del key
    return plain_text

#gui

BG_DARK = "#1e1e2e"      
BG_SURFACE = "#313244"   
FG_TEXT = "#cdd6f4"      
ACCENT_PRI = "#f9e2af"   
ACCENT_NEG = "#f38ba8"   

FONT_BODY = ("Arial", 10)
FONT_TITLE = ("Arial", 14, "bold")
FONT_LABEL = ("Arial", 10, "bold")

root = tk.Tk()
root.title("Compact Vigenère Cipher")
root.geometry("550x550")
root.configure(bg=BG_DARK)
show_password = False


def handle_encrypt():
    plain = input_text.get("1.0", tk.END).strip()
    if not plain: messagebox.showwarning("Warning", "Enter text!"); return
    try:
        encrypted, pwd = encrypter(plain, password_entry.get().strip() or False)
        output_text.delete("1.0", tk.END); output_text.insert("1.0", encrypted)
        password_entry.delete(0, tk.END); password_entry.insert(0, pwd)
        status_label.config(text="ENCRYPTED", fg=ACCENT_PRI)
    except FileNotFoundError: status_label.config(text="FAILED (Missing D:\\ files)", fg=ACCENT_NEG)
    except Exception as e: messagebox.showerror("Error", str(e)); status_label.config(text="FAILED", fg=ACCENT_NEG)

def handle_decrypt():
    cipher = input_text.get("1.0", tk.END).strip()
    password = password_entry.get().strip()
    if not cipher or not password: messagebox.showwarning("Warning", "Text and password required!"); return
    try:
        decrypted = decrypter(cipher, password)
        output_text.delete("1.0", tk.END); output_text.insert("1.0", decrypted)
        status_label.config(text="DECRYPTED", fg=ACCENT_PRI)
    except FileNotFoundError: status_label.config(text="FAILED (Missing D:\\ files)", fg=ACCENT_NEG)
    except Exception as e: messagebox.showerror("Error", str(e)); status_label.config(text="FAILED", fg=ACCENT_NEG)

def generate_password():
    password_entry.delete(0, tk.END); password_entry.insert(0, password_maker())
    status_label.config(text="PASSWORD GENERATED", fg=ACCENT_PRI)

def toggle_password():
    global show_password
    show_password = not show_password
    setting, text, color = ("", "HIDE", ACCENT_PRI) if show_password else ("*", "SHOW", FG_TEXT)
    password_entry.config(show=setting)
    show_btn.config(text=text, fg=color)

def clear_all():
    input_text.delete("1.0", tk.END); output_text.delete("1.0", tk.END); password_entry.delete(0, tk.END)
    status_label.config(text="[READY]", fg=FG_TEXT)

def copy_output():
    output = output_text.get("1.0", tk.END).strip()
    if output: root.clipboard_clear(); root.clipboard_append(output); status_label.config(text="COPIED", fg=ACCENT_PRI)
    else: messagebox.showwarning("Warning", "Nothing to copy!")

def file_dialog(action):
    if action == 'load':
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as f: content = f.read()
                input_text.delete("1.0", tk.END); input_text.insert("1.0", content)
                status_label.config(text="FILE LOADED", fg=ACCENT_PRI)
            except Exception as e: messagebox.showerror("Error", f"Load failed: {str(e)}")
    elif action == 'save':
        output = output_text.get("1.0", tk.END).strip()
        if not output: messagebox.showwarning("Warning", "Nothing to save!"); return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as f: f.write(output)
                status_label.config(text="FILE SAVED", fg=ACCENT_PRI)
            except Exception as e: messagebox.showerror("Error", f"Save failed: {str(e)}")

BUTTONS = [
    ("ENCRYPT", handle_encrypt, ACCENT_PRI, 2, 0, 1, 1),
    ("DECRYPT", handle_decrypt, ACCENT_NEG, 2, 1, 1, 1),
    ("Load File", lambda: file_dialog('load'), FG_TEXT, 2, 2, 1, 1),
    ("Clear All", clear_all, FG_TEXT, 2, 3, 1, 1),
    ("Copy", copy_output, FG_TEXT, 6, 0, 1, 1),
    ("Save", lambda: file_dialog('save'), ACCENT_PRI, 6, 1, 3, 3)
]

tk.Label(root, text="Cipher Tool", font=FONT_TITLE, bg=BG_SURFACE, fg=ACCENT_PRI).pack(fill=tk.X, ipady=5)

main_frame = tk.Frame(root, bg=BG_DARK, padx=10, pady=10)
main_frame.pack(fill=tk.BOTH, expand=True)
main_frame.grid_columnconfigure((0, 1, 2, 3), weight=1)

tk.Label(main_frame, text="INPUT TEXT:", font=FONT_LABEL, bg=BG_DARK, fg=FG_TEXT).grid(row=0, column=0, sticky="w", pady=(5,0))
input_text = scrolledtext.ScrolledText(main_frame, font=FONT_BODY, height=6, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT)
input_text.grid(row=1, column=0, columnspan=4, sticky="nsew", pady=(2, 8),padx = (0,5))
main_frame.grid_rowconfigure(1, weight=1)

tk.Label(main_frame, text="PASSWORD:", font=FONT_LABEL, bg=BG_DARK, fg=FG_TEXT).grid(row=3,column=0, sticky="w")
password_entry = tk.Entry(main_frame, font=FONT_BODY, show="*", bg=BG_SURFACE, fg=FG_TEXT, relief=tk.SUNKEN)
password_entry.grid(row=3,column=1,columnspan=2, sticky="ew", padx=(0, 5))

tk.Button(main_frame, text="Generate", command=generate_password, bg=BG_SURFACE, fg=ACCENT_PRI, font=FONT_BODY).grid(row=3, column=2, sticky="ew",padx=(0,5))
show_btn = tk.Button(main_frame, text="SHOW", command=toggle_password, bg=BG_SURFACE, fg=FG_TEXT, font=FONT_BODY)
show_btn.grid(row=3, column=3, sticky="ew",padx = (0,5)) 

for text, command, fg, r, c, cspan, w in BUTTONS:
    btn = tk.Button(main_frame, text=text, command=command, bg=BG_SURFACE, fg=fg, font=FONT_BODY, relief=tk.RAISED)
    btn.grid(row=r, column=c, columnspan=cspan, sticky="ew", padx=3, pady=8)

tk.Label(main_frame, text="OUTPUT:", font=FONT_LABEL, bg=BG_DARK, fg=FG_TEXT).grid(row=4, column=0, sticky="w", pady=(5,0))
output_text = scrolledtext.ScrolledText(main_frame, font=FONT_BODY, height=6, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT)
output_text.grid(row=5, column=0, columnspan=4, sticky="nsew", pady=(2, 8))
main_frame.grid_rowconfigure(5, weight=1)

status_frame = tk.Frame(root, bg=BG_SURFACE, height=25, relief=tk.SUNKEN, bd=1)
status_frame.pack(fill=tk.X, side=tk.BOTTOM)
status_frame.pack_propagate(False)

status_label = tk.Label(status_frame, text="[READY]", font=("Arial", 9), bg=BG_SURFACE, fg=FG_TEXT, anchor=tk.W)
status_label.pack(fill=tk.X, padx=5)

root.mainloop()