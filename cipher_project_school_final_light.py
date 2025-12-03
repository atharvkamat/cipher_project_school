from random import choice
import string
import tkinter as tk
from tkinter import messagebox, filedialog, scrolledtext

global symbols, symbols_len
symbols = list(string.printable)
symbols_len = len(symbols)

def password_maker():
    pass_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    password = ''
    for i in range(16):
        password += choice(pass_list)
    return password

def key_file(n, i):
    file_path = f'D:\\cs_project\\cs_project_keys\\{n}.txt'
    with open(file_path, 'r') as file:
        file.seek(i, 0)
        return file.read(1)

def key_maker(plain_text_length, password):
    t = (plain_text_length//16) + 1
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
            sum_val = symbols.index(plain_text[a]) + symbols.index(key[a])
            value += symbols[sum_val % symbols_len]
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
            diff = symbols.index(value[a]) - symbols.index(key[a])
            plain_text += symbols[diff % symbols_len]
        except ValueError:
            plain_text += value[a]
    del key
    return plain_text

#gui

BG_DARK = "#f0f0f0"      
BG_SURFACE = "#ffffff"   
FG_TEXT = "#333333"      
ACCENT_PRI = "#00087a"   
ACCENT_NEG = "#ff0000" 

FONT_BODY = ('Consolas', 14,'bold')
FONT_TITLE = ('Consolas', 15, 'bold')
FONT_LABEL = ('Consolas', 15, 'bold')

root = tk.Tk()
root.title("FINAL PROJECT")
root.geometry("1280x720")
root.configure(bg=BG_DARK)
show_password = False


def handle_encrypt():
    plain = input_text.get("1.0", tk.END).strip()
    if not plain: 
        messagebox.showwarning("Warning", "Enter text!")
        return None
    try:
        encrypted, password = encrypter(plain, password_entry.get().strip() or False)
        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", encrypted)
        password_entry.delete(0, tk.END) 
        password_entry.insert(0, password)
        status_label.config(text="ENCRYPTED", fg=ACCENT_PRI)
    except FileNotFoundError: 
        status_label.config(text="FAILED (Missing D:\\ files)", fg=ACCENT_NEG)
    except Exception as e: 
        messagebox.showerror("Error", str(e))
        status_label.config(text="FAILED", fg=ACCENT_NEG)

def handle_decrypt():
    cipher = input_text.get("1.0", tk.END).strip()
    password = password_entry.get().strip()
    if not cipher or not password: 
        messagebox.showwarning("Warning", "Text and password required!") 
        return None
    try:
        decrypted = decrypter(cipher, password)
        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", decrypted)
        status_label.config(text="DECRYPTED", fg=ACCENT_PRI)
    except FileNotFoundError: 
        status_label.config(text="FAILED (Missing D:\\ files)", fg=ACCENT_NEG)
    except Exception as e: 
        messagebox.showerror("Error", str(e))
        status_label.config(text="FAILED", fg=ACCENT_NEG)

def generate_password():
    password_entry.delete(0, tk.END)
    password_entry.insert(0, password_maker())
    status_label.config(text="PASSWORD GENERATED", fg=ACCENT_PRI)

def toggle_password():
    global show_password
    show_password = not show_password
    if show_password==True:
        setting = ''
        text = 'HIDE'
        color = ACCENT_PRI
    else:
        setting = '*'
        text = 'SHOW'
        color = FG_TEXT
    password_entry.config(show=setting)
    show_btn.config(text=text, fg=color)

def clear_all():
    input_text.delete("1.0", tk.END)
    output_text.delete("1.0", tk.END)
    password_entry.delete(0, tk.END)
    status_label.config(text="READY", fg=FG_TEXT)

def copy_output():
    output = output_text.get("1.0", tk.END).strip()
    if output: 
        root.clipboard_clear()
        root.clipboard_append(output)
        status_label.config(text="COPIED", fg=ACCENT_PRI)
    else: 
        messagebox.showwarning("Warning", "Nothing to copy!")


def file_dialog(action):
    if action == 'load':
        file_path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'r') as f: content = f.read()
                input_text.delete("1.0", tk.END)
                input_text.insert("1.0", content)
                status_label.config(text="FILE LOADED", fg=ACCENT_PRI)
            except Exception as e: 
                messagebox.showerror("Error", f"Load failed: {str(e)}")
    elif action == 'save':
        output = output_text.get("1.0", tk.END).strip()
        if not output: 
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, 'w') as f:
                    f.write(output)
                status_label.config(text="FILE SAVED", fg=ACCENT_PRI)
            except Exception as e: 
                messagebox.showerror("Error", f"Save failed: {str(e)}")



tk.Label(root, text="CIPHER TOOL", font=FONT_TITLE, bg=BG_SURFACE, fg=ACCENT_PRI).pack(fill=tk.X, ipady=5)

main_frame = tk.Frame(root, bg=BG_DARK, padx=10, pady=10)
main_frame.pack(fill=tk.BOTH, expand=True)

tk.Label(main_frame, text="INPUT TEXT:", font=FONT_LABEL, bg=BG_DARK, fg=FG_TEXT).pack(fill=tk.X, anchor='w', pady=(5,0))
input_text = scrolledtext.ScrolledText(main_frame, font=FONT_BODY, height=6, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT)
input_text.pack(fill=tk.BOTH, expand=True, pady=(2, 8))

password_frame = tk.Frame(main_frame, bg=BG_DARK)
password_frame.pack(fill=tk.X, pady=(0, 10))

tk.Label(password_frame, text="PASSWORD:", font=FONT_LABEL, bg=BG_DARK, fg=FG_TEXT).pack(side=tk.LEFT)

entry_btn_frame = tk.Frame(password_frame, bg=BG_DARK)
entry_btn_frame.pack(side=tk.RIGHT, fill=tk.X, expand=True)

show_btn = tk.Button(entry_btn_frame, text="SHOW", command=toggle_password, bg=BG_SURFACE, fg=FG_TEXT, font=FONT_BODY, width=5)
show_btn.pack(side=tk.RIGHT, padx=(5,0))

tk.Button(entry_btn_frame, text="GENERATE", command=generate_password, bg=BG_SURFACE, fg=ACCENT_PRI, font=FONT_BODY, width=9).pack(side=tk.RIGHT, padx=4)

password_entry = tk.Entry(entry_btn_frame, font=FONT_BODY, show="*", bg=BG_SURFACE, fg=FG_TEXT, relief=tk.SUNKEN)
password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

action_frame = tk.Frame(main_frame, bg=BG_DARK)
action_frame.pack(fill=tk.X, pady=8)


tk.Button(action_frame, text="ENCRYPT", command=handle_encrypt, bg=BG_SURFACE, fg=ACCENT_PRI, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
tk.Button(action_frame, text="DECRYPT", command=handle_decrypt, bg=BG_SURFACE, fg=ACCENT_NEG, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
tk.Button(action_frame, text="LOAD FILE", command=lambda: file_dialog('load'), bg=BG_SURFACE, fg=FG_TEXT, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
tk.Button(action_frame, text="CLEAR ALL", command=clear_all, bg=BG_SURFACE, fg=FG_TEXT, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)


tk.Label(main_frame, text="OUTPUT:", font=FONT_LABEL, bg=BG_DARK, fg=FG_TEXT).pack(fill=tk.X, anchor='w', pady=(5,0))
output_text = scrolledtext.ScrolledText(main_frame, font=FONT_BODY, height=6, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT)
output_text.pack(fill=tk.BOTH, expand=True, pady=(2, 8))


output_mgmt_frame = tk.Frame(main_frame, bg=BG_DARK)
output_mgmt_frame.pack(fill=tk.X)


tk.Button(output_mgmt_frame, text="COPY", command=copy_output, bg=BG_SURFACE, fg=FG_TEXT, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)
tk.Button(output_mgmt_frame, text="SAVE", command=lambda:file_dialog('save'), bg=BG_SURFACE, fg=ACCENT_PRI, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3, ipadx=40)


status_frame = tk.Frame(root, bg=BG_SURFACE, height=25, relief=tk.SUNKEN, bd=1)
status_frame.pack(fill=tk.X, side=tk.BOTTOM)
status_frame.pack_propagate(False)

status_label = tk.Label(status_frame, text="READY", font=("Consolas", 9,'bold'), bg=BG_SURFACE, fg=FG_TEXT, anchor=tk.W)
status_label.pack(fill=tk.X, padx=5)

root.mainloop()

