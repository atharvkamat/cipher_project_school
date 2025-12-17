from random import choice
import string
import tkinter as tk
import hashlib as hs
from tkinter import messagebox, filedialog, scrolledtext

global symbols, symbols_len,symbol_to_number, number_to_symbol,reserved_sentances
reserved_sentances = ['INPUT CONTAINS INVALID CHARACTERS/S','DATA CORRUPTED','SENTANCE IS RESERVED(CANNOT BE ENCRYPTED)','DATA IS OF INVALID LENGTH','PASSWORD INCORRECT OR DATA MAY HAVE BEEN CORRUPTED']

symbols = list(string.printable)
symbols_len = len(symbols)
symbol_to_number = {}
number_to_symbol = {}
for i in range(symbols_len):
    if symbols[i]== '\n':
        symbol_to_number['\n']= '\n'
        number_to_symbol['\n']='\n'
    else:
        symbol_to_number[symbols[i]]= chr(945+i)
        number_to_symbol[chr(945+i)]=symbols[i]


def password_maker():
    pass_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
    password = ''
    for i in range(32):
        password += choice(pass_list)
    return password

def key_file(n, i):
    file_path = f'D:\\python projects\\lab activity 3\\cs_project_key_files_final\\{n}.txt'
    with open(file_path, 'r') as file:
        file.seek(i, 0)
        return file.read(1)

def key_maker(plain_text_length, password,block_number = 2):
    if block_number == 1:
        t = (plain_text_length//16) + 1
    else:
        t = (plain_text_length//64) +1

    key = ''

    for i in range(t):
        for k in password:
            key += key_file(k, i)
    key = key[:plain_text_length] 
    return key

def char_encrypter(plain_text,password,block_number = 2):
    p_len = len(plain_text)
    key = key_maker(p_len,password,block_number)
    cipher_text = ''
    for a in range(p_len):
        sum_val = symbols.index(plain_text[a]) + symbols.index(key[a])
        cipher_text += symbols[sum_val % symbols_len]
    return cipher_text

def encrypter(plain_text, password=False):
    if not password:
        password = password_maker()

    password_filler = ''
    for i in range(32):
        password_filler += choice(symbols)
    
    pt_filler = ''
    for i in range(32):
        pt_filler += choice(symbols)

    
    password_filler_text = password + password_filler
    pt_filler_text = plain_text+ pt_filler

    plain_text_hash = hs.sha256(pt_filler_text.encode('utf-8')).hexdigest()
    password_hash = hs.sha256(password_filler_text.encode('utf-8')).hexdigest()

    block1 = password_filler+ password_hash + plain_text_hash
    block2 = pt_filler_text

    block1_hash = hs.sha256(block1.encode('utf-8')).hexdigest()

    try:
        cipher_text1 = char_encrypter(block1,password,1)
        cipher_text2 = char_encrypter(block2,block1_hash)
        cipher_text = ''
        for i in cipher_text1+cipher_text2:
            cipher_text += symbol_to_number[i]
    except ValueError:
        cipher_text = reserved_sentances[0]
    if plain_text in reserved_sentances:
        cipher_text = reserved_sentances[2]

    return cipher_text, password

def char_decrypter(cipher_text,key, lower,upper,block_number = 2):
    decrypted_char = ''
    d = 0
    if block_number ==1:
        pass
    else:
        d = 160

    for a in range(lower,upper,1):
        diff = symbols.index(cipher_text[a]) - symbols.index(key[a-d])
        decrypted_char += symbols[diff % symbols_len]
    return decrypted_char
    

def decrypter(raw_cipher_text, password):
    cipher_text = ''
    try:
        for i in raw_cipher_text:
            cipher_text += number_to_symbol[i]
        p_len = len(cipher_text)
        plain_text = ''

        if p_len-192<=0:
            plain_text = reserved_sentances[3]

        else:
            block1 = char_decrypter(cipher_text,key_maker(160,password,1),0,160,1)
            password_filler = block1[0:32]
            password_hash = block1[32:96]
            plain_text_hash = block1[96:]

            password_filler_text = password + password_filler
            ciphert_output_password_hash = hs.sha256(password_filler_text.encode('utf-8')).hexdigest()
            if ciphert_output_password_hash == password_hash:
                block1_hash = hs.sha256(block1.encode('utf-8')).hexdigest()

                block2 = char_decrypter(cipher_text, key_maker(p_len-160,block1_hash),160,p_len)

                plain_text = block2[0:-32:1]

                ciphert_output_pt_hash = hs.sha256(block2.encode('utf-8')).hexdigest()
                if ciphert_output_pt_hash == plain_text_hash:
                    pass
                else:
                    plain_text = reserved_sentances[1]

            else:
                plain_text = reserved_sentances[4]
    except KeyError:
        plain_text = reserved_sentances[1]

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
                with open(file_path, 'r') as f: 
                    content = f.read()
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

