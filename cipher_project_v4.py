from random import choice
import string
import tkinter as tk
import hashlib as hs
from tkinter import messagebox, filedialog, scrolledtext
from time import perf_counter

global cache,chunk_number_list ,chunk_size,pass_list,key_files_path,key_file_len, symbols, symbols_len,symbol_to_ord,ord_to_symbol,symbol_to_sub, sub_to_symbol,reserved_sentances
reserved_sentances = ['INPUT CONTAINS INVALID CHARACTERS/S','DATA CORRUPTED','SENTANCE IS RESERVED(CANNOT BE ENCRYPTED)','PASSWORD INCORRECT OR DATA MAY HAVE BEEN CORRUPTED']
pass_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e','f']
key_files_path = 'D:\\python projects\\lab activity 3\\cs_project_key_files_final\\'

symbols = list(string.printable)
symbols_len = len(symbols)
symbol_to_ord = dict(zip(symbols,range(100)))
ord_to_symbol = dict(zip(range(100),symbols))

cache = dict.fromkeys(symbols,None)
chunk_size = 8912
chunk_number_list =[-1]
with open(key_files_path+'a.txt','r') as f:
    key_file_len = len(f.read())

with open(key_files_path+'substitution_cipher_dictionaries.txt','r') as f:
    dictionaries = f.read().split('\n')
symbol_to_sub = eval(dictionaries[0])
sub_to_symbol = eval(dictionaries[1])
del dictionaries

def cache_update(n):
    global cache,chunk_number_list
    check = n%chunk_size
    if check ==0:
        if chunk_number_list[-1]==n:
            pass
        else:
            chunk_number_list.append(n)
            if n+chunk_size<key_file_len:
                for i in pass_list:
                    with open(key_files_path+f'{i}.txt','r') as f:
                        f.seek(n)
                        chunk = f.read(chunk_size)
                        cache[i]= chunk
            else:
                new_chunk_size = key_file_len-n
                for i in pass_list:
                    with open(key_files_path+f'{i}.txt','r') as f:
                        f.seek(n)
                        chunk = f.read(new_chunk_size)
                        cache[i]= chunk

def password_maker():
    password = ''
    for i in range(32):
        password += choice(pass_list)
    return password

def key_file(file_name, i):
    cache_update(i)
    return cache[file_name][i%chunk_size]

def key_maker(plain_text_length, password,block_number = 2):
    if block_number == 1:
        t = (plain_text_length//16) + 1
    else:
        t = (plain_text_length//64) +1
    key_list = []
    for i in range(t):
        for k in password:
            key_list.append(key_file(k, i)) 
    return ''.join(key_list)

def char_encrypter(plain_text,password,block_number = 2):
    p_len = len(plain_text)
    key = key_maker(p_len,password,block_number)
    cipher_text_list = []
    for a in range(p_len):
        sum_val = symbol_to_ord[plain_text[a]] + symbol_to_ord[key[a]]
        cipher_text_list.append(ord_to_symbol[sum_val % symbols_len])
    return ''.join(cipher_text_list)

def subsitution_encrypter(plaintext):
    cipher_text_list = []
    current_index = 0
    for i in plaintext:
        current_char_tuple = (symbol_to_ord[i],current_index%100)
        temp = symbol_to_sub[current_char_tuple]
        char = ''
        for k in temp:
            char += chr(k)
        cipher_text_list.append(char)
      
        if (current_index+1)%30 ==0:
            cipher_text_list.append('\n')
        current_index +=1

    return ''.join(cipher_text_list)

def encrypter(plain_text, password=False):
    global chunk_number_list
    start_time = perf_counter()
    if not password:
        password = password_maker()

    password_filler = ''
    pt_filler = ''
    for i in range(32):
        password_filler += choice(symbols)
        pt_filler += choice(symbols)
    
    password_filler_text = password + password_filler
    pt_filler_text = plain_text+ pt_filler

    plain_text_hash = hs.sha256(pt_filler_text.encode()).hexdigest()
    password_hash = hs.sha256(password_filler_text.encode()).hexdigest()

    block1 = password_filler+ password_hash + plain_text_hash
    block2 = pt_filler_text

    block1_hash = hs.sha256(block1.encode()).hexdigest()

    try:
        cipher_text1 = char_encrypter(block1,password,1)
        cipher_text2 = char_encrypter(block2,block1_hash)
        cipher_text_final = subsitution_encrypter(cipher_text1+cipher_text2)
    except KeyError:
        cipher_text_final = reserved_sentances[0]
    if plain_text in reserved_sentances:
        cipher_text_final = reserved_sentances[2]
    end_time = perf_counter()
    chunk_number_list = [-1]
    return cipher_text_final, password, end_time-start_time, len(plain_text), len(cipher_text_final)

def char_decrypter(cipher_text,key, lower,upper,block_number = 2):
    decrypted_char_list = []
    d = 0
    if block_number ==1:
        pass
    else:
        d = 160

    for a in range(lower,upper,1):
        diff = symbol_to_ord[cipher_text[a]] - symbol_to_ord[key[a-d]]
        decrypted_char_list.append(ord_to_symbol[diff % symbols_len])
    return ''.join(decrypted_char_list)
    
def subsitution_decrypter(raw_cipher_text):
    raw_ct_clean_list = []
    for i in raw_cipher_text:
        if i in symbols:
            pass
        else:
            raw_ct_clean_list.append(i)

    output_text_list = []

    for i in range(0,len(raw_ct_clean_list),3):
        temp = []
        for k in raw_ct_clean_list[i:i+3]:
            temp.append(ord(k))
        char = ord_to_symbol[sub_to_symbol[tuple(temp)]]
        output_text_list.append(char)
    return ''.join(output_text_list)

def decrypter(raw_cipher_text, password):
    global chunk_number_list
    start_time = perf_counter()
    try:
        cipher_text = subsitution_decrypter(raw_cipher_text)
        p_len = len(cipher_text)

        if p_len-192<=0:
            plain_text = reserved_sentances[1]

        else:
            block1 = char_decrypter(cipher_text,key_maker(160,password,1),0,160,1)
            password_filler = block1[0:32]
            password_hash = block1[32:96]
            plain_text_hash = block1[96:]

            password_filler_text = password + password_filler
            ciphert_output_password_hash = hs.sha256(password_filler_text.encode()).hexdigest()

            if ciphert_output_password_hash == password_hash:
                block1_hash = hs.sha256(block1.encode()).hexdigest()
                block2 = char_decrypter(cipher_text, key_maker(p_len-160,block1_hash),160,p_len)

                plain_text = block2[0:-32:1]
                ciphert_output_pt_hash = hs.sha256(block2.encode()).hexdigest()
                if ciphert_output_pt_hash == plain_text_hash:
                    pass
                else:
                    plain_text = reserved_sentances[1]
            else:
                plain_text = reserved_sentances[3]
    except KeyError:
        plain_text = reserved_sentances[1]
    
    end_time = perf_counter()
    chunk_number_list = [-1]
    return plain_text, end_time-start_time, len(raw_cipher_text),len(plain_text)

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
        encrypted, password,time_taken,input_len,output_len = encrypter(plain, password_entry.get().strip() or False)
        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", encrypted)
        password_entry.delete(0, tk.END) 
        password_entry.insert(0, password)
        status_label.config(text=f"ENCRYPTED, TIME TAKEN: {time_taken}, INPUT LENGTH: {input_len}, OUTPUT LENGTH: {output_len}", fg=ACCENT_PRI)
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
        decrypted,time_taken,input_len,output_len = decrypter(cipher, password)
        output_text.delete("1.0", tk.END)
        output_text.insert("1.0", decrypted)
        status_label.config(text=f"DECRYPTED, TIME TAKEN: {time_taken},INPUT LENGTH: {input_len}, OUTPUT LENGTH: {output_len} ", fg=ACCENT_PRI)
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
tk.Button(action_frame, text="CLEAR ALL", command=clear_all, bg=BG_SURFACE, fg=FG_TEXT, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

tk.Label(main_frame, text="OUTPUT:", font=FONT_LABEL, bg=BG_DARK, fg=FG_TEXT).pack(fill=tk.X, anchor='w', pady=(5,0))
output_text = scrolledtext.ScrolledText(main_frame, font=FONT_BODY, height=6, bg=BG_SURFACE, fg=FG_TEXT, relief=tk.FLAT)
output_text.pack(fill=tk.BOTH, expand=True, pady=(2, 8))

output_mgmt_frame = tk.Frame(main_frame, bg=BG_DARK)
output_mgmt_frame.pack(fill=tk.X)

tk.Button(output_mgmt_frame, text="COPY", command=copy_output, bg=BG_SURFACE, fg=FG_TEXT, font=FONT_BODY, relief=tk.RAISED).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=3)

status_frame = tk.Frame(root, bg=BG_SURFACE, height=25, relief=tk.SUNKEN, bd=1)
status_frame.pack(fill=tk.X, side=tk.BOTTOM)
status_frame.pack_propagate(False)

status_label = tk.Label(status_frame, text="READY", font=("Consolas", 9,'bold'), bg=BG_SURFACE, fg=FG_TEXT, anchor=tk.W)
status_label.pack(fill=tk.X, padx=5)

root.mainloop()
