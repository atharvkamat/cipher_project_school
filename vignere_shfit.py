from random import randint,choice
from time import sleep
from tqdm import tqdm
import string

global symbol_list,symbol_list_len
symbol_list = []
for i in string.printable:
    symbol_list.append(i)
symbol_list_len = len(symbol_list)

def password_maker():
    final = ''
    pass_list = ['0','1','2','3','4','5','6','7','8','9','a','b','c','d','e']
    for i in range(16):
        final += choice(pass_list)
    return final

def key_file(n,i):
    file = open('D:\\school_project_2025\\vignere_shift_final\\cs_project_keys_files\\cs_project_keys\\'+n+'.txt','r')
    file.seek(i,0)
    final = file.read(1)
    file.close()
    return final

def key_maker(n,password):
    t = n//16+1
    key = ''
    for i in range(t):
        for k in password:
            key += key_file(k,i) 
    return key
    
def encrypter(plain_text,password = False):
    p_len = len(plain_text)
    if password == False:
        password = password_maker()
    key = key_maker(p_len,password)
    value = ''
    for a in range(p_len):
        try:
            sum = symbol_list.index(plain_text[a])+symbol_list.index(key[a])
            value += symbol_list[sum%symbol_list_len]
        except ValueError:
            value += plain_text[a]
    del key
    return (value,password)

def decrypter(value,password):
    p_len = len(value)
    key = key_maker(p_len,password)
    plain_text = ''
    for a in range(p_len):
        try:
            diff = symbol_list.index(value[a])-symbol_list.index(key[a])
            plain_text += symbol_list[diff%symbol_list_len]
        except ValueError:
            plain_text += value[a]
    del key
    return plain_text

test = 'is this the real life? is this just fantasy?'
for i in range(2000):
    v,p = encrypter(test)
    final = decrypter(v,p)
    print(final,' ',p,' ',test==final)
    if test != final:
        print('oh my god something went wrong!')
        print(final,' ',p,' ',test)
        break