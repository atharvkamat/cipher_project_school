from secrets import choice
import string

key_files_path = 'D:\\python projects\\lab activity 3\\cs_project_key_files_final\\New test\\l'

#making of key files
symbols = list(string.printable)
symbols_3_comb = []

for a in symbols:
    for b in symbols:
        for c in symbols:
            symbols_3_comb.append(a+b+c)

pass_list = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e','f']

for n in pass_list:
    with open(key_files_path+str(n)+'.txt','w') as f:
        for i in range(10000):
            f.write(choice(symbols_3_comb))

#makingg of substitution dictionary files
sub_symbols_ord = []
ranges_of_sub_symbols_ord = [(8448, 8528),(8592, 8704),(8704, 8960),(10176, 11085)] #ranges of unicode(in decimal) of math symbols to be used for substitution
for lower,upper in ranges_of_sub_symbols_ord:
    for i in range(lower,upper):
        sub_symbols_ord.append(i)

symbols_to_ord = dict(zip(symbols,range(100)))

sub_symbols_ord_comb3 = []
count = 0
while count<10000:
    temp = []
    for k in range(3):
        temp.append(choice(sub_symbols_ord))
    if temp in sub_symbols_ord_comb3:
        pass
    else:
        count +=1
        sub_symbols_ord_comb3.append(tuple(temp))

symbol_to_sub = {}
sub_to_symbol = {}
for i in symbols:
    for k in range(100):
        temp = choice(sub_symbols_ord_comb3)
        symbol_to_sub[(symbols_to_ord[i],k)]=temp
        sub_to_symbol[temp]= symbols_to_ord[i]
        sub_symbols_ord_comb3.remove(temp)

with open(key_files_path+'substitution_cipher_dictionaries.txt','w') as f:
    f.write(str(symbol_to_sub)+'\n')

    f.write(str(sub_to_symbol))
