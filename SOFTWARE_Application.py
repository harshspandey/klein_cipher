from tkinter import *
import socket
import tkinter
import os
from tkinter import filedialog
from tkinter import simpledialog
from tkinter import messagebox
import random





from itertools import zip_longest

SBOX = [0x7, 0x4, 0xA, 0x9, 0x1, 0xF, 0xB, 0x0,
        0xC, 0x3, 0x2, 0x6, 0x8, 0xE, 0xD, 0x5]


def sbox_nibble(bits, i, N):
    offset = N - (i+1)*4
    nibble = (bits >> offset) & 0xF  # fetch the nibble
    return bits & ~(0xF << offset) | (SBOX[nibble] << offset)  # add back in

class KLEIN(object):


    def __init__(self, nr=12, size=64):
        self.nr = nr
        self.size = size

    def addRoundKey(self, state, sk):
        return state ^ (sk >> self.size-64) & 0xFFFFFFFFFFFFFFFF

    def subNibbles(self, state):
        for i in range(16):
            state = sbox_nibble(state, i, 64)
        return state

    def rotateNibbles(self, state):
        return (state << 16) & 0xFFFFFFFFFFFFFFFF | (state >> 48)

    def mixNibbles(self, state):
        def mix_columns(bits):
            c01 = 0xFF & (bits >> 24)
            c23 = 0xFF & (bits >> 16)
            c45 = 0xFF & (bits >> 8)
            c67 = 0xFF & bits

            def mul2or3(x, n):  # this is not nearly as generic as galoisMult
                x = (x << 1) if n == 2 else ((x << 1) ^ x)
                if x > 0xFF:
                    return (x ^ 0x1B) & 0xFF
                return x

            s01 = mul2or3(c01, 2) ^ mul2or3(c23, 3) ^ c45 ^ c67
            s23 = c01 ^ mul2or3(c23, 2) ^ mul2or3(c45, 3) ^ c67
            s45 = c01 ^ c23 ^ mul2or3(c45, 2) ^ mul2or3(c67, 3)
            s67 = mul2or3(c01, 3) ^ c23 ^ c45 ^ mul2or3(c67, 2)
            return s01 << 24 | s23 << 16 | s45 << 8 | s67

        col1 = mix_columns(state >> 32)
        col2 = mix_columns(state & 0xFFFFFFFFFFFFFFFF)
        return col1 << 32 | col2

    def keySchedule(self, sk, i):
        a = (sk >> self.size//2)
        b = sk & int('1' * (self.size//2), 2)
        a = (a << 8) & int('1' * (self.size//2), 2) | (a >> (self.size//2 - 8))
        b = (b << 8) & int('1' * (self.size//2), 2) | (b >> (self.size//2 - 8))
        a ^= b
        a, b = b, a
        a ^= i << (self.size//2 - 24)
        for i in range(2, 6):
            b = sbox_nibble(b, i, self.size//2)
        return a << self.size//2 | b

    def encrypt(self, key, plaintext):
        state = plaintext
        sk = key
        for i in range(1, self.nr+1):
            state = self.addRoundKey(state, sk)
            state = self.subNibbles(state)
            state = self.rotateNibbles(state)
            state = self.mixNibbles(state)
            sk = self.keySchedule(sk, i)
        state = self.addRoundKey(state, sk)
        return state


klein64 =KLEIN(nr=12, size=64)


def encrypt_klein_64_block(msg,key):

    msg=int.from_bytes(msg, "big") & 0x0F
    key= int.from_bytes(key, "big") & 0x0F

    temp=klein64.encrypt(key,msg)


    temp=bytearray.fromhex('{:0016x}'.format(temp))
    temp=bytes(temp)
    return temp


def bxor(a, b, longest=True):
    if longest:
        return bytes([ x^y for (x, y) in zip_longest(a, b, fillvalue=0)])
    else:
        return bytes([ x^y for (x, y) in zip(a, b)])


def klein_64_ctr_keystream_generator(key, nonce):
    counter = 0
    while True:
        to_encrypt = (nonce.to_bytes(length=4, byteorder='little')
                     +counter.to_bytes(length=4, byteorder='little'))
        keystream_block = encrypt_klein_64_block(to_encrypt, key)
        yield from keystream_block

        counter += 1

def klein_64_ctr_transform(msg, key, nonce):
    keystream = klein_64_ctr_keystream_generator(key, nonce)
    return bxor(msg, keystream, longest=False)


def ENCRYPT_DECRYPT(BINARY_DATA,key,nonce):
    return klein_64_ctr_transform(BINARY_DATA, key, nonce)






#key_assigned="0"
nonce_assigned=1
#binary_assigned=b'0'









sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.connect(("8.8.8.8", 80))
#print(sock.getsockname())

IP_ADDR=sock.getsockname()
IP_ADDR=IP_ADDR[0]
IP_ADDR_str=str(IP_ADDR)
sock.close()





root=Tk()
root.geometry("305x600")
root.resizable(False,False)
root.title("KLEIN Cipher- File Transfer")

frame=Frame(root)
frame.pack()

#Displaying Host Name

host_name=Label(frame,text="HOST NAME: "+socket.gethostname(),font=("Arial", 13,"bold"),bg="lightblue",fg="darkblue")
host_name.pack(ipadx=80,fill=BOTH)

#Displaying Ip Address
#ip_name=Label(frame,text="IP ADDRESS: "+socket.gethostbyname(socket.gethostname()),font=("Arial", 13,"bold"),bg="lightblue",fg="darkblue")

ip_name=Label(frame,text="IP ADDRESS: "+IP_ADDR_str,font=("Arial", 13,"bold"),bg="lightblue",fg="darkblue")


ip_name.pack(ipadx=80,fill=BOTH)

#Creating List For File Adding
file_list=Listbox(root,bg="lightgrey",width=20)
file_list.pack(ipadx=90)

#Creating Message Box
note=Label(root,text="Wait Checking Your Connectivity...",bg="black",fg="cyan",font=("Arial",10,"bold"))
note.pack(ipadx=150)

#Checking Internet Connection

timeout=5
try:
    #request = requests.get(url, timeout=timeout)
    note.config(text="O n l i n e")
except:
    note.config(fg="red",text="Offline")
    ip_name.configure(padx=19)   # Only for Looks

#function for adding and removing files

def add():
    global filename
    filename = filedialog.askopenfilename()
    c=str(filename)
    name=os.path.basename(filename)
    if bool(c) is True:
        box.configure(fg="green")
        file_list.insert(END,name)
        box.insert(END,"File Added Succesfully......\n")
    else:
        box.insert(END,"File Not Selected ......\n")

    


    

def remove():
    file_list.delete(ACTIVE)

#File Sharing
def send():

    key_assigned=simpledialog.askstring("ENCRYPTION KEY","ENTER KEY FOR ENCRYPTION: ",parent=root)
    key_assigned=str(key_assigned)
    key_assigned=key_assigned.encode("ascii")


    messagebox.showinfo("Ready To Send....", "Type address or Host name From Reciever Side")
    
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    s.bind((IP_ADDR,1234))
    s.listen(1)
    print(socket.gethostname()) #To Know Socket Name 
    try:
        cli,adr=s.accept()
        box.insert(END,"Waiting For Connection....\n")
        box.insert(END,"Connected Succesfully To: "+str(adr) + "\n")
    except socket.error as error:
        box.insert(END,str(error))
    file_s=filename
    a=os.path.getsize(file_s)
    name,exte=os.path.splitext(file_s)
    b=str(a)
    cli.send(bytes(exte,"utf-8"))  #Sending File  Extension To Client

    print(a)  #Sending File Size To Client
    cli.send(bytes(b,"utf-8"))
    f=open(file_s,"rb")

    data=ENCRYPT_DECRYPT(f.read(a),key_assigned,nonce_assigned)

    while data:
        cli.send(data)
        data=f.read(a)
        f.close()
        box.insert(END,"File Transfered Succesfully To: " +str(socket.gethostname())+"\n")


#Receving File

def rec():
    ip=simpledialog.askstring("RECIEVER ADDDRESS","ENTER HOST NAME OR IP ADDRESS: ",parent=root)
    


    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    host=ip
    try:
        s.connect((host,1234))
        box.insert(END,"Succesfully Connected With: "+str(host)+"\n")
    except socket.error as error:
        box.insert(END,str(error))

    directory="PyShare"
    parent_dir="C:/"

    ext=s.recv(10000)
    exte=ext.decode("utf-8")
    print(exte)

    msg=s.recv(100000)
    a=msg.decode("utf-8")
    print(a)
    b=int(a)

    key_assigned=simpledialog.askstring("DECRYPTION KEY","ENTER KEY FOR DECRYPTION: ",parent=root)
    key_assigned=key_assigned.encode("ascii")

    file_name=simpledialog.askstring("FILENAME","NAME OF RECIEVED FILE:",parent=root)

    if file_name is not None:     
        file_s=str(file_name+str(exte))
        path = os.path.join(parent_dir,directory)
        try:  
            os.mkdir(path)  
        except OSError as error:  
            print("\n")
        save=os.path.join(path,file_s)
        f=open(save,"wb")
        data=s.recv(b,socket.MSG_WAITALL)




        temp_var=ENCRYPT_DECRYPT(data,key_assigned,nonce_assigned)



        f.write(temp_var)
        f.close()
        box.insert(END,"Your File Is Recieved At: C://PyShare//"+str(file_s)+"\n")
    else:
        name2=str(random.randrange(1,50641206))
        file_s=str(name2+str(exte))
        path = os.path.join(parent_dir,directory)
        try:  
            os.mkdir(path)  
        except OSError as error:  
            print("\n")
        save=os.path.join(path,file_s)
        f=open(save,"wb")
        data=s.recv(b,socket.MSG_WAITALL)

        temp_var=ENCRYPT_DECRYPT(data,key_assigned,nonce_assigned)



        f.write(temp_var)
        f.close()
        box.insert(END,"Your File Is Recieved At: C://PyShare//"+str(file_s)+"\n")







#frame for Button
frame1=Frame(root,bg="lightgrey")
frame1.pack()

#Creating Button For Adding and Removing Files
add=Button(frame1,text="ADD FILES",font=("Arial",10,"bold"),bg="lightgreen",command=add)
add.grid(row=4,padx=5,ipadx=35,ipady=30)

remove=Button(frame1,text="REMOVE FILE",font=("Arial",10,"bold"),bg="#fa8e70",command=remove)
remove.grid(row=4,column=2,ipadx=15,ipady=30)

#Creating Send Button
send=Button(frame1,text="SEND",font=("Arial",10,"bold"),bg="darkorchid3",command=send)
send.grid(row=5,padx=5,ipadx=52,ipady=30)

#Creating Recieve Button
rec=Button(frame1,text="RECIEVE",font=("Arial",10,"bold"),bg="cyan2",command=rec)
rec.grid(row=5,column=2,padx=5,ipadx=32,ipady=30)



#creating Message Box 
box=Text(root,font=("Arial"),height=10,width=50,bg="black",fg="turquoise")
box.pack()

root.mainloop()
