# CCSC2020
### WriteUps for the Cyprus Cyber Security Challenge

![Jaskier Challenge](Jaskier.JPG)

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
