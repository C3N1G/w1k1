> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [wiki.xazlsec.com](https://wiki.xazlsec.com/project-15/doc-251/)

> ## 什么是堆 在程序运行过程中，堆可以提供动态分配的内存，允许程序申请大小未知的内存。堆其实就是程序虚拟地址空间的一块连续的线性区域，它由低地址向高地址方向增长。我们一般称管理堆的那部分程序为堆管

什么是堆
----

在程序运行过程中，堆可以提供动态分配的内存，允许程序申请大小未知的内存。堆其实就是程序虚拟地址空间的一块连续的线性区域，它由低地址向高地址方向增长。我们一般称管理堆的那部分程序为堆管理器。

堆管理器处于用户程序与内核中间，主要做以下工作

1.  响应用户的申请内存请求，向操作系统申请内存，然后将其返回给用户程序。同时，为了保持内存管理的高效性，内核一般都会预先分配很大的一块连续的内存，然后让堆管理器通过某种算法管理这块内存。只有当出现了堆空间不足的情况，堆管理器才会再次与操作系统进行交互。
2.  管理用户所释放的内存。一般来说，用户释放的内存并不是直接返还给操作系统的，而是由堆管理器进行管理。这些释放的内存可以来响应用户新申请的内存的请求。

Linux 中早期的堆分配与回收由 Doug Lea 实现，但它在并行处理多个线程时，会共享进程的堆内存空间。因此，为了安全性，一个线程使用堆时，会进行加锁。然而，与此同时，加锁会导致其它线程无法使用堆，降低了内存分配和回收的高效性。同时，如果在多线程使用时，没能正确控制，也可能影响内存分配和回收的正确性。Wolfram Gloger 在 Doug Lea 的基础上进行改进使其可以支持多线程，这个堆分配器就是 ptmalloc 。在 glibc-2.3.x. 之后，glibc 中集成了 ptmalloc2。

目前 Linux 标准发行版中使用的堆分配器是 glibc 中的堆分配器：ptmalloc2。ptmalloc2 主要是通过 malloc/free 函数来分配和释放内存块。

需要注意的是，在内存分配与使用的过程中，Linux 有这样的一个基本内存管理思想，**只有当真正访问一个地址的时候，系统才会建立虚拟页面与物理页面的映射关系**。 所以虽然操作系统已经给程序分配了很大的一块内存，但是这块内存其实只是虚拟内存。只有当用户使用到相应的内存时，系统才会真正分配物理页面给用户使用。

堆的基本操作
------

这里我们主要介绍

*   基本的堆操作，包括堆的分配，回收，堆分配背后的系统调用
*   介绍堆目前的多线程支持。

### malloc

在 glibc 的 [malloc.c](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L448) 中，malloc 的说明如下

```
/*
  malloc(size_t n)
  Returns a pointer to a newly allocated chunk of at least n bytes, or null
  if no space is available. Additionally, on failure, errno is
  set to ENOMEM on ANSI C systems.
  If n is zero, malloc returns a minumum-sized chunk. (The minimum
  size is 16 bytes on most 32bit systems, and 24 or 32 bytes on 64bit
  systems.)  On most systems, size_t is an unsigned type, so calls
  with negative arguments are interpreted as requests for huge amounts
  of space, which will often fail. The maximum supported value of n
  differs across systems, but is in all cases less than the maximum
  representable value of a size_t.
*/

```

可以看出，malloc 函数返回对应大小字节的内存块的指针。此外，该函数还对一些异常情况进行了处理

*   当 n=0 时，返回当前系统允许的堆的最小内存块。
*   当 n 为负数时，由于在大多数系统上，**size_t 是无符号数（这一点非常重要）**，所以程序就会申请很大的内存空间，但通常来说都会失败，因为系统没有那么多的内存可以分配。

### free

在 glibc 的 [malloc.c](https://github.com/iromise/glibc/blob/master/malloc/malloc.c#L465) 中，free 的说明如下

```
/*
      free(void* p)
      Releases the chunk of memory pointed to by p, that had been previously
      allocated using malloc or a related routine such as realloc.
      It has no effect if p is null. It can have arbitrary (i.e., bad!)
      effects if p has already been freed.
      Unless disabled (using mallopt), freeing very large spaces will
      when possible, automatically trigger operations that give
      back unused memory to the system, thus reducing program footprint.
    */

```

可以看出，free 函数会释放由 p 所指向的内存块。这个内存块有可能是通过 malloc 函数得到的，也有可能是通过相关的函数 realloc 得到的。

此外，该函数也同样对异常情况进行了处理

*   **当 p 为空指针时，函数不执行任何操作。**
*   当 p 已经被释放之后，再次释放会出现乱七八糟的效果，这其实就是 `double free`。
*   除了被禁用 (mallopt) 的情况下，当释放很大的内存空间时，程序会将这些内存空间还给系统，以便于减小程序所使用的内存空间。

### 内存分配背后的系统调用

在前面提到的函数中，无论是 malloc 函数还是 free 函数，我们动态申请和释放内存时，都经常会使用，但是它们并不是真正与系统交互的函数。这些函数背后的系统调用主要是 [(s)brk](http://man7.org/linux/man-pages/man2/sbrk.2.html) 函数以及 [mmap, munmap](http://man7.org/linux/man-pages/man2/mmap.2.html) 函数。

如下图所示，我们主要考虑对堆进行申请内存块的操作。

![](data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAADIAAAAyCAYAAAAeP4ixAAACbklEQVRoQ+2aMU4dMRCGZw6RC1CSSyQdLZJtKQ2REgoiRIpQkCYClCYpkgIESQFIpIlkW+IIcIC0gUNwiEFGz+hlmbG9b1nesvGW++zxfP7H4/H6IYzkwZFwQAUZmpJVkSeniFJKA8ASIi7MyfkrRPxjrT1JjZ8MLaXUDiJuzwngn2GJaNd7vyP5IoIYY94Q0fEQIKIPRGS8947zSQTRWh8CwLuBgZx479+2BTkHgBdDAgGAC+fcywoyIFWqInWN9BSONbTmFVp/AeA5o+rjKRJ2XwBYRsRXM4ZXgAg2LAPzOCDTJYQx5pSIVlrC3EI45y611osMTHuQUPUiYpiVooerg7TWRwDAlhSM0TuI+BsD0x4kGCuFSRVzSqkfiLiWmY17EALMbCAlMCmI6IwxZo+INgQYEYKBuW5da00PKikjhNNiiPGm01rrbwDwofGehQjjNcv1SZgddALhlJEgwgJFxDNr7acmjFLqCyJuTd6LEGFttpmkYC91Hrk3s1GZFERMmUT01Xv/sQljjPlMRMsxO6WULwnb2D8FEs4j680wScjO5f3vzrlNJszESWq2LYXJgTzjZm56MCHf3zVBxH1r7ftU1splxxKYHEgoUUpTo+grEf303rPH5hxENJqDKQEJtko2q9zGeeycWy3JhpKhWT8+NM/sufIhBwKI+Mta+7pkfxKMtd8Qtdbcx4dUQZcFCQ2I6DcAnLUpf6YMPxhIDDOuxC4C6djoQUE6+tKpewWZ1wlRkq0qUhXptKTlzv93aI3jWmE0Fz2TeujpX73F9TaKy9CeMk8vZusfBnqZ1g5GqyIdJq+XrqNR5AahKr9CCcxGSwAAAABJRU5ErkJggg==)

#### (s)brk

对于堆的操作，操作系统提供了 brk 函数，glibc 库提供了 sbrk 函数，我们可以通过增加 [brk](https://en.wikipedia.org/wiki/Sbrk) 的大小来向操作系统申请内存。

初始时，堆的起始地址 [start_brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 以及堆的当前末尾 [brk](http://elixir.free-electrons.com/linux/v3.8/source/include/linux/mm_types.h#L365) 指向同一地址。根据是否开启 ASLR，两者的具体位置会有所不同

*   不开启 ASLR 保护时，start_brk 以及 brk 会指向 data/bss 段的结尾。
*   开启 ASLR 保护时，start_brk 以及 brk 也会指向同一位置，只是这个位置是在 data/bss 段结尾后的随机偏移处。

具体效果如下图（这个图片与网上流传的基本一致，这里是因为要画一张大图，所以自己单独画了下）所示

![][img-0]

**例子**

```
/* sbrk and brk example */
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
int main()
{
        void *curr_brk, *tmp_brk = NULL;
        printf("Welcome to sbrk example:%d\n", getpid());
        /* sbrk(0) gives current program break location */
        tmp_brk = curr_brk = sbrk(0);
        printf("Program Break Location1:%p\n", curr_brk);
        getchar();
        /* brk(addr) increments/decrements program break location */
        brk(curr_brk+4096);
        curr_brk = sbrk(0);
        printf("Program break Location2:%p\n", curr_brk);
        getchar();
        brk(tmp_brk);
        curr_brk = sbrk(0);
        printf("Program Break Location3:%p\n", curr_brk);
        getchar();
        return 0;
}

```

需要注意的是，在每一次执行完操作后，都执行了 getchar() 函数，这是为了我们方便我们查看程序真正的映射。

**在第一次调用 brk 之前**

从下面的输出可以看出，并没有出现堆。因此

*   start_brk = brk = end_data = 0x804b000

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ ./sbrk
Welcome to sbrk example:6141
Program Break Location1:0x804b000
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6141/maps
...
0804a000-0804b000 rw-p 00001000 08:01 539624     /home/sploitfun/ptmalloc.ppt/syscalls/sbrk
b7e21000-b7e22000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$

```

**第一次增加 brk 后**

从下面的输出可以看出，已经出现了堆段

*   start_brk = end_data = 0x804b000
*   brk = 0x804c000

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ ./sbrk
Welcome to sbrk example:6141
Program Break Location1:0x804b000
Program Break Location2:0x804c000
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6141/maps
...
0804a000-0804b000 rw-p 00001000 08:01 539624     /home/sploitfun/ptmalloc.ppt/syscalls/sbrk
0804b000-0804c000 rw-p 00000000 00:00 0          [heap]
b7e21000-b7e22000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$

```

其中，关于堆的那一行

*   0x0804b000 是相应堆的起始地址
*   rw-p 表明堆具有可读可写权限，并且属于隐私数据。
*   00000000 表明文件偏移，由于这部分内容并不是从文件中映射得到的，所以为 0。
*   00:00 是主从 (Major/mirror) 的设备号，这部分内容也不是从文件中映射得到的，所以也都为 0。
*   0 表示着 Inode 号。由于这部分内容并不是从文件中映射得到的，所以为 0。

#### mmap

malloc 会使用 [mmap](http://lxr.free-electrons.com/source/mm/mmap.c?v=3.8#L1285) 来创建独立的匿名映射段。匿名映射的目的主要是可以申请以 0 填充的内存，并且这块内存仅被调用进程所使用。

**例子**

```
/* Private anonymous mapping example using mmap syscall */
#include <stdio.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
void static inline errExit(const char* msg)
{
        printf("%s failed. Exiting the process\n", msg);
        exit(-1);
}
int main()
{
        int ret = -1;
        printf("Welcome to private anonymous mapping example::PID:%d\n", getpid());
        printf("Before mmap\n");
        getchar();
        char* addr = NULL;
        addr = mmap(NULL, (size_t)132*1024, PROT_READ|PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (addr == MAP_FAILED)
                errExit("mmap");
        printf("After mmap\n");
        getchar();
        /* Unmap mapped region. */
        ret = munmap(addr, (size_t)132*1024);
        if(ret == -1)
                errExit("munmap");
        printf("After munmap\n");
        getchar();
        return 0;
}

```

**在执行 mmap 之前**

我们可以从下面的输出看到，目前只有. so 文件的 mmap 段。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e21000-b7e22000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$

```

**mmap 后**

从下面的输出可以看出，我们申请的内存与已经存在的内存段结合在了一起构成了 b7e00000 到 b7e21000 的 mmap 段。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e00000-b7e22000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$

```

**munmap**

从下面的输出，我们可以看到我们原来申请的内存段已经没有了，内存段又恢复了原来的样子了。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$ cat /proc/6067/maps
08048000-08049000 r-xp 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
08049000-0804a000 r--p 00000000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
0804a000-0804b000 rw-p 00001000 08:01 539691     /home/sploitfun/ptmalloc.ppt/syscalls/mmap
b7e21000-b7e22000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/syscalls$

```

### 多线程支持

在原来的 dlmalloc 实现中，当两个线程同时要申请内存时，只有一个线程可以进入临界区申请内存，而另外一个线程则必须等待直到临界区中不再有线程。这是因为所有的线程共享一个堆。在 glibc 的 ptmalloc 实现中，比较好的一点就是支持了多线程的快速访问。在新的实现中，所有的线程共享多个堆。

这里给出一个例子。

```
/* Per thread arena example. */
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <sys/types.h>
void* threadFunc(void* arg) {
        printf("Before malloc in thread 1\n");
        getchar();
        char* addr = (char*) malloc(1000);
        printf("After malloc and before free in thread 1\n");
        getchar();
        free(addr);
        printf("After free in thread 1\n");
        getchar();
}
int main() {
        pthread_t t1;
        void* s;
        int ret;
        char* addr;
        printf("Welcome to per thread arena example::%d\n",getpid());
        printf("Before malloc in main thread\n");
        getchar();
        addr = (char*) malloc(1000);
        printf("After malloc and before free in main thread\n");
        getchar();
        free(addr);
        printf("After free in main thread\n");
        getchar();
        ret = pthread_create(&t1, NULL, threadFunc, NULL);
        if(ret)
        {
                printf("Thread creation error\n");
                return -1;
        }
        ret = pthread_join(t1, &s);
        if(ret)
        {
                printf("Thread join error\n");
                return -1;
        }
        return 0;
}

```

**第一次申请之前**， 没有任何任何堆段。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread
Welcome to per thread arena example::6501
Before malloc in main thread
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
b7e05000-b7e07000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$

```

**第一次申请后**， 从下面的输出可以看出，堆段被建立了，并且它就紧邻着数据段，这说明 malloc 的背后是用 brk 函数来实现的。同时，需要注意的是，我们虽然只是申请了 1000 个字节，但是我们却得到了 0x0806c000-0x0804b000=0x21000 个字节的堆。**这说明虽然程序可能只是向操作系统申请很小的内存，但是为了方便，操作系统会把很大的内存分配给程序。这样的话，就避免了多次内核态与用户态的切换，提高了程序的效率。**我们称这一块连续的内存区域为 arena。此外，我们称由主线程申请的内存为 main_arena。后续的申请的内存会一直从这个 arena 中获取，直到空间不足。当 arena 空间不足时，它可以通过增加 brk 的方式来增加堆的空间。类似地，arena 也可以通过减小 brk 来缩小自己的空间。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$

```

**在主线程释放内存后**，我们从下面的输出可以看出，其对应的 arena 并没有进行回收，而是交由 glibc 来进行管理。当后面程序再次申请内存时，在 glibc 中管理的内存充足的情况下，glibc 就会根据堆分配的算法来给程序分配相应的内存。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
...
sploitfun@sploitfun-VirtualBox:~/lsploits/hof/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7e05000-b7e07000 rw-p 00000000 00:00 0
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$

```

**在第一个线程 malloc 之前**，我们可以看到并没有出现与线程 1 相关的堆，但是出现了与线程 1 相关的栈。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7604000-b7605000 ---p 00000000 00:00 0
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$

```

**第一个线程 malloc 后**， 我们可以从下面输出看出线程 1 的堆段被建立了。而且它所在的位置为内存映射段区域，同样大小也是 132KB(b7500000-b7521000)。因此这表明该线程申请的堆时，背后对应的函数为 mmap 函数。同时，我们可以看出实际真的分配给程序的内存为 1M(b7500000-b7600000)。而且，只有 132KB 的部分具有可读可写权限，这一块连续的区域成为 thread arena。

注意：

> 当用户请求的内存大于 128KB 时，并且没有任何 arena 有足够的空间时，那么系统就会执行 mmap 函数来分配相应的内存空间。这与这个请求来自于主线程还是从线程无关。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
After malloc and before free in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7500000-b7521000 rw-p 00000000 00:00 0
b7521000-b7600000 ---p 00000000 00:00 0
b7604000-b7605000 ---p 00000000 00:00 0
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$

```

**在第一个线程释放内存后**， 我们可以从下面的输出看到，这样释放内存同样不会把内存重新给系统。

```
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ ./mthread
Welcome to per thread arena example::6501
Before malloc in main thread
After malloc and before free in main thread
After free in main thread
Before malloc in thread 1
After malloc and before free in thread 1
After free in thread 1
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$ cat /proc/6501/maps
08048000-08049000 r-xp 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
08049000-0804a000 r--p 00000000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804a000-0804b000 rw-p 00001000 08:01 539625     /home/sploitfun/ptmalloc.ppt/mthread/mthread
0804b000-0806c000 rw-p 00000000 00:00 0          [heap]
b7500000-b7521000 rw-p 00000000 00:00 0
b7521000-b7600000 ---p 00000000 00:00 0
b7604000-b7605000 ---p 00000000 00:00 0
b7605000-b7e07000 rw-p 00000000 00:00 0          [stack:6594]
...
sploitfun@sploitfun-VirtualBox:~/ptmalloc.ppt/mthread$

```

参考文献
----

*   [sploitfun](https://sploitfun.wordpress.com/archives/)

介绍
--

堆溢出是指程序向某个堆块中写入的字节数超过了堆块本身可使用的字节数（**之所以是可使用而不是用户申请的字节数，是因为堆管理器会对用户所申请的字节数进行调整，这也导致可利用的字节数都不小于用户申请的字节数**），因而导致了数据溢出，并覆盖到**物理相邻的高地址**的下一个堆块。

不难发现，堆溢出漏洞发生的基本前提是

*   程序向堆上写入数据。
*   写入的数据大小没有被良好地控制。

对于攻击者来说，堆溢出漏洞轻则可以使得程序崩溃，重则可以使得攻击者控制程序执行流程。

堆溢出是一种特定的缓冲区溢出（还有栈溢出， bss 段溢出等）。但是其与栈溢出所不同的是，堆上并不存在返回地址等可以让攻击者直接控制执行流程的数据，因此我们一般无法直接通过堆溢出来控制 EIP 。一般来说，我们利用堆溢出的策略是

1.  覆盖与其**物理相邻的下一个 chunk** 的内容。
    *   prev_size
    *   size，主要有三个比特位，以及该堆块真正的大小。
        *   NON_MAIN_ARENA
        *   IS_MAPPED
        *   PREV_INUSE
        *   the True chunk size
    *   chunk content，从而改变程序固有的执行流。
2.  利用堆中的机制（如 unlink 等 ）来实现任意地址写入（ Write-Anything-Anywhere）或控制堆块中的内容等效果，从而来控制程序的执行流。

基本示例
----

下面我们举一个简单的例子：

```
#include <stdio.h>
int main(void) 
{
  char *chunk;
  chunk=malloc(24);
  puts("Get input:");
  gets(chunk);
  return 0;
}

```

这个程序的主要目的是调用 malloc 分配一块堆上的内存，之后向这个堆块中写入一个字符串，如果输入的字符串过长会导致溢出 chunk 的区域并覆盖到其后的 top chunk 之中 (实际上 puts 内部会调用 malloc 分配堆内存，覆盖到的可能并不是 top chunk)。

```
0x602000:    0x0000000000000000    0x0000000000000021 <===chunk
0x602010:    0x0000000000000000    0x0000000000000000
0x602020:    0x0000000000000000    0x0000000000020fe1 <===top chunk
0x602030:    0x0000000000000000    0x0000000000000000
0x602040:    0x0000000000000000    0x0000000000000000

```

print ‘A’*100  
进行写入

```
0x602000:    0x0000000000000000    0x0000000000000021 <===chunk
0x602010:    0x4141414141414141    0x4141414141414141
0x602020:    0x4141414141414141    0x4141414141414141 <===top chunk(已被溢出)
0x602030:    0x4141414141414141    0x4141414141414141
0x602040:    0x4141414141414141    0x4141414141414141

```

小总结
---

堆溢出中比较重要的几个步骤:

### 寻找堆分配函数

通常来说堆是通过调用 glibc 函数 malloc 进行分配的，在某些情况下会使用 calloc 分配。calloc 与 malloc 的区别是 **calloc 在分配后会自动进行清空，这对于某些信息泄露漏洞的利用来说是致命的**。

```
calloc(0x20);
//等同于
ptr=malloc(0x20);
memset(ptr,0,0x20);

```

除此之外，还有一种分配是经由 realloc 进行的，realloc 函数可以身兼 malloc 和 free 两个函数的功能。

```
#include <stdio.h>
int main(void) 
{
  char *chunk,*chunk1;
  chunk=malloc(16);
  chunk1=realloc(chunk,32);
  return 0;
}

```

realloc 的操作并不是像字面意义上那么简单，其内部会根据不同的情况进行不同操作

*   当 realloc(ptr,size) 的 size 不等于 ptr 的 size 时
    *   如果申请 size > 原来 size
        *   如果 chunk 与 top chunk 相邻，直接扩展这个 chunk 到新 size 大小
        *   如果 chunk 与 top chunk 不相邻，相当于 free(ptr),malloc(new_size)
    *   如果申请 size < 原来 size
        *   如果相差不足以容得下一个最小 chunk(64 位下 32 个字节，32 位下 16 个字节)，则保持不变
        *   如果相差可以容得下一个最小 chunk，则切割原 chunk 为两部分，free 掉后一部分
*   当 realloc(ptr,size) 的 size 等于 0 时，相当于 free(ptr)
*   当 realloc(ptr,size) 的 size 等于 ptr 的 size，不进行任何操作

### 寻找危险函数

通过寻找危险函数，我们快速确定程序是否可能有堆溢出，以及有的话，堆溢出的位置在哪里。

常见的危险函数如下

*   输入
    *   gets，直接读取一行，忽略 `'\x00'`
    *   scanf
    *   vscanf
*   输出
    *   sprintf
*   字符串
    *   strcpy，字符串复制，遇到 `'\x00'` 停止
    *   strcat，字符串拼接，遇到 `'\x00'` 停止
    *   bcopy

### 确定填充长度

这一部分主要是计算**我们开始写入的地址与我们所要覆盖的地址之间的距离**。  
一个常见的误区是 malloc 的参数等于实际分配堆块的大小，但是事实上 ptmalloc 分配出来的大小是对齐的。这个长度一般是字长的 2 倍，比如 32 位系统是 8 个字节，64 位系统是 16 个字节。但是对于不大于 2 倍字长的请求，malloc 会直接返回 2 倍字长的块也就是最小 chunk，比如 64 位系统执行`malloc(0)`会返回用户区域为 16 字节的块。

```
#include <stdio.h>
int main(void) 
{
  char *chunk;
  chunk=malloc(0);
  puts("Get input:");
  gets(chunk);
  return 0;
}

```

```
//根据系统的位数，malloc会分配8或16字节的用户空间
0x602000:    0x0000000000000000    0x0000000000000021
0x602010:    0x0000000000000000    0x0000000000000000
0x602020:    0x0000000000000000    0x0000000000020fe1
0x602030:    0x0000000000000000    0x0000000000000000

```

注意用户区域的大小不等于 chunk_head.size，chunk_head.size = 用户区域大小 + 2 * 字长

还有一点是之前所说的用户申请的内存大小会被修改，其有可能会使用与其物理相邻的下一个 chunk 的 prev_size 字段储存内容。回头再来看下之前的示例代码

```
#include <stdio.h>
int main(void) 
{
  char *chunk;
  chunk=malloc(24);
  puts("Get input:");
  gets(chunk);
  return 0;
}

```

观察如上代码，我们申请的 chunk 大小是 24 个字节。但是我们将其编译为 64 位可执行程序时，实际上分配的内存会是 16 个字节而不是 24 个。

```
0x602000:    0x0000000000000000    0x0000000000000021
0x602010:    0x0000000000000000    0x0000000000000000
0x602020:    0x0000000000000000    0x0000000000020fe1

```

16 个字节的空间是如何装得下 24 个字节的内容呢？答案是借用了下一个块的 pre_size 域。我们可来看一下用户申请的内存大小与 glibc 中实际分配的内存大小之间的转换。

```
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)

```

当 req=24 时，request2size(24)=32。而除去 chunk 头部的 16 个字节。实际上用户可用 chunk 的字节数为 16。而根据我们前面学到的知识可以知道 chunk 的 pre_size 仅当它的前一块处于释放状态时才起作用。所以用户这时候其实还可以使用下一个 chunk 的 prev_size 字段，正好 24 个字节。**实际上 ptmalloc 分配内存是以双字为基本单位，以 64 位系统为例，分配出来的空间是 16 的整数倍，即用户申请的 chunk 都是 16 字节对齐的。**

堆的操作就这么复杂，那么在 glibc 内部必然也有精心设计的数据结构来管理它。与堆相应的数据结构主要分为

*   宏观结构，包含堆的宏观信息，可以通过这些数据结构索引堆的基本信息。
*   微观结构，用于具体处理堆的分配与回收中的内存块。

Overview？？？？
------------

**这里给一个宏观的图片。**

微观结构
----

这里首先介绍堆中比较细节的结构，**堆的漏洞利用与这些结构密切相关**。

### malloc_chunk

#### 概述

在程序的执行过程中，我们称由 malloc 申请的内存为 chunk 。这块内存在 ptmalloc 内部用 malloc_chunk 结构体来表示。当程序申请的 chunk 被 free 后，会被加入到相应的空闲管理列表中。

非常有意思的是，**无论一个 chunk 的大小如何，处于分配状态还是释放状态，它们都使用一个统一的结构**。虽然它们使用了同一个数据结构，但是根据是否被释放，它们的表现形式会有所不同。

malloc_chunk 的结构如下

```
/*
  This struct declaration is misleading (but accurate and necessary).
  It declares a "view" into memory allowing access to necessary
  fields at known offsets from a given base. See explanation below.
*/
struct malloc_chunk {
  INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if free).  */
  INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. */
  struct malloc_chunk* fd;         /* double links -- used only if free. */
  struct malloc_chunk* bk;
  /* Only used for large blocks: pointer to next larger size.  */
  struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
  struct malloc_chunk* bk_nextsize;
};

```

首先，这里给出一些必要的解释 INTERNAL_SIZE_T，SIZE_SZ，MALLOC_ALIGN_MASK：

```
/* INTERNAL_SIZE_T is the word-size used for internal bookkeeping of
   chunk sizes.
   The default version is the same as size_t.
   While not strictly necessary, it is best to define this as an
   unsigned type, even if size_t is a signed type. This may avoid some
   artificial size limitations on some systems.
   On a 64-bit machine, you may be able to reduce malloc overhead by
   defining INTERNAL_SIZE_T to be a 32 bit `unsigned int' at the
   expense of not being able to handle more than 2^32 of malloced
   space. If this limitation is acceptable, you are encouraged to set
   this unless you are on a platform requiring 16byte alignments. In
   this case the alignment requirements turn out to negate any
   potential advantages of decreasing size_t word size.
   Implementors: Beware of the possible combinations of:
     - INTERNAL_SIZE_T might be signed or unsigned, might be 32 or 64 bits,
       and might be the same width as int or as long
     - size_t might have different width and signedness as INTERNAL_SIZE_T
     - int and long might be 32 or 64 bits, and might be the same width
   To deal with this, most comparisons and difference computations
   among INTERNAL_SIZE_Ts should cast them to unsigned long, being
   aware of the fact that casting an unsigned int to a wider long does
   not sign-extend. (This also makes checking for negative numbers
   awkward.) Some of these casts result in harmless compiler warnings
   on some systems.  */
#ifndef INTERNAL_SIZE_T
# define INTERNAL_SIZE_T size_t
#endif
/* The corresponding word size.  */
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
/* The corresponding bit mask value.  */
#define MALLOC_ALIGN_MASK (MALLOC_ALIGNMENT - 1)

```

一般来说，size_t 在 64 位中是 64 位无符号整数，32 位中是 32 位无符号整数。

每个字段的具体的解释如下

*   **prev_size**, 如果该 chunk 的**物理相邻的前一地址 chunk（两个指针的地址差值为前一 chunk 大小）**是空闲的话，那该字段记录的是前一个 chunk 的大小 (包括 chunk 头)。否则，该字段可以用来存储物理相邻的前一个 chunk 的数据。** 这里的前一 chunk 指的是较低地址的 chunk **。
*   **size** ，该 chunk 的大小，大小必须是 2 * SIZE_SZ 的整数倍。如果申请的内存大小不是 2 * SIZE_SZ 的整数倍，会被转换满足大小的最小的 2 * SIZE_SZ 的倍数。32 位系统中，SIZE_SZ 是 4；64 位系统中，SIZE_SZ 是 8。 该字段的低三个比特位对 chunk 的大小没有影响，它们从高到低分别表示
    *   NON_MAIN_ARENA，记录当前 chunk 是否不属于主线程，1 表示不属于，0 表示属于。
    *   IS_MAPPED，记录当前 chunk 是否是由 mmap 分配的。
    *   PREV_INUSE，记录前一个 chunk 块是否被分配。一般来说，堆中第一个被分配的内存块的 size 字段的 P 位都会被设置为 1，以便于防止访问前面的非法内存。当一个 chunk 的 size 的 P 位为 0 时，我们能通过 prev_size 字段来获取上一个 chunk 的大小以及地址。这也方便进行空闲 chunk 之间的合并。
*   **fd，bk**。 chunk 处于分配状态时，从 fd 字段开始是用户的数据。chunk 空闲时，会被添加到对应的空闲管理链表中，其字段的含义如下
    *   fd 指向下一个（非物理相邻）空闲的 chunk
    *   bk 指向上一个（非物理相邻）空闲的 chunk
    *   通过 fd 和 bk 可以将空闲的 chunk 块加入到空闲的 chunk 块链表进行统一管理
*   **fd_nextsize， bk_nextsize**，也是只有 chunk 空闲的时候才使用，不过其用于较大的 chunk（large chunk）。
    *   fd_nextsize 指向前一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。
    *   bk_nextsize 指向后一个与当前 chunk 大小不同的第一个空闲块，不包含 bin 的头指针。
    *   一般空闲的 large chunk 在 fd 的遍历顺序中，按照由大到小的顺序排列。**这样做可以避免在寻找合适 chunk 时挨个遍历。**

一个已经分配的 chunk 的样子如下。**我们称前两个字段称为 chunk header，后面的部分称为 user data。每次 malloc 申请得到的内存指针，其实指向 user data 的起始处。**

当一个 chunk 处于使用状态时，它的下一个 chunk 的 prev_size 域无效，所以下一个 chunk 的该部分也可以被当前 chunk 使用。**这就是 chunk 中的空间复用。**

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of chunk, in bytes                     |A|M|P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             User data starts here...                          .
        .                                                               .
        .             (malloc_usable_size() bytes)                      .
next    .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             (size of chunk, but used for application data)    |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|1|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

被释放的 chunk 被记录在链表中（可能是循环双向链表，也可能是单向链表）。具体结构如下

```
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of previous chunk, if unallocated (P clear)  |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`head:' |             Size of chunk, in bytes                     |A|0|P|
  mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Forward pointer to next chunk in list             |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Back pointer to previous chunk in list            |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Unused space (may be 0 bytes long)                .
        .                                                               .
 next   .                                                               |
chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
`foot:' |             Size of chunk, in bytes                           |
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
        |             Size of next chunk, in bytes                |A|0|0|
        +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

```

可以发现，如果一个 chunk 处于 free 状态，那么会有两个位置记录其相应的大小

1.  本身的 size 字段会记录，
    
2.  它后面的 chunk 会记录。
    

**一般情况下**，物理相邻的两个空闲 chunk 会被合并为一个 chunk 。堆管理器会通过 prev_size 字段以及 size 字段合并两个物理相邻的空闲 chunk 块。

**！！！一些关于堆的约束，后面详细考虑！！！**

```
/*
    The three exceptions to all this are:
     1. The special chunk `top' doesn't bother using the
    trailing size field since there is no next contiguous chunk
    that would have to index off it. After initialization, `top'
    is forced to always exist.  If it would become less than
    MINSIZE bytes long, it is replenished.
     2. Chunks allocated via mmap, which have the second-lowest-order
    bit M (IS_MMAPPED) set in their size fields.  Because they are
    allocated one-by-one, each must contain its own trailing size
    field.  If the M bit is set, the other bits are ignored
    (because mmapped chunks are neither in an arena, nor adjacent
    to a freed chunk).  The M bit is also used for chunks which
    originally came from a dumped heap via malloc_set_state in
    hooks.c.
     3. Chunks in fastbins are treated as allocated chunks from the
    point of view of the chunk allocator.  They are consolidated
    with their neighbors only in bulk, in malloc_consolidate.
*/

```

#### chunk 相关宏

这里主要介绍 chunk 的大小、对齐检查以及一些转换的宏。

**chunk 与 mem 指针头部的转换**

mem 指向用户得到的内存的起始位置。

```
/* conversion from malloc headers to user pointers, and back */
#define chunk2mem(p) ((void *) ((char *) (p) + 2 * SIZE_SZ))
#define mem2chunk(mem) ((mchunkptr)((char *) (mem) -2 * SIZE_SZ))

```

**最小的 chunk 大小**

```
/* The smallest possible chunk */
#define MIN_CHUNK_SIZE (offsetof(struct malloc_chunk, fd_nextsize))

```

这里，offsetof 函数计算出 fd_nextsize 在 malloc_chunk 中的偏移，说明最小的 chunk 至少要包含 bk 指针。

**最小申请的堆内存大小**

用户最小申请的内存大小必须是 2 * SIZE_SZ 的最小整数倍。

**注：就目前而看 MIN_CHUNK_SIZE 和 MINSIZE 大小是一致的，个人认为之所以要添加两个宏是为了方便以后修改 malloc_chunk 时方便一些。**

```
/* The smallest size we can malloc is an aligned minimal chunk */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define MINSIZE                                                                \
    (unsigned long) (((MIN_CHUNK_SIZE + MALLOC_ALIGN_MASK) &                   \
                      ~MALLOC_ALIGN_MASK))

```

**检查分配给用户的内存是否对齐**

2 * SIZE_SZ 大小对齐。

```
/* Check if m has acceptable alignment */
// MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define aligned_OK(m) (((unsigned long) (m) & MALLOC_ALIGN_MASK) == 0)
#define misaligned_chunk(p)                                                    \
    ((uintptr_t)(MALLOC_ALIGNMENT == 2 * SIZE_SZ ? (p) : chunk2mem(p)) &       \
     MALLOC_ALIGN_MASK)

```

**请求字节数判断**

```
/*
   Check if a request is so large that it would wrap around zero when
   padded and aligned. To simplify some other code, the bound is made
   low enough so that adding MINSIZE will also not wrap around zero.
 */
#define REQUEST_OUT_OF_RANGE(req)                                              \
    ((unsigned long) (req) >= (unsigned long) (INTERNAL_SIZE_T)(-2 * MINSIZE))

```

**将用户请求内存大小转为实际分配内存大小**

```
/* pad request bytes into a usable size -- internal version */
//MALLOC_ALIGN_MASK = 2 * SIZE_SZ -1
#define request2size(req)                                                      \
    (((req) + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE)                           \
         ? MINSIZE                                                             \
         : ((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
/*  Same, except also perform argument check */
#define checked_request2size(req, sz)                                          \
    if (REQUEST_OUT_OF_RANGE(req)) {                                           \
        __set_errno(ENOMEM);                                                   \
        return 0;                                                              \
    }                                                                          \
    (sz) = request2size(req);

```

当一个 chunk 处于已分配状态时，它的物理相邻的下一个 chunk 的 prev_size 字段必然是无效的，故而这个字段就可以被当前这个 chunk 使用。这就是 ptmalloc 中 chunk 间的复用。具体流程如下

1.  首先，利用 REQUEST_OUT_OF_RANGE 判断是否可以分配用户请求的字节大小的 chunk。
2.  其次，需要注意的是用户请求的字节是用来存储数据的，即 chunk header 后面的部分。与此同时，由于 chunk 间复用，所以可以使用下一个 chunk 的 prev_size 字段。因此，这里只需要再添加 SIZE_SZ 大小即可以完全存储内容。
3.  由于系统中所允许的申请的 chunk 最小是 MINSIZE，所以与其进行比较。如果不满足最低要求，那么就需要直接分配 MINSIZE 字节。
4.  如果大于的话，因为系统中申请的 chunk 需要 2 * SIZE_SZ 对齐，所以这里需要加上 MALLOC_ALIGN_MASK 以便于对齐。

**个人认为，这里在 request2size 的宏的第一行中没有必要加上 MALLOC_ALIGN_MASK。**

**需要注意的是，通过这样的计算公式得到的 size 最终一定是满足用户需要的。**

**标记位相关**

```
/* size field is or'ed with PREV_INUSE when previous adjacent chunk in use */
#define PREV_INUSE 0x1
/* extract inuse bit of previous chunk */
#define prev_inuse(p) ((p)->mchunk_size & PREV_INUSE)
/* size field is or'ed with IS_MMAPPED if the chunk was obtained with mmap() */
#define IS_MMAPPED 0x2
/* check for mmap()'ed chunk */
#define chunk_is_mmapped(p) ((p)->mchunk_size & IS_MMAPPED)
/* size field is or'ed with NON_MAIN_ARENA if the chunk was obtained
   from a non-main arena.  This is only set immediately before handing
   the chunk to the user, if necessary.  */
#define NON_MAIN_ARENA 0x4
/* Check for chunk from main arena.  */
#define chunk_main_arena(p) (((p)->mchunk_size & NON_MAIN_ARENA) == 0)
/* Mark a chunk as not being on the main arena.  */
#define set_non_main_arena(p) ((p)->mchunk_size |= NON_MAIN_ARENA)
/*
   Bits to mask off when extracting size
   Note: IS_MMAPPED is intentionally not masked off from size field in
   macros for which mmapped chunks should never be seen. This should
   cause helpful core dumps to occur if it is tried by accident by
   people extending or adapting this malloc.
 */
#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)

```

**获取 chunk size**

```
/* Get size, ignoring use bits */
#define chunksize(p) (chunksize_nomask(p) & ~(SIZE_BITS))
/* Like chunksize, but do not mask SIZE_BITS.  */
#define chunksize_nomask(p) ((p)->mchunk_size)

```

**获取下一个物理相邻的 chunk**

```
/* Ptr to next physical malloc_chunk. */
#define next_chunk(p) ((mchunkptr)(((char *) (p)) + chunksize(p)))

```

**获取前一个 chunk 的信息**

```
/* Size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define prev_size(p) ((p)->mchunk_prev_size)
/* Set the size of the chunk below P.  Only valid if !prev_inuse (P).  */
#define set_prev_size(p, sz) ((p)->mchunk_prev_size = (sz))
/* Ptr to previous physical malloc_chunk.  Only valid if !prev_inuse (P).  */
#define prev_chunk(p) ((mchunkptr)(((char *) (p)) - prev_size(p)))

```

**当前 chunk 使用状态相关操作**

```
/* extract p's inuse bit */
#define inuse(p)                                                               \
    ((((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size) & PREV_INUSE)
/* set/clear chunk as being inuse without otherwise disturbing */
#define set_inuse(p)                                                           \
    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size |= PREV_INUSE
#define clear_inuse(p)                                                         \
    ((mchunkptr)(((char *) (p)) + chunksize(p)))->mchunk_size &= ~(PREV_INUSE)

```

**设置 chunk 的 size 字段**

```
/* Set size at head, without disturbing its use bit */
// SIZE_BITS = 7
#define set_head_size(p, s)                                                    \
    ((p)->mchunk_size = (((p)->mchunk_size & SIZE_BITS) | (s)))
/* Set size/use field */
#define set_head(p, s) ((p)->mchunk_size = (s))
/* Set size at footer (only when chunk is not in use) */
#define set_foot(p, s)                                                         \
    (((mchunkptr)((char *) (p) + (s)))->mchunk_prev_size = (s))

```

**获取指定偏移的 chunk**

```
/* Treat space at ptr + offset as a chunk */
#define chunk_at_offset(p, s) ((mchunkptr)(((char *) (p)) + (s)))

```

**指定偏移处 chunk 使用状态相关操作**

```
/* check/set/clear inuse bits in known places */
#define inuse_bit_at_offset(p, s)                                              \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size & PREV_INUSE)
#define set_inuse_bit_at_offset(p, s)                                          \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size |= PREV_INUSE)
#define clear_inuse_bit_at_offset(p, s)                                        \
    (((mchunkptr)(((char *) (p)) + (s)))->mchunk_size &= ~(PREV_INUSE))

```

### bin

#### 概述

我们曾经说过，用户释放掉的 chunk 不会马上归还给系统，ptmalloc 会统一管理 heap 和 mmap 映射区域中的空闲的 chunk。当用户再一次请求分配内存时，ptmalloc 分配器会试图在空闲的 chunk 中挑选一块合适的给用户。这样可以避免频繁的系统调用，降低内存分配的开销。

在具体的实现中，ptmalloc 采用分箱式方法对空闲的 chunk 进行管理。首先，它会根据空闲的 chunk 的大小以及使用状态将 chunk 初步分为 4 类：fast bins，small bins，large bins，unsorted bin。每类中仍然有更细的划分，相似大小的 chunk 会用双向链表链接起来。也就是说，在每类 bin 的内部仍然会有多个互不相关的链表来保存不同大小的 chunk。

对于 small bins，large bins，unsorted bin 来说，ptmalloc 将它们维护在同一个数组中。这些 bin 对应的数据结构在 malloc_state 中，如下

```
#define NBINS 128
/* Normal bins packed as described above */
mchunkptr bins[ NBINS * 2 - 2 ];

```

`bins` 主要用于索引不同 bin 的 fd 和 bk。以 32 位系统为例，bins 前 4 项的含义如下

<table><thead><tr><th>含义</th><th>bin1 的 fd/bin2 的 prev_size</th><th>bin1 的 bk/bin2 的 size</th><th>bin2 的 fd/bin3 的 prev_size</th><th>bin2 的 bk/bin3 的 size</th></tr></thead><tbody><tr><td>bin 下标</td><td>0</td><td>1</td><td>2</td><td>3</td></tr></tbody></table>

可以看到，bin2 的 prev_size、size 和 bin1 的 fd、bk 是重合的。由于我们只会使用 fd 和 bk 来索引链表，所以该重合部分的数据其实记录的是 bin1 的 fd、bk。 也就是说，虽然后一个 bin 和前一个 bin 共用部分数据，但是其实记录的仍然是前一个 bin 的链表数据。通过这样的复用，可以节省空间。

数组中的 bin 依次如下

1.  第一个为 unsorted bin，字如其面，这里面的 chunk 没有进行排序，存储的 chunk 比较杂。
2.  索引从 2 到 63 的 bin 称为 small bin，同一个 small bin 链表中的 chunk 的大小相同。两个相邻索引的 small bin 链表中的 chunk 大小相差的字节数为 **2 个机器字长**，即 32 位相差 8 字节，64 位相差 16 字节。
3.  small bins 后面的 bin 被称作 large bins。large bins 中的每一个 bin 都包含一定范围内的 chunk，其中的 chunk 按 fd 指针的顺序从大到小排列。相同大小的 chunk 同样按照最近使用顺序排列。

此外，上述这些 bin 的排布都会遵循一个原则：**任意两个物理相邻的空闲 chunk 不能在一起**。

需要注意的是，并不是所有的 chunk 被释放后就立即被放到 bin 中。ptmalloc 为了提高分配的速度，会把一些小的 chunk **先**放到 fast bins 的容器内。**而且，fastbin 容器中的 chunk 的使用标记总是被置位的，所以不满足上面的原则。**

bin 通用的宏如下

```
typedef struct malloc_chunk *mbinptr;
/* addressing -- note that bin_at(0) does not exist */
#define bin_at(m, i)                                                           \
    (mbinptr)(((char *) &((m)->bins[ ((i) -1) * 2 ])) -                        \
              offsetof(struct malloc_chunk, fd))
/* analog of ++bin */
//获取下一个bin的地址
#define next_bin(b) ((mbinptr)((char *) (b) + (sizeof(mchunkptr) << 1)))
/* Reminders about list directionality within bins */
// 这两个宏可以用来遍历bin
// 获取 bin 的位于链表头的 chunk
#define first(b) ((b)->fd)
// 获取 bin 的位于链表尾的 chunk
#define last(b) ((b)->bk)

```

#### Fast Bin

大多数程序经常会申请以及释放一些比较小的内存块。如果将一些较小的 chunk 释放之后发现存在与之相邻的空闲的 chunk 并将它们进行合并，那么当下一次再次申请相应大小的 chunk 时，就需要对 chunk 进行分割，这样就大大降低了堆的利用效率。**因为我们把大部分时间花在了合并、分割以及中间检查的过程中。**因此，ptmalloc 中专门设计了 fast bin，对应的变量就是 malloc state 中的 fastbinsY

```
/*
   Fastbins
    An array of lists holding recently freed small chunks.  Fastbins
    are not doubly linked.  It is faster to single-link them, and
    since chunks are never removed from the middles of these lists,
    double linking is not necessary. Also, unlike regular bins, they
    are not even processed in FIFO order (they use faster LIFO) since
    ordering doesn't much matter in the transient contexts in which
    fastbins are normally used.
    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */
typedef struct malloc_chunk *mfastbinptr;
/*
    This is in malloc_state.
    /* Fastbins */
    mfastbinptr fastbinsY[ NFASTBINS ];
*/

```

为了更加高效地利用 fast bin，glibc 采用单向链表对其中的每个 bin 进行组织，并且**每个 bin 采取 LIFO 策略**，最近释放的 chunk 会更早地被分配，所以会更加适合于局部性。也就是说，当用户需要的 chunk 的大小小于 fastbin 的最大大小时， ptmalloc 会首先判断 fastbin 中相应的 bin 中是否有对应大小的空闲块，如果有的话，就会直接从这个 bin 中获取 chunk。如果没有的话，ptmalloc 才会做接下来的一系列操作。

默认情况下（**32 位系统为例**）， fastbin 中默认支持最大的 chunk 的数据空间大小为 64 字节。但是其可以支持的 chunk 的数据空间最大为 80 字节。除此之外， fastbin 最多可以支持的 bin 的个数为 10 个，从数据空间为 8 字节开始一直到 80 字节（注意这里说的是数据空间大小，也即除去 prev_size 和 size 字段部分的大小）定义如下

```
#define NFASTBINS (fastbin_index(request2size(MAX_FAST_SIZE)) + 1)
#ifndef DEFAULT_MXFAST
#define DEFAULT_MXFAST (64 * SIZE_SZ / 4)
#endif
/* The maximum fastbin request size we support */
#define MAX_FAST_SIZE (80 * SIZE_SZ / 4)
/*
   Since the lowest 2 bits in max_fast don't matter in size comparisons,
   they are used as flags.
 */
/*
   FASTCHUNKS_BIT held in max_fast indicates that there are probably
   some fastbin chunks. It is set true on entering a chunk into any
   fastbin, and cleared only in malloc_consolidate.
   The truth value is inverted so that have_fastchunks will be true
   upon startup (since statics are zero-filled), simplifying
   initialization checks.
 */
//判断分配区是否有 fast bin chunk，1表示没有
#define FASTCHUNKS_BIT (1U)
#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)
/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.
   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */
// MORECORE是否返回连续的内存区域。
// 主分配区中的MORECORE其实为sbr()，默认返回连续虚拟地址空间
// 非主分配区使用mmap()分配大块虚拟内存，然后进行切分来模拟主分配区的行为
// 而默认情况下mmap映射区域是不保证虚拟地址空间连续的，所以非主分配区默认分配非连续虚拟地址空间。
#define NONCONTIGUOUS_BIT (2U)
#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)
/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
   arena.  Such an arena is no longer used to allocate chunks.  Chunks
   allocated in that arena before detecting corruption are not freed.  */
#define ARENA_CORRUPTION_BIT (4U)
#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)
/*
   Set value of max_fast.
   Use impossibly small value if 0.
   Precondition: there are no existing fastbin chunks.
   Setting the value clears fastchunk bit but preserves noncontiguous bit.
 */
#define set_max_fast(s)                                                        \
    global_max_fast =                                                          \
        (((s) == 0) ? SMALLBIN_WIDTH : ((s + SIZE_SZ) & ~MALLOC_ALIGN_MASK))
#define get_max_fast() global_max_fast

```

ptmalloc 默认情况下会调用 set_max_fast(s) 将全局变量 global_max_fast 设置为 DEFAULT_MXFAST，也就是设置 fast bins 中 chunk 的最大值。当 MAX_FAST_SIZE 被设置为 0 时，系统就不会支持 fastbin 。

**fastbin 的索引**

```
#define fastbin(ar_ptr, idx) ((ar_ptr)->fastbinsY[ idx ])
/* offset 2 to use otherwise unindexable first 2 bins */
// chunk size=2*size_sz*(2+idx)
// 这里要减2，否则的话，前两个bin没有办法索引到。
#define fastbin_index(sz)                                                      \
    ((((unsigned int) (sz)) >> (SIZE_SZ == 8 ? 4 : 3)) - 2)

```

**需要特别注意的是，fastbin 范围的 chunk 的 inuse 始终被置为 1。因此它们不会和其它被释放的 chunk 合并。**

但是当释放的 chunk 与该 chunk 相邻的空闲 chunk 合并后的大小大于 FASTBIN_CONSOLIDATION_THRESHOLD 时，内存碎片可能比较多了，我们就需要把 fast bins 中的 chunk 都进行合并，以减少内存碎片对系统的影响。

```
/*
   FASTBIN_CONSOLIDATION_THRESHOLD is the size of a chunk in free()
   that triggers automatic consolidation of possibly-surrounding
   fastbin chunks. This is a heuristic, so the exact value should not
   matter too much. It is defined at half the default trim threshold as a
   compromise heuristic to only attempt consolidation if it is likely
   to lead to trimming. However, it is not dynamically tunable, since
   consolidation reduces fragmentation surrounding large chunks even
   if trimming is not used.
 */
#define FASTBIN_CONSOLIDATION_THRESHOLD (65536UL)

```

**malloc_consolidate 函数可以将 fastbin 中所有能和其它 chunk 合并的 chunk 合并在一起。具体地参见后续的详细函数的分析。**

```
/*
    Chunks in fastbins keep their inuse bit set, so they cannot
    be consolidated with other free chunks. malloc_consolidate
    releases all chunks in fastbins and consolidates them with
    other free chunks.
 */

```

#### Small Bin

small bins 中每个 chunk 的大小与其所在的 bin 的 index 的关系为：chunk_size = 2 * SIZE_SZ *index，具体如下

<table><thead><tr><th>下标</th><th>SIZE_SZ=4（32 位）</th><th>SIZE_SZ=8（64 位）</th></tr></thead><tbody><tr><td>2</td><td>16</td><td>32</td></tr><tr><td>3</td><td>24</td><td>48</td></tr><tr><td>4</td><td>32</td><td>64</td></tr><tr><td>5</td><td>40</td><td>80</td></tr><tr><td>x</td><td>2*4*x</td><td>2*8*x</td></tr><tr><td>63</td><td>504</td><td>1008</td></tr></tbody></table>

small bins 中一共有 62 个循环双向链表，每个链表中存储的 chunk 大小都一致。比如对于 32 位系统来说，下标 2 对应的双向链表中存储的 chunk 大小为均为 16 字节。每个链表都有链表头结点，这样可以方便对于链表内部结点的管理。此外，**small bins 中每个 bin 对应的链表采用 FIFO 的规则**，所以同一个链表中先被释放的 chunk 会先被分配出去。

small bin 相关的宏如下

```
#define NSMALLBINS 64
#define SMALLBIN_WIDTH MALLOC_ALIGNMENT
// 是否需要对small bin的下标进行纠正
#define SMALLBIN_CORRECTION (MALLOC_ALIGNMENT > 2 * SIZE_SZ)
#define MIN_LARGE_SIZE ((NSMALLBINS - SMALLBIN_CORRECTION) * SMALLBIN_WIDTH)
//判断chunk的大小是否在small bin范围内
#define in_smallbin_range(sz)                                                  \
    ((unsigned long) (sz) < (unsigned long) MIN_LARGE_SIZE)
// 根据chunk的大小得到small bin对应的索引。
#define smallbin_index(sz)                                                     \
    ((SMALLBIN_WIDTH == 16 ? (((unsigned) (sz)) >> 4)                          \
                           : (((unsigned) (sz)) >> 3)) +                       \
     SMALLBIN_CORRECTION)

```

**或许，大家会很疑惑，那 fastbin 与 small bin 中 chunk 的大小会有很大一部分重合啊，那 small bin 中对应大小的 bin 是不是就没有什么作用啊？** 其实不然，fast bin 中的 chunk 是有可能被放到 small bin 中去的，我们在后面分析具体的源代码时会有深刻的体会。

#### Large Bin

large bins 中一共包括 63 个 bin，每个 bin 中的 chunk 的大小不一致，而是处于一定区间范围内。此外，这 63 个 bin 被分成了 6 组，每组 bin 中的 chunk 大小之间的公差一致，具体如下：

<table><thead><tr><th>组</th><th>数量</th><th>公差</th></tr></thead><tbody><tr><td>1</td><td>32</td><td>64B</td></tr><tr><td>2</td><td>16</td><td>512B</td></tr><tr><td>3</td><td>8</td><td>4096B</td></tr><tr><td>4</td><td>4</td><td>32768B</td></tr><tr><td>5</td><td>2</td><td>262144B</td></tr><tr><td>6</td><td>1</td><td>不限制</td></tr></tbody></table>

这里我们以 32 位平台的 large bin 为例，第一个 large bin 的起始 chunk 大小为 512 字节，位于第一组，所以该 bin 可以存储的 chunk 的大小范围为 [512,512+64)。

关于 large bin 的宏如下，这里我们以 32 位平台下，第一个 large bin 的起始 chunk 大小为例，为 512 字节，那么 512>>6 = 8，所以其下标为 56+8=64。

```
#define largebin_index_32(sz)                                                  \
    (((((unsigned long) (sz)) >> 6) <= 38)                                     \
         ? 56 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)
#define largebin_index_32_big(sz)                                              \
    (((((unsigned long) (sz)) >> 6) <= 45)                                     \
         ? 49 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)
// XXX It remains to be seen whether it is good to keep the widths of
// XXX the buckets the same or whether it should be scaled by a factor
// XXX of two as well.
#define largebin_index_64(sz)                                                  \
    (((((unsigned long) (sz)) >> 6) <= 48)                                     \
         ? 48 + (((unsigned long) (sz)) >> 6)                                  \
         : ((((unsigned long) (sz)) >> 9) <= 20)                               \
               ? 91 + (((unsigned long) (sz)) >> 9)                            \
               : ((((unsigned long) (sz)) >> 12) <= 10)                        \
                     ? 110 + (((unsigned long) (sz)) >> 12)                    \
                     : ((((unsigned long) (sz)) >> 15) <= 4)                   \
                           ? 119 + (((unsigned long) (sz)) >> 15)              \
                           : ((((unsigned long) (sz)) >> 18) <= 2)             \
                                 ? 124 + (((unsigned long) (sz)) >> 18)        \
                                 : 126)
#define largebin_index(sz)                                                     \
    (SIZE_SZ == 8 ? largebin_index_64(sz) : MALLOC_ALIGNMENT == 16             \
                                                ? largebin_index_32_big(sz)    \
                                                : largebin_index_32(sz))

```

#### Unsorted Bin

unsorted bin 可以视为空闲 chunk 回归其所属 bin 之前的缓冲区。

其在 glibc 中具体的说明如下

```
/*
   Unsorted chunks
    All remainders from chunk splits, as well as all returned chunks,
    are first placed in the "unsorted" bin. They are then placed
    in regular bins after malloc gives them ONE chance to be used before
    binning. So, basically, the unsorted_chunks list acts as a queue,
    with chunks being placed on it in free (and malloc_consolidate),
    and taken off (to be either used or placed in bins) in malloc.
    The NON_MAIN_ARENA flag is never set for unsorted chunks, so it
    does not have to be taken into account in size comparisons.
 */

```

从下面的宏我们可以看出

```
/* The otherwise unindexable 1-bin is used to hold unsorted chunks. */
#define unsorted_chunks(M) (bin_at(M, 1))

```

unsorted bin 处于我们之前所说的 bin 数组下标 1 处。故而 unsorted bin 只有一个链表。unsorted bin 中的空闲 chunk 处于乱序状态，主要有两个来源

*   当一个较大的 chunk 被分割成两半后，如果剩下的部分大于 MINSIZE，就会被放到 unsorted bin 中。
*   释放一个不属于 fast bin 的 chunk，并且该 chunk 不和 top chunk 紧邻时，该 chunk 会被首先放到 unsorted bin 中。关于 top chunk 的解释，请参考下面的介绍。

此外，Unsorted Bin 在使用的过程中，采用的遍历顺序是 FIFO 。

#### common macro

这里介绍一些通用的宏。

**根据 chunk 的大小统一地获得 chunk 所在的索引**

```
#define bin_index(sz)                                                          \
    ((in_smallbin_range(sz)) ? smallbin_index(sz) : largebin_index(sz))

```

### Top Chunk

glibc 中对于 top chunk 的描述如下

```
/*
   Top
    The top-most available chunk (i.e., the one bordering the end of
    available memory) is treated specially. It is never included in
    any bin, is used only if no other chunk is available, and is
    released back to the system if it is very large (see
    M_TRIM_THRESHOLD).  Because top initially
    points to its own bin with initial zero size, thus forcing
    extension on the first malloc request, we avoid having any special
    code in malloc to check whether it even exists yet. But we still
    need to do so when getting memory from system, so we make
    initial_top treat the bin as a legal but unusable chunk during the
    interval between initialization and the first call to
    sysmalloc. (This is somewhat delicate, since it relies on
    the 2 preceding words to be zero during this interval as well.)
 */
/* Conveniently, the unsorted bin can be used as dummy top on first call */
#define initial_top(M) (unsorted_chunks(M))

```

程序第一次进行 malloc 的时候，heap 会被分为两块，一块给用户，剩下的那块就是 top chunk。其实，所谓的 top chunk 就是处于当前堆的物理地址最高的 chunk。这个 chunk 不属于任何一个 bin，它的作用在于当所有的 bin 都无法满足用户请求的大小时，如果其大小不小于指定的大小，就进行分配，并将剩下的部分作为新的 top chunk。否则，就对 heap 进行扩展后再进行分配。在 main arena 中通过 sbrk 扩展 heap，而在 thread arena 中通过 mmap 分配新的 heap。

需要注意的是，top chunk 的 prev_inuse 比特位始终为 1，否则其前面的 chunk 就会被合并到 top chunk 中。

**初始情况下，我们可以将 unsorted chunk 作为 top chunk。**

### last remainder

在用户使用 malloc 请求分配内存时，ptmalloc2 找到的 chunk 可能并不和申请的内存大小一致，这时候就将分割之后的剩余部分称之为 last remainder chunk ，unsort bin 也会存这一块。top chunk 分割剩下的部分不会作为 last remainder.

宏观结构
----

### arena

在我们之前介绍的例子中，无论是主线程还是新创建的线程，在第一次申请内存时，都会有独立的 arena。那么会不会每个线程都有独立的 arena 呢？下面我们就具体介绍。

#### arena 数量

对于不同系统，arena 数量的[约束](https://github.com/sploitfun/lsploits/blob/master/glibc/malloc/arena.c#L847)如下

```
For 32 bit systems:
     Number of arena = 2 * number of cores.
For 64 bit systems:
     Number of arena = 8 * number of cores.

```

显然，不是每一个线程都会有对应的 arena。至于为什么 64 位系统，要那么设置，我也没有想明白。此外，因为每个系统的核数是有限的，当线程数大于核数的二倍（超线程技术）时，就必然有线程处于等待状态，所以没有必要为每个线程分配一个 arena。

#### arena 分配规则

**待补充。**

#### 区别

与 thread 不同的是，main_arena 并不在申请的 heap 中，而是一个全局变量，在 libc.so 的数据段。

### heap_info

程序刚开始执行时，每个线程是没有 heap 区域的。当其申请内存时，就需要一个结构来记录对应的信息，而 heap_info 的作用就是这个。而且当该 heap 的资源被使用完后，就必须得再次申请内存了。此外，一般申请的 heap 是不连续的，因此需要记录不同 heap 之间的链接结构。

**该数据结构是专门为从 Memory Mapping Segment 处申请的内存准备的，即为非主线程准备的。**

主线程可以通过 sbrk() 函数扩展 program break location 获得（直到触及 Memory Mapping Segment），只有一个 heap，没有 heap_info 数据结构。

heap_info 的主要结构如下

```
#define HEAP_MIN_SIZE (32 * 1024)
#ifndef HEAP_MAX_SIZE
# ifdef DEFAULT_MMAP_THRESHOLD_MAX
#  define HEAP_MAX_SIZE (2 * DEFAULT_MMAP_THRESHOLD_MAX)
# else
#  define HEAP_MAX_SIZE (1024 * 1024) /* must be a power of two */
# endif
#endif
/* HEAP_MIN_SIZE and HEAP_MAX_SIZE limit the size of mmap()ed heaps
   that are dynamically created for multi-threaded programs.  The
   maximum size must be a power of two, for fast determination of
   which heap belongs to a chunk.  It should be much larger than the
   mmap threshold, so that requests with a size just below that
   threshold can be fulfilled without creating too many heaps.  */
/***************************************************************************/
/* A heap is a single contiguous memory region holding (coalesceable)
   malloc_chunks.  It is allocated with mmap() and always starts at an
   address aligned to HEAP_MAX_SIZE.  */
typedef struct _heap_info
{
  mstate ar_ptr; /* Arena for this heap. */
  struct _heap_info *prev; /* Previous heap. */
  size_t size;   /* Current size in bytes. */
  size_t mprotect_size; /* Size in bytes that has been mprotected
                           PROT_READ|PROT_WRITE.  */
  /* Make sure the following data is properly aligned, particularly
     that sizeof (heap_info) + 2 * SIZE_SZ is a multiple of
     MALLOC_ALIGNMENT. */
  char pad[-6 * SIZE_SZ & MALLOC_ALIGN_MASK];
} heap_info;

```

该结构主要是描述堆的基本信息，包括

*   堆对应的 arena 的地址
*   由于一个线程申请一个堆之后，可能会使用完，之后就必须得再次申请。因此，一个线程可能会有多个堆。prev 即记录了上一个 heap_info 的地址。这里可以看到每个堆的 heap_info 是通过单向链表进行链接的。
*   size 表示当前堆的大小
*   最后一部分确保对齐

!!! note “pad 里负数的缘由是什么呢？”  
`pad` 是为了确保分配的空间是按照 `MALLOC_ALIGN_MASK+1` (记为 `MALLOC_ALIGN_MASK_1`) 对齐的。在 `pad` 之前该结构体一共有 6 个 `SIZE_SZ` 大小的成员, 为了确保 `MALLOC_ALIGN_MASK_1` 字节对齐, 可能需要进行 `pad`，不妨假设该结构体的最终大小为 `MALLOC_ALIGN_MASK_1*x`，其中 `x` 为自然数，那么需要 `pad` 的空间为 `MALLOC_ALIGN_MASK_1 * x - 6 * SIZE_SZ = (MALLOC_ALIGN_MASK_1 * x - 6 * SIZE_SZ) % MALLOC_ALIGN_MASK_1 = 0 - 6 * SIZE_SZ % MALLOC_ALIGN_MASK_1=-6 * SIZE_SZ % MALLOC_ALIGN_MASK_1 = -6 * SIZE_SZ & MALLOC_ALIGN_MASK`。

看起来该结构应该是相当重要的，但是如果如果我们仔细看完整个 malloc 的实现的话，就会发现它出现的频率并不高。

### malloc_state

该结构用于管理堆，记录每个 arena 当前申请的内存的具体状态，比如说是否有空闲 chunk，有什么大小的空闲 chunk 等等。无论是 thread arena 还是 main arena，它们都只有一个 malloc state 结构。由于 thread 的 arena 可能有多个，malloc state 结构会在最新申请的 arena 中。

**注意，main arena 的 malloc_state 并不是 heap segment 的一部分，而是一个全局变量，存储在 libc.so 的数据段。**

其结构如下

```
struct malloc_state {
    /* Serialize access.  */
    __libc_lock_define(, mutex);
    /* Flags (formerly in max_fast).  */
    int flags;
    /* Fastbins */
    mfastbinptr fastbinsY[ NFASTBINS ];
    /* Base of the topmost chunk -- not otherwise kept in a bin */
    mchunkptr top;
    /* The remainder from the most recent split of a small request */
    mchunkptr last_remainder;
    /* Normal bins packed as described above */
    mchunkptr bins[ NBINS * 2 - 2 ];
    /* Bitmap of bins, help to speed up the process of determinating if a given bin is definitely empty.*/
    unsigned int binmap[ BINMAPSIZE ];
    /* Linked list, points to the next arena */
    struct malloc_state *next;
    /* Linked list for free arenas.  Access to this field is serialized
       by free_list_lock in arena.c.  */
    struct malloc_state *next_free;
    /* Number of threads attached to this arena.  0 if the arena is on
       the free list.  Access to this field is serialized by
       free_list_lock in arena.c.  */
    INTERNAL_SIZE_T attached_threads;
    /* Memory allocated from the system in this arena.  */
    INTERNAL_SIZE_T system_mem;
    INTERNAL_SIZE_T max_system_mem;
};

```

*   __libc_lock_define(, mutex);
    
    *   该变量用于控制程序串行访问同一个分配区，当一个线程获取了分配区之后，其它线程要想访问该分配区，就必须等待该线程分配完成后才能够使用。
*   flags
    
    *   flags 记录了分配区的一些标志，比如 bit0 记录了分配区是否有 fast bin chunk ，bit1 标识分配区是否能返回连续的虚拟地址空间。具体如下

```
/*
   FASTCHUNKS_BIT held in max_fast indicates that there are probably
   some fastbin chunks. It is set true on entering a chunk into any
   fastbin, and cleared only in malloc_consolidate.
   The truth value is inverted so that have_fastchunks will be true
   upon startup (since statics are zero-filled), simplifying
   initialization checks.
 */
#define FASTCHUNKS_BIT (1U)
#define have_fastchunks(M) (((M)->flags & FASTCHUNKS_BIT) == 0)
#define clear_fastchunks(M) catomic_or(&(M)->flags, FASTCHUNKS_BIT)
#define set_fastchunks(M) catomic_and(&(M)->flags, ~FASTCHUNKS_BIT)
/*
   NONCONTIGUOUS_BIT indicates that MORECORE does not return contiguous
   regions.  Otherwise, contiguity is exploited in merging together,
   when possible, results from consecutive MORECORE calls.
   The initial value comes from MORECORE_CONTIGUOUS, but is
   changed dynamically if mmap is ever used as an sbrk substitute.
 */
#define NONCONTIGUOUS_BIT (2U)
#define contiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) == 0)
#define noncontiguous(M) (((M)->flags & NONCONTIGUOUS_BIT) != 0)
#define set_noncontiguous(M) ((M)->flags |= NONCONTIGUOUS_BIT)
#define set_contiguous(M) ((M)->flags &= ~NONCONTIGUOUS_BIT)
/* ARENA_CORRUPTION_BIT is set if a memory corruption was detected on the
   arena.  Such an arena is no longer used to allocate chunks.  Chunks
   allocated in that arena before detecting corruption are not freed.  */
#define ARENA_CORRUPTION_BIT (4U)
#define arena_is_corrupt(A) (((A)->flags & ARENA_CORRUPTION_BIT))
#define set_arena_corrupt(A) ((A)->flags |= ARENA_CORRUPTION_BIT)

```

*   fastbinsY[NFASTBINS]
    *   存放每个 fast chunk 链表头部的指针
*   top
    *   指向分配区的 top chunk
*   last_reminder
    *   最新的 chunk 分割之后剩下的那部分
*   bins
    *   用于存储 unstored bin，small bins 和 large bins 的 chunk 链表。
*   binmap
    *   ptmalloc 用一个 bit 来标识某一个 bin 中是否包含空闲 chunk 。

### malloc_par

**！！待补充！！**

[img-0]:data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAzMAAAMYCAYAAAD/wLlDAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAEXRFWHRTb2Z0d2FyZQBTbmlwYXN0ZV0Xzt0AACAASURBVHic7N1rcBznfef7X89gLhjO4DIASIgUAOrCi24WCVlaykcC41oqlisp+Ug8x4nLdipVduTaWlmXk61yXCeVxC82WaeyR5Ll7JZl5byI5ePEtZSOXM4RvWTKAuRYsGWBskXJBClRBECCEAeD2wwGMxjM9HnR6MYMMLgSwEyD308VJc6lu/89AMn+4fk/TxuvnRk1tRbGmrbaNKsvr4JOaJlSKqjSTbHh51thH2iFlbOpDOPaOvuKO9tNLqjizn8TrfrcXfdhra5g153efFd5Aq4//w10rV0DrJb7yl/nig3Js757BAAAAIDNQZgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EpV5S5gK/PMpOTJTsqYmZInl5bM/KLvzdTvlySZkr7x3//HJlUIAADK6W+++r9LkgzDKHMlgDsRZjaCmZdv6oqMmZRyvhrlqxuV9QYlY+mBMNOUzNm/y/7y6S9vQqEAAKBcvvHUC8rlTVV5DJmmSaAB1oAws848+WlVJS8qX7VN2cjuZQPMfLmcuTGFAQCAipPNWyHG6yHIAGtBmFlPZl5VyYuaCTYo769dw/YEGQAAriW5nCl5ZV0DMDIDrBoLAKwj39QV5au2rS3ISJJBngEA4JrCv/3AVSHMrBPPTErGTEoz1U3lLgUAAAC4JhBm1oknO6mcr2bVc2QAAAAArA1X3uvEmJmS6QuVuwwAAADgmkGYWSeeXFp5b7DcZQAAAADXDMLMejHztJgBAAAAm4irbwAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGQAAAACuRJgBgDK5++xZHXjjjXKXAQCAaxFmAGxpB954Q3efPVv03L3Dw64IEbe98oo6TNP5tevxx8tdEgAAFYUwA+CaYgebt++9t8yVLO2m555Tw0MP6dcdHeoyDP26o0Otf/EX5S4LAICKUlXuAgBgs9z2yiuq3rNHXYZR7lKWFWxtVTYe1/jrr0uSxl9/XW80Npa5KgAAKgsjMwCuCYUjHfPtevzxonau2155xXmt9v771WGauum555zXJSsY3X32bFEr2Px2NskaCSrc90ql+/vla2jQTc89V/J1+9iF+5/fOmfXXuq8Sp13YRvbUp8JAACVgjADYMur3rNHux57TB888YQz0mHb9fjjuunZZ/XBE0+oyzDUZRhqeOihBSFi12OPOa8X7te3fbvzfPWePUUX/Xa4sV+P/+hHund4eEU1f/DVr2qiu1u7Hnts0fkyDQ89pJGf/MRpQ6s5dMg5fu399+vWl192jv3BE0+o4aGHnP3MP+/CNraVfiYAAJQbYWZdmJIqv20FuFZNnTunqXPnSs45afrc5zTR3a1L3/qW89xEd7ein/pU0fs+eOKJBdtm4/GiuTdT587Jt327JCtMVO/Zo7Nf+pLz+sW/+zv5GhpWPJH/7XvvVZdhaOrcOd307LMLgtBEd7c++OpXJVltaBPd3QrdcovzuLAtzT6/4J49znlPnTvnPF/4/pV+JgAAlBtzZtaBJ59V3usvdxkAlvDm3r1OK1ZhAPE1NKh6z54FLWBT586t+hjZeNz5ffjgQUnSnV1da6x4zpt796r2/vt1Z1eXbnruOSfALDj+lSvyNTQ4j2975RU1PPTQiuottJ6fCQAAG2nDwsz41Ixe6x3VlYmsotuqdPSu7Qve09Of0IexKY1MzljFeAxFw1W6dWdYe7ZXS5L++ZdXNJGemSvYY2h7jV/37alVbXWFZLFcRqoKlrsKAMv44IkndNOzzxYFgmw8vmCEZT0kT52SJP26o2NBa9tarGQf9qiQNDdHqLAtbn44KQw+hTbqMwEAYL1tSJvZ6UuTeumtmK5MZBd9z7/8Jq63LiScICNJM3lTVyay+s1AwnmuMMjY7xkcy+hn58bXv/A18mbGlfNWl7sMAMu49K1vKf6jH2nXY4+p9v77JUmJX/1KNYcOOY/Xy/jrrysbj+uGv/3bNW1/99mzRe1o9nyV4R/+0Hmu5tAh5/na++9XzaFDGvnJTyRZq6EVmj/fJfaDH1hziQqOYbexbdRnAgDAetuQoY1YYlrRcJWqPB4NjmUWvN7Tn3Cev3l7tdrbIqqtrtKl0YzOfpRaEGAk6d6banX7rm366ZlRvX9lSulsbiNKXzVPZlwyc8oHastdCoAVePczn9HdZ8/q1pdf1huNjc4Izfx2sEvf/vai7Vwr9UZjo+4dHi4aEcnG4ytaYvnsl75ktZU9+6zz3PxRHnsey67Z/cd/9COnZvs87WNPdHcXtZVd+ta3FNyzxxqpmj2GPS9oIz8TAADWk/HamdGVrxVatOXyb7GDx/w2s1fetkZtbt5erU/ur19yH9/tGpS0MMzsrAvo9z5WukViheVd9RaezLiqpmLKRlpkegOr3n4+0zSVzUl//cIx/eXTX77q/QHYuu4+e5ZWMMDlvvHUC/rzrzyiYJVXVR7JcME9sDbbhn8iLv/I3Vf+OldslGkBgJGkNfLSFLEmzdsBxba9xqfPHGgq2uaND8b1xgdWa1m136sDLeFNqraQKU8+K+Uy8s6OyKxXkAEAAACwOmVZmnkmv/Rg0Exu6denpnNlmTMTGO2Vb/y8fMlLkqRspJUgAwAAAJRJWUZmotuqNDI5o1hiWtI2fXJ/vT65v37BCE0hu83s0mhGP+0d00R6RqcvTer2Xds2re5M/T55ctPSzJS80xPyJS9pJtQs01Mhq6oBuGa8uXdvuUsAAKDsyjIys73GGs14/8qUXj83rvEpq+0su8yITPkZynsDygfqlI20Ku/bJl/igoz84qu2AQAAANgYGzKkMH+EZWRyRt/tGnTmwty/p1aDoxlNpGd05vKkzlyeXHafhXNmJOt+My3R8rZ45QLW4gVVk5eVjbQu824AAAAA66ksIzOS9Af3bNcd14dVE5zLU9YNMX3a1zzXOlb4uv2enXUB/e5t0Yq4aaYdaDzTlXPfGwAAAOBasCFpwJ4Ds5xDN9bo0I01S77nD+7ZvuTrlSAXrJc3O6m8n3vNAAAAAJulbCMzW4o3IM2UXrgAAAAAwMYgzKyDvMdnrXIGAAAAYNMQZtaFIanSV2IDAAAAthbCDAAAAABXIswAAAAAcCXCDAAAAABXIswAAAAAcCXCDAAAAABXIswAAAAAcCXCDAAAAABXqip3AQAAAFi9Z08OOL8P+b36k46d67Lfl3piGhhJO48P76vXgZaw87jr3JhO9SWcx/uaQ3rw9oZV1fb97iENJ7PO44fbm9QaDTqPj5+Oq3co5Txub4uoY0+d87h/JK2XemLO48awT1841Fx0jOe7BpWazjmPnzzSssRZr59nTgws+lpLNKijdzU5j4+/E9eZoZT2N4f04B0NC97/YveQhhNzn9OTD7QUvRbyeYv29/SJAe1vDunTJfZVyrG3Yuov+FofbW9Sa0PQeS2VzemLh5p1qj+p13pHS+7D3uZ782qVpMaIT1+c93VZb4QZAAAAl3n25EBRiPhu16C+3z2kz1/lheNLPTHFk1k9MXvhf/x0XJ29o4puq1JrNOgEGTt8vD2QVGfvqEIBrxM2lqvt+91DkuQc46WemF7uiRUds3copSeOtMiQFZ56+hKKBKt0sCXsBJnCgPPMyQEd64npaLt1Yf9816Aawj492m6FqBe7h/R816AeXafAt5TCwPF856Bao4GSQUWS+kcyaokG1T+SWfDasbdiSmXyzv66zo7p2FuxovBS6Dudg2qM+FYcZF59J67+kbSemt3/qf6kOs+N6YsNC7+HDraGdbA1XPTc92a/jnb4kaTWeWFtM9BmBgAA4CJd58YkqWg0ZN91IQ0ns0U/ZV+LgZG09l0Xch7bx3hvcNJ6PZ5WSzTojKIcaAmrMezTQDy9otr6R9IaTmZ12665C+OP744UbTswktG+5rkaOvbUKeT36nxsyqkl5PcWjdTsbw45o0mnBpJKTed09+x+Jem2XWGlpnM6NZC8qs9nPZ3qt2o5eleTVVt/cW1T2Zwawj7nccfeukWDwrG3rFGq1YyCpKbzaozM7f9ga3jF23eeHdNwIqvDBV+DcmFkBgAAwEWGE1k1FlzkStLuhqBO9SU0MjmjkUlrtKSwPey7XYNqiQackFHYSma3gb09e6G/u+An7ZLVwpWazlvHTmZ1sK349YawTwOzIwvL1TaRnpGkora11mhQIb9XqUxO/SNppaZzaq4NLDjG1GzL2HAyW3SRL0k7agM6M5RS/0haH41nFPJ7i9rWDraE1dk7qsTs8Qt1nbVGfkp5pL1J8ckZdS7SYnV4X/2CEYuVOh+bcs6jJRrU+dhU0b6qfV4NjKTVH08XjX7MN3+EZaVCfo/6R9I61Z9c9Tn09CW0vzm0ZF2bhTADAACwhRxoCet8bEpvfjihAy1hvdQTU8jvKQoy81vJjp+OLwgQ14qOvXXq2Lv4CENrg9YcWJYyMJLW4X31kqSmiG9BoDp6V5Oe7xx05gY9WSKs2CNxdnvdanz6jgYNT2b1Wu+oXusdLZovs5Rjb8UU8ntLtrP1j6T1dMGcod+5irC3UrSZAQAAbDGPzF7cfrdrUAMjad1fcLFeqpVs/gR+bKyus2MK+b3Ohb4dprrOjhW979HDO50Q88yJAaedzGaPanWeK95upb54qFlPPdCikN+rYz0xZx7MYk71J9U/ktY9N9SUfL01GtRTD7Q4vzY6yEiMzKwfwyOZeev/AAAAZXb3DTXq7B0tmuNiqwlyCWgrR5uZ3U43f+WzxeY8PflAi1Pn/LazT98e1bGemF59J77iyf/zfeXwTmfFsqXazn754YRao8FNCSkrxXfyOsl7g/LMTCnv21buUgAAwBYW8nuKlk6WpAuzE/AL56LYQWZgJK23B5JFr02UmDsS3Vbl7Ksw/BTOkwn5vQuW340XzGFZrjZ7Xk5hPYXzZOzjDo1npIJ648msWqNWG1y136t4sriGwnkyF+LW/vpH5s7j1CLzgaTNbzPrj6etyfPzgtCpfmuu02JzZCKLBNDWhqDa2yLq6UuouTaw5lobti0dC159J67UdE5H79r4FeFWg2GEdZKvCskzk1r+jQAAAFfh1p3WD06Pn447z/VeTqmlIIC81BNTY9inR9qb1BIN6s0PJ5zXWqJB9V6eu2bpOjem46fjao0G1Rj2Fb1mH8NeOawlGrAmpc8GlrcHkhpOZnVjU/WKajvQElbI79W7l+ZW7vrVhYRCfq8TblqiwaJ7zHSdG1NqOufs+8amaqWmc87qZ5J0ZijlhB271jcvzI22vHspqcawb8EIVTnYq7HNDx32Y3vluPmjNudjU1ZgKxF0Du+tU2s0uOi9YEr5Tueg+uNzwfPd2eOWCkP98bTODKXU3hZZ8Fq5MTKzTkx/WN7ERRmBOpke3/IbAAAArEFrNKjD++rV2TvqXPS3RIPOPJmuc2MaGEnr4dnHj7Q36dmTA3qpJ6ZH2pv0SHuTvt895NzYsvCmlp8/1Kzvdg0W3fTyiYKbTT54e4NS03m9XHDDysJV05arTZL+pGOnnj05UPL4dr2F9dnP2UHkYEtYifSMevoSTnvY/nk37nykvUkv9cT0zOw+St1Us1yGJxeuxmYrvOdMe1ukKNCE/F49enjxUZGjdzXpO52D+l730IqWWL7nhhod6ymeg7PYimgfzoaews/cVjjJf/4CACG/V19Zoub1YLx2ZtRc25brXMk6W315V39C3qlhebIJZSNta5o7Y5qmsjnpr184pr98+stXXQ8AAKhc33jqBf35Vx5RsMqrKo9kGBV+cVUGG/6JuPwjd1/561yxQZvZuspVN0oev3yJPnlmpspdDgAAALCl0Wa2zrLhnfJkxlWVvCTTF1LOt03yBpX3+uXG/AwAAAB3OfZWbNGV0SSrhe3wEoseuAlhZt0ZygfqlPXXyJMZk3c6KeXi8uWzkhbv6MvU7y96/I2nXtjgOgEAALAVHb1r9TfRdCvmzFzFFuvBMGdkTE/Km01K+ayM/IwMc0Zdbw8svzEAAHCtjgPzJ1sbktcvwxeUqgLW/33bpGt4Lg1zZpbmvvLXf84MIzNl4sml5Z2KWfemqdqmnG+bTE9AWXn11s86dX3bjeUuEQAAbKCut8/r7k8eUcDrkcczO5E5Py0zm5ZmMjKTwzLNK/LUXCf5qstdLlCRCDObzczLN3lZxsyUctUNyoavl51S8yYrMgAAcC3xeySPx5QhwxqB8QZkeANzb0iPKz9+UYY/LEV2yFjDaqnAVsafiE1k5KblT/TJ9Po0XXujcoF6FQ63eWReyyPJAABcczyGfSVQ+gLACNbKaLhJkiklPtrEygB3IMxsEiM3LV+iXzOBqGaqty9yHxrDhb2PAABgrQyPoeUuxwzDIyPSLDM7JWUSS74XuNYQZjaDmZdv8pJmqpuUD9SWuxoAAOA2hkdG7S7lE0NSfqbc1QAVgzCzCXyTl5X3bSPIAACANTOqAjL8YZmMzgAOwswG8+TSMmamNBNsLHcpAADA7XzVUnbxmyEC1xrCzAbzTsWUq25YZI4MAADAyhm+oDV3BoAkwsyGMswZeWamlAvUlbsUAACwFXgDMnLTkrm2e54DWw1hZgMZ05PKV22TG+/PCgAAKpBhyPT6pfx0uSsBKgJhZgN5s0nlfNvKXQYAANhCrFYz5s0AEmFmY5kzUuFdfAEAAK5WVVCayZS7CqAiVJW7gK3MyGdleviIAQDAOqoKSJNbb3nmrnNj6r2c0p907Cx3KRvm+Dtx9Y9k9Ojh9TvHV9+J68xQSpL0O/vqdbA1XPK5rYor7Q1k5GdkenzlLgMAAGwhhn+bzMlhmVNjMqrXf5GhrnNjOtVXHJb2NYf04O0N636sSnC84MJfkg676OK/P57WmaFUUWAp9dxWRpgBAABwm5rrZI5ckBGMSIZ3Qw7xxJEWSVL/SFov98QkacsFmq6zYzozlNIj7U1qbQiqP57W8dMjTgjoOjumM5dT6zqSsp7ikzOSVBRaSj13Nb7XPaTGbT59+o7K/NozZwYAAMBlDK9fxrYGmWOXJDO3ocdqjQbVEg0qnsxu6HHKIZXJKeT3qrUhKElqbQhWbHApZSI9s6LntjJGZgAAAFzIqI7KNPPKD5+XEdkuI1i7qcf/fveQhmcDTsjvLZrr8t2uQe27LqTeyymlpq2wdbAtoo49c21x89vZDrZFFhzj+OniFrCWaFBH25ucx8+cHNDhffXq7B11nnukvUnvDU46283fplAo4FVqOqeus2Pq2FvcsnfsrZgGRqxV4545MSBJevIBa7TqVH+y6JjtbZGi7bvOjqmn4NzskZ/57GPY+51v/nFCfq8Ttgrre/rEgBojPoV8XvXPe+6Lh5rVOa+e9raIDs/We6o/qdcKjrG/OeSMwjw9e97DiazODKXUGg3q6F2lP8tyIcwAAAC4kWHI2NYkBWqkicsyp8Yk/zYZVQGpyi95/JJx9fe6e3sgqYGRdFHY+H73kG7bFdaBFquV6btdg3qpJ6ZHCkLDqb6EDu+r14GWsBNcdjcE1RoN6u2BpE71JZyAY7eyhfxzLXPHT8fVO5TSk0fmLvSfOTmgYz2xonDS2TtqhYVoUC92D+mlnphaokE9eaRF/SNpvdQTU9e5saIgZevYW6dYIquevoR6Zuu127OO3tVUss3sVH9S7w4mnQBiB5fdDUG1NgSdx3aAOdWfVNe5MX2hobno2MfeiimezC4bZAprerF7SM93DurRwzud+nr6EnqqYB+dJZ7r6UuUnENjB5nC154+MaBQwKvDe+v01AMtFd9mRpgBAABwMaMqIEV3y5walZm4IrOg7cyz49Y17/fZkwPO7x+eDQu2zx8qvjBvCPs0NV3c7ravOeSEnd0NQZ3qS2hkckatUWloPKOQ3+sEjNZoUAfbIuq9PDcK0zuUUvu80Zr9zSH1jxQvS93eFnFqa20IKjWdd8JOazSoxrBPqczirXj2SMOL3UPq7B3Vmx9OLNlqdrA1XBQKdjcE1dOXUHxyRq0N1hyjlmjQGYmZ/37JCjJT2dySx3l3MKmWaLBo29t2htXZO6r+eLrkSM9ShsYzkorrOB+bsj77gmO0RoPO6I4bEGYAAADczDRlTsZkTo3LqK6V/GEr4HivbkVVewGA73cP6SenR4rayAoXBbA1hhc/XmEQkqTUdF4h//JTtyPB4ktVuy1sI3zhULP647MjOSXazgoVtniVsm2Jc0tN55QayakxsvzXZ/5+GrZZn4cdnFbqqQda9PSJAZ0ZSink9+orsyEqlc1pOJF12slsK6mtUhBmAAAAXMrMTcscuyjD65en8SbJWP+1ne7fW6eX57VqvdwTK5oD81JPbMHIzFJCfs+K3p+YN5ndnrC/UVYy2nH8nXhRe5gdgApNTucX3d6e9/LMiQEdfyeuB5do35q/H3ulMjvUrIbddva97iF9r3tIXzzUrJDPq9aot+LmwawGq5kBAAC40UzaWp45VC+j7voNCTLS3GpmdgtYqRakpUYpSmmuDWg4mdXbA0lJcubQFGqJBosmrUuanYQeWNWxlvJi95BO9Sedx11nxyRZrWO2+SNB8wPGe4OTRY9bo0ENjKTVH7c+k/54Wi92Dy049uF99TozlHKOOZ+9n8L63h1MqjHiW3WLWaGQz6uQzwqEjRGf+gtqXUxqiXBWbozMAAAAuI1pKj8+KE/NdVJg4Spg6+3GpmoNjKT19kBSB1rCOtgW0am+hBNA9jWHVrV084GWsIbGM+rsHVVn76hCfq8O76vXmx9OOO95pL1J3+8e0jMFc3f2r/PNOzv21OmlntiC1dDssNCxt05nLqeKVjM7eleTnu8cdJ7b3xwq3ufeOqUyuaLRmkdKrKZ2sDWsRHpGPX0JRYJVC+bV2PuxPyPJCh9fmDdfaTnzVysrbDOzVzQ7Nm9kqXC1s9t3hvVa76iePjFQkauZGa+dGTXXtuU6V7LOVl/e+p9QYPSMMvX7V76BaZXxi5+e0PVtN657PQAAoHJc7Duvjt99QMZso8xqFh4zUyPSdMoakdnCNvxys8KvZ5fjvvLXuWKDNjMAAAB3yWdlTsZl1OwodyVA2RFmAAAAXMScTskIhCWPe1acAjYKYQYAAMBNslOSb+0TwIGthDADAADgIuZ0SoavutxlABWBMAMAAOAWpikjNy151295YsDNCDMAAABukcvI9PpXt/QZsIURZgAAAFzCnMnQYgYUIMwAAAC4RTbN5H+gAGEGAADABUwzLzMzIfm3lbsUoGIQZgAAANwg8ZGMQI0Mr7/clQAVgzADAABQ6bJT0vSkjHBTuSsBKkpVuQsAAADA4sxMUubEZRm110kGP4cGChFmAAAAKpGZl5m8IjOTkKfueolVzIAFCDMVxpT0au+41Huq3KUAAIAN9Dd/cLsU/0CmxydVBWQEwlJVwAox6YTM9JgMX0hGw02MyACLIMxUENOUzNl7YNXsaCtvMQAAYOPlstavbEr5qVHrOY9XRrBGnlpGY4DlEPMriqlczix3EQAAYBN8/Z9Pa6puj/JN+6Xtt8qz41Z5tu+TEay1RmZm0uUuEah4hJkKYsoanQEAANeGXN7699/Q7AWA4ZURaZYn2iYzNSozMVTW+oBKR5ipIIZR7goAAMCmMgwpb8ic/9NMb0BGdLc0My1z7CI/7QQWQZgBAAAoI1OmjBI/0TQMj4y6Fkl5mZPDm18Y4AKEGQAAgDIxDJUMMoVvMGp3yUyPyZxObl5hgEsQZgAAACqZ4ZVRc500MUS7GTAPYQYAAKDCGf6w5PXJTI+XuxSgohBmAAAA3GBbo8TcGaAIYQYAAMAFDP826ze5THkLASoIYQYAAMAlTP82melEucsAKgZhBgAAwCU8gbCUTZW7DKBiEGYAAADcosov5bLlrgKoGIQZAAAAtzC8MvO5clcBVAzCDAAAgFt4qqT8TLmrACoGYQYAAACAKxFmAAAAALgSYQYAAACAKxFmAAAAALgSYQYAAACAKxFmAAAAALgSYQYAAACAKxFmAAAAALgSYQYAAACAKxFmAAAAALgSYQYAAACAKxFmAAAAALgSYQYAXOYfHz+srx+9s9xlAABQdlXlLgAAtoJ/fPywItU+SVJiKqs/+lZnmSsCAGDrY2QGAK7S3z/6CSXSWT38zZN6+Jsn9dtLY0UjJ3//6CcYSQEAYAMwMgMAVykS9Om3l8acx39z7NdlrAYAgGsHYQYArlIindU9NzeVfO3lrx2RJO2sD+nlrx1R7+C4/ux7b0qS/ssX79a+nbXOex/+5smibf/+0U9oZ31IkjQ4mtJ/fP7nix6jcL8AAFwraDMDgKtkh4yXv3ZE//j44aLXHv7mSQ2OpvTL92N6+Jsni4LM+0MTTmva4GhKf//oJ5zt7N/bryemsvryA/sWHPvlrx3RL9+PEWQAANckRmYAYB08/M2TuvX6Ov3nz3/cCRhLtZvNDx8X45O6ZVedJOnW6+u0sz6kfzjZu+j7JSvI/EvPgF440bvgNQAArgWEGQBYJ+9dHNPD3zyprx+9c9G2s0J2C5otMZUtenz+o8Si265k/wAAbHW0mQHAOotNpJd9zz8+fthpPXv4myf1y/djC95z447Iotv/8v2Y/qVnQL/X3qJbr6+7qnoBAHArwgwAXIVbr69bME/m4A0NGhxNFT1XG/IXPbbvSWOzW8wka4RncDSlT9/V4jz39aN3Lpgz88KJXvUOjus/f/7jV3UOAAC4FWEGAK7CexfH9NtLY3r5a0ecxwdHGwAAIABJREFUX5KKVh579a0B7dtZq5e/dkT/5Yt3S5L+4WSv7rm5ydmmcGlne/tI0Oe8fn3DtpJzY/7se29qcDS1IFABAHAtMF47M2qubct1rmSdrb689T+hwOgZZer3r/j9pmkqm5P++oVjqtnRtu71AACAyjHxUZ/+/CuPKFjlVZVHMoyVXYvkP3pPnh23bnB1lWHDLzcr/Hp2Oe4rf50rNhiZAQAAAOBShBkAAAAArkSYAQAAAOBKhBkAAAAArkSYAQAAAOBKhBkAAAA38fqkfLbcVQAVgTADAADgIobXL+Vmyl0GUBEIMwAAAC5iev0yc9PlLgOoCIQZAAAAF/EEwjLTE+UuA6gIVeUuAAA2UlNNUH/6mTu0sz6kSLVPkhRPZPTBRxP6m2O/LnN1i/vc/Tfps5+4oei5xFRWH15J6Nv/33uKTaTLVBmAsvNvk8YHZZp5GQY/l8a1jT8BALas+27Zoee+fK/27ax1gowkNUQCuufmJv3+XS1lrG5pu7eHFzwXqfbpY21R/dc//ndqqgmWoSoAFcHwyAhGpPR4uSsByo6RGQBb1h9/cq8CPq/iiYz+319c0I/fGpBkjXrcd8uOMle3MoOjKf3H538uyar7M3e3KlLt059+5g792ffeLHN1AMpmW6PMkQsygrUSozO4hhFmAGxJ992yQw2RgDLZnL7+4ptFbVk/eP0D/eD1D5zHXz96p+65uUmd715W+42N8ld59If/10+d127ZVeeM7FyIJfXd/3lG710c098/+gntrA/phz//UD94/QM11QT1/H+4T5lsztnebhf7Td+I/vKfevS5+2/Spw9er0i1T5lsTr/uG1lxu5td82c/cYN2N82N3Nx3yw4dvXfuucRUVj3nh/XMj9+VJL38tSOSpEf/+88Um0g7NV2IJfXU/90tSfrGH7brY21R/fDnHyqRmtaXjuzTb/pGFPB5tW9nrTLZnHoHx/WX/9Sz+i8GgHVneP1SsEZm4iMZNdeVuxygbIjyALakj9/UKEmKJzNOkHn5a0eKfs0fnTl823WKVPsU8HklWRf499zcVNSitrsprD975E5J0rlBq8Vj/65aSdJn/l2bJCng8+pz998kSbpzd1SSdOaS9d7PfuIG+as8+uX7MV2IJbW9tnpV52UHGrvGW6+v02OfvrUo3ESqfTp823X68gP7JFkBTJKO3LmrqKbdTWGnXe2G7RFJ0slfX3L287G2qPbtrHWO97G2qGtGtIBrQni7zOmUzKnRclcClA0jMwC2pOrA8n+91YX8RY8HR1P6q9mRh6aaoD7WZl30/8PJXv34rQHden2d/uKzBxWp9un372rR/3z7kg7fdp0TBG5urlEmm1PA53UCzu6msDLZXNFIkCTFJtJ64UTvVU/k/4P7blTA59WFWFJ//T/eVmwi7YyyHLyhQZL07sCodjeFdefuqH7w+gfaWR9y6jxy5y4NDCcVqfbpQixZVE8mm9OLne/rF+di+qs/bNfO+pDuv7VZP/vtR1dVM4D1YRgeGfWtyo9ckLx+Gf5ta95X/0haL/fEip5rDPv0+UPNzuO3B5Lq7B3Vw+1Nao0Wz9ub/1rh/g7vq9eBloXzALvOjelUX0Ihv1d/0rFzwX4uxNM61ZdYtObD++p1sMR+5zt+Oq4zQ6kF2x3riWlgZPG/g598YG5e5al+q67GiE9fKPhMCtnvsYX8Xj16eGfRa4+0N6m1wfrsjr9j1VV4nErSeXZMPQWff2s0qKN3NTmPv9M5qNR0TvubQ/r0HQ0Ltu+Pp3Vs9nvgaMF5f6fzklLTuaL3/s6+eh1sjaypTsIMgC3pnQsjuufmJjWEA2qqCSo2kdbD3zwpaa7tar6L8UnnYt5eHGBwNOXMtXnv4pjiyYx21ofmHicyaogEdN8tO7SzPqTLY1NqCAd0w/aI7rtlhwI+r3oH5ybp/kvPgDpuadbvtbfoyB071X32itMOthL2iE9iyrr7d+PsyMq//vqSU/ub52JOEJOkV37Rp99rb9HuprBuvd5qmftN34g+1hbVnbuj2lFr7ePdgeKf7saTGefcL8YnnfMGUEG8Phl1u2SOXZTC22VU113V7gqDx3e7BvX97qGiQLNaIb9X715KlgwzvZdTCvm9i27bsadOh/dY53NqoCAMRFe+AErXuTGdGUo52/WPpHX89IgOtoR1tL1JMqz3HX8nrv6RjBM+5jsfm1JLNKiBkbT642nnwtxmB5PCsNJ1dkwvdg+VDD9dZ626Du+rX/G5bCY7yBSGkKdPDOjVd+JFwSXk9+rMUKpkmHnzghVU5wcXSdrfvM3Z5tV34nqtd3TNYYY2MwBb0o/fGnBGH/7mC3c77VErXQXs/EfWT6N21oecYHPfLTvUEA5IksZS1g3rTvePSJJ+/+PWxPx3B0b14ZWEItU+Hb3XWlr5/aG5+0G8cKJXf/StTv3w5x9KslrbVspeAECyQpY0F2r+/Z27nHO771brH87pmbwkaxToQiypgM+rP/rkHknSP//svOKJjHY3hbVntpXs54y4AK5k+EIyorulVFxmYkgy8+uy333XhTSczF7VPlqiAQ0ns+qfNwLy9kBSqemcWqKBq9r/clKZnEJ+rxOAWqNBPdpROrAsZWAkrbt3R9QY8em9wcmi1/rjaSeYFIacjr11JYNMfzytnr6E2tsiOti6/MhSOTifW8H5NEZ8C97XOvv16zw7tuC1/pG08/pSmmutLon++No6FRiZAbBlvfJmvz77iRvUEAnoTx+6Q3/60B0r3va9i2MaHE1pZ31IXzqyT186ss95bXA05bRa2a1m+woCwY07IvpYW9SZx/LKL/okWWHo0Qf268MrCaWz1k+qMtmFP7EqtLM+tGAkKZ7I6L++8o4k6WfvDWnfzlrtbgrr+f9wX9H7/rVg/ovdarZvZ60SU1m9d3FMH3w0oXtubtLO+pDiiYzeu7jwHyMA7mB4/TKjN8hMfCRz+AN5wo1SBax01lwb0MBIRu8NThaNqLx7Kal9zRs/2hsKWCMDXefG1LFnbaNWXWfHnAv71nhQZy6nil5/b3BSIb93xcHkpZ6Y9jeH1LF3dfX0x9N6qaAVsCUa1P9W0PZV6v3H5rUOSsUtX4tprg3ozFBKnWfHdHhvnU71JzWcyDojZYXsEa9Cr74TV2PE5+xnKedjUwuC02owMgNgy/rB6x/o//z+r9Q7OF4UGuKJjH7TN+K0UC3mr/6pp2hbe0WvvypY0ctuNbP3+97FMWdUSFLRPJTeS+NKpLP6WFtU99zcpGR6Rq+82V/y2BeuJBc8F09k9Mv3Y0Wrs/34rQH98OcfOjXY7/vhzz8sOr+f//Yjp6YPr1ijTq+/N+S8bo8wLWcqM7Oi9wHYfIbhkafmOhnRNpmZSeVj52SOX5KZmZByGSm/uj+/p/oSallFS9diWqJWoLH1j6Q1nMzq1p1rn+OzUh176tQSDaqnL6FnTg7o1MDCv1uXUzjCsLshqNR0Tqf65/YzOZ1XKLCyS+qXemJqiQb1YIm2rCVrmA0y7W0RPflAi558oEXxZFavvhNfdJtXT49of3NITz3QYrXUyZqbspLQcLA1rN/ZV6+evoSePjGg13pHFw1BNzZVaziRLRpZ6R/JLNkOeGZoUk+f6NfTJ/rVP5LW/uvW/r3AyAyALe29i2PL3o9lsaWRYxPpFd3L5cv/7fUFz9lLM8/fn33PmOXMXz76at/73sWxBTX97LcflZzM/+O3BhYEvZUuHw2g/AyvX6q7XkYuI3P8ssyxizILXvfsuHXRbTt7R51J7AfbImsezSj04O0NevbkgDM68qsLCTWGfWqNBhe0bG0E+0L+xe4hdfaO6s0PJ1bcatYfT2s4kXU+h9aGoBojPp2PTa2pRWx/c0hnhlI61Z9c1fbvDU6qMeIrGs1pjQbUXxAS59edms7pttnA2NoQVMjv1UR65YH2fGxq9jjWyMurp0f0lRJzig62hnV6MKk3LyTU2hBU59kxpaZzzohOKYVzZqwRpCtKZXIl594shzADAACwlWQSyidjUi4rIxCWEdplBRxvleRZOO+hkL0AwPHTcZ3qS2h3Q3BVE+4X0xINaiCelvZY80/KMfH9C4ea1T9ijXCstO3MDlsvLWjXmptLtM3vUXyFc4tu3blNk9N5dfaOrirMTE7nNZzI6pkTxT9oWmwBBXsE5cPZxQpO9VtzlGqCK7v0P/ZWTMPJrJ4qWGntO52D+l73kL5YYh5Q6+zol2SNZO1fRQth6+z32PDk9Iq3KUSYAQAA2Apm0sqPD0qSPOEmKbC21aEkazRlYCSjX11IrEuYubGpWp29ozp+Oq6Q31tydbPNsNpz6R/JaH9zaEFb2DMnBtR1dkwde+u0Y3ZeyEpHW47e1aTnOwcXXemslG1+T8lloY1ltuvpSzghYzULDgwnswsm7y81EnR4b516+hJ69Z34onNrNgpzZgAAAFzOTI0oP9ovI9woT8ONVxVkbPuuC1lLES9xL5aVOtASVsjvVe9QasNXMCv0YvdQ0TyZrnPWQie7VzBvxB7NKDW3pzHicz6Xg61htUSD6uwdLZo3Yi/NXMqDt0c1nMjqeMGclxe7hxZ9/47agIYT2UXbtqS5kRO79pDfq6ceaHF+HS5oUeuPp52llksJBTwLgkv/SGbJuUGt0aDODKXUGPGtajJ/fzw9Oy9pdTeRtjEyAwAA4GLmxGWZM2l5Gm5Yto1sNTr21OlUX2LBSmTzb675xJGV3fSxJRpQ71BqUyb+2zr21umlnljRzSxXeq+aj8Yzi66yZbdV2fecOXpXk46/Ey9qRyu8aeaC7RuCam+LqKcvoR21AWfEpNpXum3Mfr1wTpOkRW9YebA1rPOxKT09ry2tvS1SFGoW88VDzfpe91DR9o0RX8kWM9uNTdWzoWT5z/bM0KTODM3Nl2pvq1lRXaUYr50ZNZd/W6kt17TVpll9eet/QoHRM8rU71/x+03TVDYn/fULx1Szo23d6wEAAJVj4qM+/flXHlGwyqsqj2QYq78WMZMxaXpSqm+VUeZlmDfChl9uVsj1rL1a2SMrWDa50GLld54d05nLqaIJ+/aNMAvnwWy+df7ADdrMAAAAXMlMj0uZCRlbNMhcS968YN1Ec633WpkvlcktaAmzb4S51dBmBgAA4DKmmZeZuCJPfUvZb4xZLsdPx5e8IeP+5pAevH31S/2Ww9Elbn65Fp++o2FBm5ikMo/KbAzCDAAAgNtMDkuBsFS1Pj/Jd6MHb29wTVgph6Xmt2wl12aUBwAAcCvTlDk1Jk9ke7krAcqOMAMAAOAiZnZSRlVQMrbe/AdgtQgzAAAAbpJOSMGrv48MsBUQZgAAANwkNy1Vbd6NJ4FKRpgBAABwETM3LWMdb44JuBlhBgAAwE1yWclLmAEkwgwAAAAAlyLMAAAAAHAlwgwAAAAAVyLMAAAAAHAlwgwAAAAAVyLMAAAAAHAlwgwAAAAAVyLMAAAAAHAlwgwAAAAAVyLMAAAAAHAlwgwAAAAAVyLMAAAAAHAlwgwAAAAAVyLMAAAAAHClqnIXgNImPuordwkAAABARSPMVBJTMgzp//jj/1WZGVO5fF6SUe6qyu5a+wSutfMtZFzLJ18JNvnzv5a/3Ks+d9d9WKsr2HWnN98qT8A0JY8h+aoM599+AGtDmKkkhiGZpn77xk/LXQkAANgEd3/yiEzTlDx0/gNrQZipMF6v9eOZ69tuLHMlAABgI13sOy+fx1CVYcjM52UQaIBVI8xUEkOSWe4iAADAZvF6JNMw5TEIMsBa8CenghimKQ99swAAXDMMSR7DkMkPM4E1IcxUFJIMAADXFEMyTf79B9aKMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAADAlQgzAAAAAFyJMAMAAOAW+RnJU1XuKoCKQZgBAABwCzMnw+MtdxVAxSDMAAAAuMXMtOT1lbsKoGIQZgAAAFzCzCQlX6jcZQAVgzADAADgEmYmKSMYKXcZQMUgzAAAALhBJiF5vJI3UO5KgIpBmAEAAHCBfDImT2R7ucsAKgphBgAAoMKZqbi1ipk/XO5SgIpCmAEAAKhg5nRS5uSIjNpd5S4FqDiEGQAAgAplTidljg/KU3c9N8sESuBPBQAAQAUyU3GZkyPy1LVIvupylwNUJMIMAABAJckklE/GZHi88jTcwIgMsAT+dAAAAJRLfkYyTWlm2mopyyQlj9datYzJ/sCyCDMAAABl0HGgRRq5MHvvGJ/kC8kTbeU+MsAqsAAAAABAGXS9PSA13ixFb5JqW2VsayTIAKtEmAEAAADgSoQZAAAAAK5EmAEAAADgSiwAAAAAUAYdB1qkK2dkzj42Jcnjk7xVMvxhGdU1zKEBlkGYAQAAKIOutwfU8bsPyJhtlDEMSbmszJmMNJ1UfqRPRrBGRni7ZNBMA5TCnwwAAIBK4fXJCIRlRJplNN4s5XPKj1yQcplyVwZUJMIMAABABTIMj4zaXTLCjcqP9Mmcnix3SUDFIcwAAABUMCNQI6N2l5QYksx8ucsBKgphBgAAoMIZ/m2SLyRzMl7uUoCKQpgBAABwASOyQ+bUmJTLlrsUoGIQZgAAANzA8MgI1sicTpa7EqBiEGYAAADcwheUsulyVwFUDMIMAACASxhVAZnZqXKXAVQMwgwAAIBbeAMyctOSaZa7EqAiEGYAAADcwjBkev3cRBOYRZgBAABwEcNXTasZMIswAwAA4Cb+EIsAALOqyl0AAAAAVs7whZRPXJFh5iTDW+5y1qx/JK2Xe2J6uL1JrdFgucvZMr7XPaThhHUvoqceaFn0ua2CMAMAAOAmXp+MUJ3MiSEZtbvWZZfPnhwoehzye/UnHTvXZd/YPJ1nxzScyBYFllLPbSW0mQEAALiMEWqUmU2v6w00D7ZF9MSRFj1xpEUhv0ff7Rpct31jc6QyOTVGfMs+t1b98bSePjGg/njltDkSZgAAANzGMOSp3Slz/LKUSaz77m/bFVZqOqf+kcq5aMXyUtP5FT23ldBmBgAA4Ea+annqW5QfuyQjk5QiO2QYG/dz6q5zYzrVNxecDu+r14GWsCTp+Om44smsGsI+9Q6lJEmNYZ8+f6jZeb89R8Z2sC2y4BhvDyTV2TvqPA75vXq0oN3txe4hNYZ9Gk5mNZy05oC0t0UUCVY5283fZr5nTg7o8L76ouM80t6k9wYndWa29pZoUEfvanJef75zUPuvC+nM5ZRS0znn/BPpGfXMfiaNEZ++UHC+dr32XJWQ36tHD8/V9cyJhXW0t0XUsbdu0dqPvxN3apSk1oI6v9M56NT29IkB7W8OqX8ks+C5T9/RoGNvxYqC6tH2JrU2WPOWXp13jN/ZV6+DrWF1nh1zzvXY7NfRfq2cCDMAAABuVRWUp+EGmYmPZA5/IFXXyQhGJI9X8qy9tejNDyfUGPY5E/O7zlnzLp44Ys27OH46rs7eUSfMSNJwMqtqv9d5z7MnB3T8dFwP3t4gSXq5J6aWaFCPtFsX3/Pb2OwgUxiSvt89pOe7BovCyZmhlNrbIvrCoWYdPx1XT19CIb9XT84e9/muQR3rieloe5MW09k7qkdmL+Bf7B7SS7O1PflAi/rjab3UE1PX2bGiYNHTl9Dh2Yv3Y2/F1Nk7qsaIT0/OzkV55sSAjr8T14N3WOf7YveQbtsZdi72n+8c1LG3YkUhqbCOrtmwEAlWlQwIdpB5smDuyzMnBpx9fuXwTh17K6ZUNqcvFoSq+c+d6k+qfyRdcg6NHWTs1071J/Va76gatlXp8N463dAQdD5bO/yUG21mAAAAbmZ4ZNRcJ2NbVGZqRPn4eeVj55T/6L1V7eZUX0LPnhzQsycH1BINFI2qdOypc0KIJDXXBiSp6Kf7Ib+36D2NYZ/T4vT2gDW35+O750ZjPnV7tOj4715KqiUaLApIpdrdWqJBdeyxQsatO7dJkh4s2FdrNKCp2dGIxbS3RZyg1hoNKuT3OiGjtSGoxohPqUzxPvY3h5yQcWNTtSQVjcS0RIOaLGjp+sKh5qJQ0hD2aSpbvM/2togTCjr21ink9+qj8dI3RLVD3Pya7BGq1TrVv3C+Vf9IpugYB1vDCvm9endwck3H2AyMzAAAALhZPqv8+GXJzMmorpN8QRlVAckbWNVuDrZF1LGnzmkna64NFAWL73cPrerCudo/t2z0RHpGkpZdgjnkL/45e8M261I1Pjmj1mipLSqXPcJTaLmJ+KHA0uMMkWDxpXso4HXayFbKDliv9Y7qtd7Rola11HROPX0Jp53MDQgzAAAAbmSaMtNjMpMxGeEmGdX167Lbjj11Goin9e6lpBNm7Ityu4Vs/tyW5dQEV3bJOX+yenzSCkF2qHGTl3piRXNgjr0VWzAyM18qk5e2Lf56YjYUzr0/p5B/9fcaOtg61/729IkBvfpOXJ++o0Ehv1f7rwvp8BLzdioNbWYAAAAuZKbHpKlxeRpuWLcgY7ttV1jDyazTHja/bet8bGpV+ytcKMD28rxRi5aGoAZG0s4xJav1rHDujluUWrp4oMTKcD19Cee9XWfHlJrOOa1z87VEgwtGTM4MpdQaXd0I3Hwhv1ehgBWIGsM+nbmcWmaLuZBZCdwXcwEAAK51+azMZEyehhuuaqL/Yg60hPXmhxM6H5vSgZawPn+o2ZlPI0n7mkOr3qe9cpe92tnD7U1FgaZjT51SmZw6e0edUZ/G8MIVwtygtSGo9rZIUcvW/uaQhieL2/Ta2yJFrWiH99UvOrH+6F1NerF7SM+cmLvBqb062WrMX62sNRp0RmKO3tWkY2/F9PSJ4puo2hP+WxuCao0GnRa1SljNzHjtzKi5ti3XuZJ1tvry1v+EAqNnlKnfv/INTKuMX/z0hK5vu3Hd6wEAAJXjYt95dfzuAzJmG2WMVVyK5Ef7ZQQj6z4iU2k2/HKzjNezz5wYWHYp5uVU+OV4CetcsUGbGQAAgKuY2dTsZP+tHWSAlSDMAAAAuEk2LcO3+jYvYCtizgwAAICbzGQkP2HG7Z4scdNKrB4jMwAAAC5iZqes+8gAIMwAAAC4hmnKyE2v+oaYwFZFmAEAAHCLXEam17+6pc+ALYwwAwAA4BJmNi3DV13uMoCKQZgBAABwi5m05Ct9U0XgWkSYAQAAcINcVmZ6QkagvHdcByoJYQYAAKDSmaby4xdlRHZIHl+5qwEqBmEGAACgkpmm8okhGV6/jGBtuasBKgo3zQQAAKhQ5nRSSnwkoyoo1VxX7nKAikOYAQAAqASmKeWnpZlpmTMZKZuSZqalmmYZfubJAKUQZirUxb7z5S4BAABsoI4DLdKVMzJnH5syJK9fqvLLqApIwVoZgYhkMCsAWAxhpqJYf53dd2C35KmSDEOmaS69CQAAcBVD1r/vecOUJ3qDPF6PTNPgPpjAGhBmKogpyTBzkqSPpY/KNHyS+JsNAICtxPr3Pq93Av+PPEZWMqtkGFySAWvBn5wKYsiUYc7IUF6+fFwyPNaQMwAA2DIMQ5JpyjDz8phpmQopr7wM2smAVSPMVBJDMpSTIVNVSkomQQYAgC3HtP5jGKYMc1qmEZDBJRmwJvzJqTSzc2QM5cpcCAAA2FCmKSlf7ioAV2M8EwAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYAAAAAuBJhBgAAAIArEWYALO0Tw9JhU7r9ldKv195vvX7YtH7vdoXns+vx0u+5+Tnr9U8Mb25tt79iHXcj2V/vcpwfAACrRJgBsLxsXGp4qPRrN/6t9fpWk41Lux4r/dr2z23Nc77nrDQzInUa1q+Jf1s8xLqFHU63QtAGACxAmAGwvIl/s/5/83MLX6s5NPf6VjLxb1L1noUXwbsel3wN5Tnn05+xQsZGqYpKqd8WH+/0ZzbueAAAXCXCDICVmeiWop8qfu72V6Spc9Lov5bexm5XOmxaP/Wf/9qux4vfU3v/XCvVYVM6+MbCfd5ztnibwoBl76+wDcx+rjCU2D+tX6yNTLLOKRuXWv5T8fO7HpPiPyq9jX3cUm1qB9+Y+7Waz6Tw/Oz9L7XP+Z/Z/P3Zv0qZGVl8BK6wxsXqX+pY9muF77Hb2Aq/pqUC82q/j+zP/ebnpANd1u8PdC3/NQcAuA5hBsDKXPnBwpGKmv9FGvlJ6fcfNq2LfrtlSVp4oX3zs9LbHdbrU+esC07fduvx2x3WqE/hxa19IWvv8/0nrHAx/wJ4++es13/eKF361sJQ0vKfrOcufWvpc574N+scbbX3W5/BwN8tfO/Nz0mRj8/VFv+RdX6Fag5J2Stz76nes/Rncunb1vktdQFeuM9Sn9nNz1r7sT8vyXpfKb/ca/1/sfkyy31NV3Kstr+Y297XYO1z5CfF51v4Pbba76PCz/39r84d3/lMl/maAwBchTADYGUufcsKHDf+rfX45uesi9H3v7rwvTc/Z4WFwhalkZ9YF9pF+/y2NP763OvZuHTqXuvx+OvW8YKt1uNdj1sX/71fWlhT5OPF+3334eLH80NJ6JaVtYmd/ox1jnY4uPFvrePZNRd6/6tztUtzo1WFF+ZT54o/k/iPrHMqVPiZvP9V6zM8Z3NTAAAgAElEQVSp//eL11i4z/HXrfcXfmb2fqS5C/nwwcX3Z4ciO2jYc2aW+5qu9FiFX5uJbuuXvY39f3ubtXwflfrcAQBbVlW5CwDgIiM/mZsUH/3U4u1Wwda5i+H1Nj9IZOPWsZYy8HfSgYesC+7kqYWhaCmF7XU1h+ZGHEq55+zCcLKUdH9xyCplZmTl+5v//uQp6/+7HrfChR3K7OcXM/66FWpuf2Wu7Wy5r+laj7WUtXwfXc3xAACuQ5gBsHLvf9UKM7e/snQgSPdbIePnjetfQ+39xYHG17D8ymLjr1uhZPvnrFGOxUZXSrnyA6tt6fZXlm5Ns1uf7FaoXY8vbDObzx5BWUpVdGV1LuXmZwtar55Y+bmn+4t/v5Kv6VqPtdjxN+r7CACwJdBmBmB1Jrqtn9YvFQhiPyxuz1oP9tyXff8w95zdenblB8tvf+UH1sjKUvN8ljpuw0NLt6bNHx3a/rmF76neU7zUcal9Fs4ZsVv5Ss3RWYmmz1pfJ3u+yVJzRmrvXzhPJvopa3tp+a/pao61Uuv5fbRUax0AwLUIMwBWxw4OSwWC8deteRe7HiteZarU6mSr8fNGKxA4K189a/30fyUXzXYoWWyez1LswLFUqPjl3uLaslcWvmfqnLXAgf2eie6FSx9f+nbByluPXd3ohn2e81cXK7WgwPjr1nnOX4XMXhRgua/pao61UuvxfWSPyt38LKuZAcAWZLx2ZnRtTe0beKuD9bD68tb/hAKjZ5Sp37+KLfLy5FPyjV/UPelDy78dwOrcc7Z4kYHNdPANK0jZ4aCUw6YVZlYbthZz+yvWYgeFx7z9FWt0ar1btzbzWMAW8ctgt3wNUeU9tTKNgGTwM+b5Nvxys8KvZ5fjvvLXuWKDkRkA1wp7WeWVtKRtFb7tC+cT+bavflGBSjsWAACzWAAAwLVhpfeW2UpO3WvNgylcDWyjJtRv5rEAAJhFmAFwbZg/N2WzraS1rXMDGgY2M0wQXAAAm4w2MwAAAACuRJgBAAAA4EqEGQAAAACuRJgBAAAA4EqEGVSum58rXhkJ5XXwjau/6SVwrbnn7Mb9uam93/o7svb+5f++/P/Zu/fguMoz3/e/1Rdd2rpYkm1sjCQwNlYYK7GcbDDJYMMkYTx4DreZGsckJ9TE26mdqSSGnLBhTtU4xPNHYMgBTDjJqbCdXWQCDqkTMJwN4yHMxpfJWLAT2cROImNzkYRsY1mSdWu1pFb3+WNpre7VF3VLbql7Sd9Plcvq7nV51kX2+/T7vO/69AXzuT/Zuu6d2PIbo+b2AaAAkcxgdln/4Sb+kcwnc+fyCd1rXjK39+kL6Ze57h1zman8J58Ln75AYgD3uO4d80++WY33xD/ztaFd+21p+JTUdzj5s0u5ZtYzmTq+n/yZ9W945Y3T2zYA5BhTMyM/ZmIK2lTGus2nrq/8QfJT1Zd/0/wPO/FBfwAK2+kd8+t5QenU3CZ1PpX77a74p/RJEgAUGJIZFI7OJ2emgdLfLFX/efL7S7aan5Wuyv0+M+F5HHCTt67JdwRIZPVGJX5JY7mUa1axPn2SdPob6fcJAHlAmRkKh1VCMlmZmVU6Zv3JpiTt/F4zYYkvi6i80fwP+73/mnodq/wsVZmatd90ZS4rf2Cuk1hSl7j9+DKzVNtMPLamI8nlNZOVqqVbLv48xy+TWDYSv79sylWmek5Slf8lHmN8+V+muFONGbCWrbwx/fqJ+01Vcph43uPP1ZqXko8lcXxRtvetNU4h/v5b+QNnzNmct3jWef/0hdTHGF/eme4Ym44474FU20ws9Uo85vj7KHFfuSrzTCzfTLw2U71HrXjjjzP+2mXzu54uznTX0zpvmcq4qv/c/DImncRrlmrfqc57piQp/ncqMeZsjj/V/ZAqtlyWHAOY00hm4B5rXjLLKg4a5p/TO6SVuzP/p9/5pFlKVvvt2HuZas07n4rtR0pOGlbulo5tMD/vfEpa/nXnf7z+GrOxYW1j+NTkY3cSt9n9svna/uwHZvJlba+/2dxmuqfKb4zGlj22wVw3sbG5crdze3/yYuyzNS+Z61jx9Pyr+Tqd5d80z4G1PeucxF+bxHMiOc9r0xEz6YyPu+a25AZXuritxlf8cS7Zmnyd49cf6zbP1dj52D1Vc5vzWm6MmtfDWqf7ZWntoezHDFTeaG7TOpcHjcl7IGtuM8+3ta/lX5fqd05+3gZ+47zXEhuJy78ute1yHmPi/RC/j/5m8xgnE7/NxOu9/JvOY+5+2TzXVm9B/U7n79iJ2zOfx3grd6dOBtp2mffp8m/GYvj9nbGYpnKPHttg3o8bo7HjTPy9TFwnm9/1T18wl5nsemVijWk5v3dq69Xclvk+yJQkJUr8d7nzqfRfsjQdMbdtLRvfe5R4XjqfMs81CQ2ADEhmkB+TfTuXTsVnnKUPqZKUdM7vNf/DtVgNxlTeusbZ2Bw+ZTZY4nU+FWsgn/6GGUfVZ5O3E7+8v2byBnD8Nnv/zfzbWr78U84GxsBvJF91+m3Fj0nqO2zGV1LnXOb0Duf24o8x8DFzf/HHOFkDp/NJ5/F2/cL8u6zJuVz8MvHn1eopa9vljLu/2Ywl27gTSwpLVyVf5/j1+39txmE1pq17yio9XPOS+Tq+sW39vPhvNCXZLt/fHEvMrAHYVoPcijn+mI/e4PwWPfjH5Huj++XYPd35pHnM5Z9yLhO/D6vHcrKGZPw2E6931WedSWTvvyX/DiXufypO74g1euNLNjufjCUc9TvNn60YpnqP9h02jyH+OK3rkfh7nO3v+vJvmp/FfwmR2HN84nbzuCYbr1L7bfO+nGpZbqb7YDpJUsVnzO1aTn8j/ZcsUuqy3pU/SD4v6f5dBYAEjJlBfkxnAgB/zUQPyNenvu7pb5jrWd9CjnWnL6OovDH5W+nhU5NvP9wz+eeDR7OLM93yY+fNRoOl+s8n3+fKH0ztPCUen6/abBRPRdORyXtvEo2dT27gpjruycY0JcZ9fm+st66sydz+pdb3pzrPqZLDdPoOm9/yrz1kXpPhU7kfg5JY2pNpUotMn0914Hfi8qF255cHS7Y69/kfi2IlRVJuJwQ5cbu5bX9Nco/PVO/R6Zjsd926l7MpRZtMxWfMpPZSJd4H002SQu3ZLXf0hlhJpOScyCHVPRnukfxLphYLgHmHZAbuMdZtNlan2ziN/9Z+sobA2kPmt6vWfpqOJDe6E03WSyIlf/s7Hf6aWCNgrDv9JAJWOc2xDbFGZqYSt0SZkrNEa16KlYhJqRPCbJQ1ORvG/iVTi6XzSfPYa79trjuVcpl0Ul1bf02sARdqdyaaqfQdjp0ba1zHZN9eT8WnL5jfjFsN9zUvZY7HXzN5QpOraXfjG+2JCYt1/zYdMY8hV5NiNB2J3TPx5zlX92gmk/2uW8n3pSRvVu/OVEvzUkm8Dyo+M/XSNSn7xF6KXY+VPzC/eLCSv1T/xk7nSxUA8w5lZnCP4VPmN7zTZZVzpHt+gpS6EZfqm9z4WnurRCJxm/Hlc9Y38tOd6jTwMecYg8kafok9GVbjZyqCf3R+s26NoUkn8dvTbEr/4lklPfU7Y+9ZpWfpygHT6flXs1FWsX56DbN4Hd83z138uB3rZyvZtcrlrJIsa3xTOuEes8cpVxKvbapEJn4ckDUleeK5iR8zteKfpvcNvaX8U85xRpM13sfOOxPWTBNbTGb5N81zf3Kbc/yMdOn36GSy/V23zudkEx5kmgDAmoVxOia7D6x/J6b6ZVH/r53/Viz/Zuz6WRMjpCpXtBK7vsPOL44s6f5dBYAE9MzAPRJLFCzxPRCT6XzSbCyHe9Iv33c4bkD/RJlW98vJ4zY6n3J+q3t6R/I2e/41u56UbJzcFitTsqTb5ulvmI1JK77hU5nL5BKduD02o5ZkNp66X05f8nH0BmfZUHwNfbbeusa5DcnZQ5Ytq6TwUhrjlr7DsYkm0vUydD5pNjBX7jb/WOMsrHOVWPIXP0YnFxLj6345OaHpftm8963B651PJZ+b83sn70mZiqM3pJ7Z6qCRukdkqvuyzrXF6plauTs2TqbvcOy6dD6Zm3s0nan8rh80ks/NVEoPK9Y7x31NhTWoPtV9MN0k6cTtyf8up7ueVvmfJf44rFLM+O1k+287gHnNONDaO73i3Vl65uF0TT283B9QcW+rRqoaprBGRJ5IUP6+D3VdaIbrujF9G6OTN7KtxmsuxwF8+kJyid2nL5jfiuayYTxXcG5iMp2L5d+MzaSXq4bjde+YvXvx+7zuHbOhn6vyukIwE7/rmfa3ZOvMPKdqY5SHkebBWyXN8tdUK+KpVNQolgwKZhLN+G9XgbdnM3Ff+DmO2KDMDHAHf01y70r8uA3EWOUylKfkj686+d70Vee2vG4+qv7z3Az8T7TyB7npyQSAPKDMDHADq5QosbSGJ3EnS/VsGcyu39+ZXBbZ30xP2aXK9Sx4ltPf4N8SAK5FmdklrJEJZWYAACAdyswyo8xscu4LnzIzAAAAAJBEMgMAAADApUhmAAAAALgSyQwAAAAAVyKZAQAAAOBKJDMAAAAAXInnzACY20rqpY/9XCpdZT5MU5JGPpQGWwr7uSdX7pLq/8H53li3NHhMemebFGrLT1wAABQQemYAzF2Lt0j/6Q9SxfpYIiNJxVdINbdJy7+Zv9gyKftE8nv+Gqnqs9K635pJGgAA8xzJDIC56+rvS56A2RNzeod00DD/tP2jNHwq39FlZ/iUM+5I0ExqPvbzfEcGAEDekcwAmJsWbzF7YCJB6difSp1Pxj77YKf01jWx99a8JG2MSg3/LH36gnTjUGzZNS+Z722Mmn8+9bZUeaP52XXvmO9duct8XVJvvo5f/8pd5nsffz322trejUPm9rP1wU6p4/8yfy77uPNYP/V2LMZPXzCPxWK9b/XmWDF96u3YMh9/PXYsy78Zi7npSCxW6xgAACgQJDMA5qaavzT/HumMjS+xGvXWn8VbnOtc9iWz18MTMF9//HWzHC2+RG3Bx6U/edH8uf9N8++KT5t/X/Ft829PIJbgVH1+Ytn/MP+u/wfJWyp1vywN/k4quXJqx/XBztg+JDOxaviJGZfFX2Mey8ofmK+Hfmf+vXSbM6YFH48lOGVrzb/P7Yltp+qzZometb+qzyafMwAA8ohkBsDc5KvIvEzRZc7Xw6ekN680/5TUm413KVaidmxDrMxr+Telsz82P7cSgfJPmZ9LsQSn7OPme1YSYgm1S3/8gvSbFGNjpqL+O2aiMfQ7M+6DhtT7b+Zn1X9u/n3xkPm3lcSUrorFuXSbmaD4a8xtxE8sEAmax/7mlbGyvMvuvrR4AQDIIZIZAHOT1aAvXh7rfbDGnqQT/KPZmA+1STUTM50Nn4qVo/UdNnt6LH2HzfE4/hozIShdJQ2fNmcdK1trvucJmD0wls6npPFhafnXzckJ4svBsmH1+Ix1m3+X1Jl/n90TS0S6X3au8+H3zb/LPm725PhrpL4j5ntVn4/1YllJj2Wk0zz2UJt5bgAAKDAkMwDmps4nzZ4FT0Ba+++x8qhsZwEbPGr+XboqNuvZ4i1mciRJox+Zf188YP59xb1mknDxkDl9sr9Gqv8/zc8GfhPb7ulvSP+xyBzML5nlYNm6cpdU+3+YP1s9JVZSs2xb7NiWbDX/jgybf4fazF4XT0Ba8U/me23fNROxso9LFdeb73X9IvtYAAAoACQzAOYua7B88RXStT83x8lc/0F26/YdjiUMK3eb6177czMhGD4ldT1vfmaVmlljS7p+EesZscaxWD0ji7eYg/M//nps6mWr3Cud0lWxMT71/xCbne2PXzA/P783tq/rPzCXs2I5Gzf+xep1qVhvJkB9h81n7XgC5j5GPjTfAwDARUhmAMxdH+w0x7n0NzuThpEPzTK0+BnOUvnd553rRoLm6999PraMVWpmbbfvcKxXSHKOQxlolsI95licmtuksZ5YwpVo8O3k90Y+NBOlY38a22bnk2YvjxWDtVzbPzqPr+sXsZgGj5l/f/Rc7HOrhymTcH92ywEAMAuMA6290emtmeNIcmzq4eX+gIp7WzVS1TCFNSLyRILy932o60Lrcx4PAAAoHG+VNMtfU62Ip1JRo1gy+I450Yw3Nwu8PZuJ+8LPccQGPTMAAAAAXIpkBgAAAIArkcwAAAAAcCWSGQAAAACuRDIDAAAAwJVIZgAAAAC4EskMAAAAAFcimQEAAADgSiQzAAAAAFyJZAYAAACAK5HMAAAAAHAlkhkAAAAArkQyAwAAAMCVSGYAAAAAuBLJDAAAAABXIpkBAAAA4EokMwAAAABciWQGAAAAgCuRzAAAAABwJZIZAAAAAK5EMgMAAADAlUhmAAAAALgSyQwAAAAAVyKZAQAAAOBKJDMAAAAAXIlkBgAAAIAr+fIdAFJ7q6Q53yEAAAAABY1kptAYhg4d68h3FAAAYBZ89rOL8h0C4GokM4UkKkWjXknSFfUr8hwMAACYSR+2vaeoUSTJq6gkI98BAS5EMlNAojIkg0sCAMB8ETFKJMMjw2AYMzAd/OYUEEOSDG++wwAAALMkEvVLhlfRaL4jAdyJboCCQgczAADzisdQNMr//8B00TMDAAAAwJVIZgAAAAC4EskMAAAAAFcimQEAAADgSiQzAAAAAFyJZAYAAACAK5HMAAAAAHAlkpkZYkTDinp4jA8AAAAwU0hmZogRjShqkMwAAAAAM4VkZqaMj0r0zAAAAAAzhmRmhnjHBjXuL8t3GAAAAMCcRTIzI6IyRgcVLSrPdyAAAADAnEUyMwM8I/2K+koUNbz5DgUAAACYs0hmci0akS/UpfHSxfmOBAAAAJjTSGZyzBfqVtS/QBFvcb5DAQAAAOY0kpkc8oz2yzM2oHDpknyHAgAAAMx5OZs7uG84rH8/1afz/aMKR6KqKPFp1dJSratzDoJvaR/Q+13D6hkKmwF4DFWX+XTt5WVataRUkvT8W+fVHwrHgvQYWlJRpD9dVanK0sKc7tgTHpYveF5j5bWMlQEAAABmQc56Zl7/Q4/OXBxROBKVJPWHwvrtBwPq7B2xl3nld9367QcDdiIjSeFIVOf7x/S7jgH7vfhExlrmzMUR/fupvlyFm1Oe0X75BjsVLluuKOVlAAAAwKzIWTeHz2uo8YoyrV9RoVPnh3WgtVeS1BsMa3lVsVraB3TmopnYrFxSqnX15aos9amzd0TvfBRMSmAk6YarK7Vm+QK90dqr0+eHFRobz1W4uRGNyBfqlmdswOyRIZEBAAAAZk3Okpnb18Zm7xoZi5gb9xiqrTYb+B09IUlmInNzQ5W97PKqYi2vyi4JKPEXSvlWVJ6RfvlCXYr6F2isvJ7SMgAAAGCW5XQAytOHzsQ27DH0n66qsMe49AyaPS+Ly4skye5tsSyp8DsSIkk68m6fjrxrlpaVFnm1trYsl+FmzYiGZUQj0viovGOD5gMxfSUKl9UyaxkAAACQJzM2mj4ciepYx6CqAj4tryq2x9KkXX588s+HR8f176f6tOW62Z0prLi31fE64i1WuGy5Ir7SWY0DAAAAgFNOk5ntGy6XJHX2moP1+0NhHesY1PKqYlUv8KlnKKyugVFJC3RzQ5VubqhK6qGJZ42Z6ewd0RsnL6o/FNaJziGtWb4gl2FPaqSqQUYkLCMyJkXG5A0PyTfYqajHq/HSxYr489NbBAAAAMx3OZvN7Pm3zutE55D92jcxhCQcMcfPLKkwy7FOnx/W4VN96hs2y87GMvTIFIKox6eIr1SRogqNBZZpdOFKjZcukTfUI3//+/KEUydjAAAAAGZOznpm+kNhxxgXy9WLA5KkG1dV6kzviPpDYbWeHVLr2aFUm3FI3F78hAL5FvEvUMS/QJ6xQfmGOjVeXKXxkpp8hwUAAADMGznrmbnh6kpVL4jlRtULfPrkleWOkrAt1y1R4xVlqiiJLWc+ENOv1Utjy8V/bi1z+cJi3fIn1QX30MyIv0xjFVfKEw7KP9iZ73AAAACAeSNnmcGa5QuyGsuyfkWF1q+omHSZ2R7kf6mihk9jZVfIP/ihfMGPFA5clu+QAAAAgDkvZz0zMDS2YLmM8ZC8IxfzHQwAAAAw55HM5JLhUTiwVN7hLhnR8XxHAwAAAMxpJDM5FvUWK1K8UL7hrnyHAgAAAMxpJDMzYLykRsZovxSN5DsUAAAAYM4imZkBUcOjqC8gz9hAvkMBAAAA5iySmRkyXlQu7+hgvsMAAAAA5iySmZniLZGi4XxHAQAAAMxZJDMzJGp4ZUTG8h0GAAAAMGeRzMyQqMcnI0LPDAAAADBTSGYAAAAAuBLJDAAAAABXIpkBAAAA4EokMwAAAABciWQGAAAAgCuRzAAAAABwJZIZAAAAAK5EMgMAAADAlUhmAAAAALgSyQwAAAAAVyKZAQAAAOBKJDMAAAAAXIlkBgAAAIArkcwAAAAAcCWSGQAAAACuRDIDAAAAwJVIZgAAAAC4EskMAAAAAFcimQEAAADgSiQzAAAAAFyJZAYAAACAK5HMAAAAAHAlkhkAAAAArkQyAwAAAMCVSGYAAAAAuBLJDAAAAABXIpkBAAAA4EokMwAAAABciWQGAAAAgCuRzAAAAABwJZIZAAAAAK5EMgMAAADAlUhmAAAAALgSyQwAAAAAVyKZAQAAAOBKJDMAAAAAXIlkBgAAAIAr+fIdAFL7sO29fIcAAAAAFDSSmYISVVTShrW1+Q4EAADMgmgkIo/XUDRq5DsUwJVIZgpIRJIiEUnSzzu/k9dYAADAzPrC8u8qonEZUUMew5vvcPLu2eZzKi3y6q51i2d1v/uPd6u9Z0Rf3Xj5rO4XuUEyU0AMRRXReL7DAAAAs2Q8Miav4VVEEXmM2FDmQ6cu6mjbgGPZ2uqSWW/oA4WOZKagmOkMAACYHyLRsCLRcXmN1HMy7ficWXre3hPSiy1d2n+iW5vW1MxmiEBBYzazQmJI0Wg031EAAIBZE5WRxXCZuuoSrV4aUEfPyMyHBLgIPTMAAAAuEByNVW9YPTVN9eV2OZrVi3OsY1AHT/baywaKvNq+wTkeZPfrHUnb37i6StULfGm3m1j6tnF1ldbWlkmS9p/oVvfgmGrK/Dp5LigpVhYXv6871y1WXXXJpMf5bPM5XRgcs7fxVxOlde09Ib3Q0qV19eVqmYjj3rjYWuJiW1dfrg2rFtqvEz/fuLpKTROxJ/rlb7vU0RPSvZ9nQiY3IJkBAAAocO09IXX0hLR6acDx/tG2ATvZkGKJTHyi8WzzOT196Iyd0DzbfM4x/mb36x1qqi/X2toytfeEUm730KmLujAwZr+3/0S3Dp7stfchSRcGx1Ra5NWOz9Xacex+vcNOYF5o6dK/nuhJSqzidfSE1FRfri+uX5q2tK6lbcBOYqzYWtoGdNfEfqykp7zEp6baMh06dVFdA2P2OlbsqZKZX/62S92DYyQyLkIyAwAAUKDiezWaEnobJLOHId7vOwdVW13iSDL+ZHmZDp7sVXtPSHXVJbowOKaNq2OfLyrzKzjinIAocbuJ+11aWayT54L2NiWzB8hKkNbWlul/vd+v1csC9ucrFpeqYyJZSqe2usTeV111iWon4p0stvbukBqWxvZTV12iRWV+vdc1rKbasqTYL6ssVqsVe02sl+iXv+3S8Ng4s5q5DMkMAABAgYrvHclWoMg5JLp6gdnc6xkKq67aTDrO9Y1IEz0xFwbHVFszeemX5Cz/mi0LijwaHp18ptfgaESt54JqnShvs9RWx6a7/lmG2IOj4wr2jGtRuf/SAsasI5kBAACYQ+LH1khmEiPFkhpJOnkuaI9tWb00kNR7keiFli5J6cflzJSh0cyzvAaKPKqrLk47y9svJ2K3ysyOpog9UOTVVzderid+1aH9x7u1qZEZ49yCZAYAAGCOqK0p0dG2AR3rGLRLzX7fOahFZX57PElwdHzKPT6JvSPvdQ3nLOZ4HT0hHTp1URtWLbTHCa2rL590nUVlfrWeC6ZNZqYS+8bVVTp4sleBYq82XGMmeD9rPidJ+tL6pVM5FMwSkhkAAIA5YsOqhQqOjOvgyV6792FRmV9fnGiIW1M8J85mtnppYNLn13xx/VLtfr3DXi9xIoJcWb00oJNng/asaQ1Z9BpZcT+RcEzWjGVfWr9UT7zeYX/eMEnsTXVlGgiF1dI2YE4gUGcmhKV+b9p1kF/Ggdbe6T3YJIs50fNp6uHl/oCKe1s1UtWQ9fJRRRUeD6msv00/7/xOzuMBAACF4wvLv6tQ1TIV+wLyGH4ZaR6cmUtWeViqGdCymTZ5ts14czPDDtq7zZnR7lq32DFZQKEo8OZ4CjmO2OChmQAAAPNGfyisQJE36T1JBZfIFIL/9cGA1tWXF2QiAxNlZgAAAPPEhlULdWFgLKnM7M6JKZXh9Fef5LwUOpIZAACAeeQuEhfMIZSZAcAlWrFojR67a782XH17Vu8DAIDcIJkBAAAA4EokMwAAAABciTEzADCLVixao69v+L79uq2nVbsP3Jv28xNnm/WTIw9JkjZcfbvu+MTXtO/tH+mOT3zNXuapQ9/WexdOzHzwAAAUGJIZAMiROz7xNUeSkchKVA6/+7JefPuHkqR//Mtf6Cs3PKSfHHlIKxat0d+u36lvvbBJUix52XD17Tr07kv2dj7/sS/ay+y46Ql9fcP37dcAMBvae0J6saVLG1dXaW1t2ZTWffrQGdVWF0/6kE4gW5SZAUCO7Hv7R/rWC5vsP08d+rbj85tW/bW6BjvtREaS3u/+g66quVaS9N6FE/qH//E39mdWAlNTttyxnf/evMv++f878d8kiUkGAADzEj0zADBLyosXanHZcj12137H+0Oj/fbPX7nhIa1Ztj7rbVJeBgCYz0hmAGCWDIxcVNdgp7732raUn9/5ib/TmmXrHSVjiYlPohWL1uQ0RgAA3IRkBgBmyenzR7Vm2Y2eeJIAACAASURBVPqkMTCWqsASx+s7P/F3Kbfzt+t32uVo/9ua/6yh0f6U2wOAmdYfCmv36x326/gxNPtPdKt7cEylRV519IRUW12S8oGdu1/vSPsZkAnJDADMEivhSJwowJqx7CdHHtLf37LH7o1p62l1lKBZWjoOOHpsGPwPIF+Otg1ox+dqJZnJy8GTvape4FNddYkk6cLgmGqrvfYyiXa/3qHVSwNMBoBpI5kBgEv03oUTKROKVO8fevelSXtR0pWgxXu785BjEgEAyJeNq6vsnzetqdHJc0F90B2yk5lAkTdtj8vu1zvUVF+uDasWzkqsmJuYzQwAAAA5ESjyZrXcyXPBGY4E8wU9MwAAAMiJ4Oh4VsutXhpQoNiro20DurKmxO7JAaaKnhkAcIlD776kb72wiemYARSMgyd77Z/3n+iWpKzLxjasWqja6hK92NI1I7FhfiCZAQAAwLQ01Zdr9+sd2v16h06eC+rOKc5Idte6xVpU5tfTh87MUISY6ygzAwAAwJTUVZfYM5Sl64lJN0PZ9g2XO15/cf3S3AaHeYWeGQAAAACuRDIDAAAAwJVIZgAAAAC4EmNmAGDCpmu/rKYrNmpx2XJJ0uj4iC4MntG/nfy5jn54MM/RpdZ0xUb979f9vUbHR/TgS7c7Pnv49pdU5C3WP7/1vYKNHwCAS0EyAwCSdtz0hOqrGxzvFXmLdXnlVdp07ZcLNhkoLzYH3hZ5i5M+s96zlgEAYK4hmQEw72269st2InPibLNefPuH6g2e14pFa3TTqr9WdeCyPEcIAABSIZkBMO+tWXaDJDOR+cmRh+z337twwvGAyg1X3647PvE1vXP+mKoCi7W4bLldwtV0xUZ9dvUXdHnlVZKkodF+/fHcb/Tcb/7JXu/i8AXt+pcvSZL+y58+rGuWrNVv2v+nnvvNP0mSdv7Fz7SwdJH+cf+XdWX1x7Tp2i/bJW9n+t7X9//ta5d0nF+54SGtWbZeh999WQ2XfVKLy5ZraLRfLR0H9OLbP7ykbQMAkA8kMwDmvUVl5jMPTp8/KinW6LckJhLXLFlr/1xevFArFq3Rlk9+y1HqtaCoQp+q+zMNjw3qxbd/qFvXfEULSxepKrBEvcHzWr5whSRp5eKPS5JWLFqjhaWLdHH4gnqD5/Vf/vR7Wly2XO+cPyZJ9vK5cOPVtznivPHq2/R25yFH4gYAgBuQzACY91KNN4nn9xY5Xg+N9uuFY/+3Puj540Ti8bCKvMU60/e+9hz5jv3eNUvWquGyT0qSzva9r/rqBt206q/1duchLSiq0Oj4iJ3grL/yVknS6a7fOfY1Oh7SgVP/b04TDStOSfrWnz2lBUUVWn/lrSQzAADXYWpmAPNe12CnJGnlkiZJ0k+OPKRvvbBJJ842p1w+ODqgox8eVG/wvCSpKrBYkvTWB/vt9/5w9ohjnZPnWyRJVy9q1CeWb5AkfdD9R0nSTav+2i5Pa/7gVUnS/j/8VBeHL2jNsvX6+obva8dNT6SM5XjCfrJZpif4kXqD59UbPK/3u/8gSSrxBzJuBwCAQkMyA2Dea+s5KUlas2y97v7Uf1VVYIkkqchbktX6wdEBSdJ1V26y122qvVmSNDY+KslMTkbHR7So7HJdvahRQ6P9er7lMUlmgnN55VUaGu23e0eOfnhQu/7lS/rnt76ni8MXVF/doA1X3564a/UGz2t0fESSOSNbVWCJqgJL7ORndHzETrAs1YHL7OWuqrlWkhQaC2Z1rAAAFBLKzADMe8/95p+0cvHHtbB0kT5V92f6VN2fTWn9ox1vqL66QZdXXqV/2PRTx2dvfbDf/tkqNbu88iq19bSqN3heXYOddq9M58X37GX/8S9/oQuDZzQwctF+L/7neB90/1HXLFmr+uqGpP2/MzEOKF5inKPjI3aPEAAAbkLPDABI2vUvX9Lhd1/WxeEL9nuj4yM60/e+fv3uy5Oue+jdl/Ra63OOdS8OX9Brrc/p0Lsv2e9ZpWbxP1u9QpL05gf/Yv98YfCMllVepTXL1svvLdKJs81pn3Xz//z7gzpxtjlp/4fffdkxO5vlTN/7dmnd0Gi/Dpz6JeNlAACuZBxo7Y1Ob80cR5JjUw8v9wdU3NuqkaqGzAtOiCqq8HhIZf1t+nnnd3IeD4D5zZqlLXEKagD58YXl31WoapmKfQF5DL8Mg++YE814c7PA27OZuC/8HEds0DMDAAAAwKVIZgBgnmGwPwBgrmACAACYJygtAzAdh05d1NG2Ae34XO2U1mvvCenFli5tXF2ltbVlMxQd5juSGQAAgDz7b4fPKTg6LkkKFHm1fcPleY4IcAfKzAAAAPJo71vdKi0ytONztdrxuVrVVhdr/4lu+/Nnm885Xl+KXG4LKAT0zAAAAOTR8GhUtVXF9utNa2ryGA3gLiQzAAAAeVRaZOjkR0FtakxOYna/3iFJujA4ppPngqqtLtFd6xZLkl5o6VJHT8heNn5My7PN51RT5ldHz4iCo+Nqqi/X0baBtNvKhjV2JtX+nj50RquXBezPN66uUvUCZzPzWMegDp7sVVN9uTasWpj1foHJkMwAAADk0dbravTU/zyv3a93JI2X2fG5Wjsxie+xeaGlS4vK/XYy8mzzOT3bfE5fXL/UXubkuaAjcdiwamHKbWWroztkJzDPNp/T04fOOGI92jbgGOzfHpdoWYkMkwEg1xgzAwAAkGff/Oxy3blusYKj49r9ekfGcS13rVvs6N2oKfMrOBpxLFNbXZLTHpD4ROlPlpcpODruSFhWLw2kTFTO9Y3o4Mle3bluMYkMco6eGQAAgAJQV12iHZ+r1f4T3Tp5Lpix98QqQbMEirwzGZ5DYgnZZE6e49lWmDn0zAAAABSQQHHmpOTpQ2e0emnAngFt9dLALEQW0zMUznrZjaurVFtdon890TODEWG+IpkBAADIk87ecf3k3y843uvoDmlRmd/xXmIJmfVMGnudnpGs95m4rWw923zO/vn3nYNaVOZXXXVJVuvGj+0BcokyMwAAgDxZXuXVFVVFevLfOu33FpX5k8anHDzZq92vd9gzkG1cXaWDJ3vtEq7VSwNZJTSptpWNQJFXNWV+u7RtOg/23L7hcu1+vUMvtHRNaRY1YDLGgdbe6PTWzHEkOTb18HJ/QMW9rRqpash6+aiiCo+HVNbfpp93fifn8QAAgMLxheXfVahqmYp9AXkMvwyDgplEM97cLPD2bCbuCz/HERv0zBSkQ8c6dLn+c77DAAAAM2m5VNJ7VpIUnfhjMmT4iiR/QCqtlOGf3fEwgJuQzBSoK+pX5DsEAAAwgw4de0//6abrVOILyDB88nhiA/+j46PS6JDUf1YRf0Ce8sukGei5ebb5nC4MjqX9nOfCoNCRzBSQaFQyDPd1GAIAgOnxGIZkGEn//xveIqm0SNGSShkD5xTp+UDGwivM93MofmwO4EYUZxYQIxqRwSUBAGDeMCbGykTTjCUwDI+MisvlCVQpevFD85tPADZazgXFI48xew+8AgAA+eX1+KSoR0amgdGlVZLXr+gwz2oB4pHMFBDDMGakHhYAABQmj+HLehYzT8VSRQcvmONpAEgimSk4Gb+ZAQAAc8aUxsp6/DJKKqSRwZkLCHAZkhkAAAC38JdK4VC+owAKBskMAACASxj+EkXHSGYAC8kMAACAW3iLZYyPStFIviMBCgLJDAAAgFsYhuQrUXRsON+RAAWBh2YCAAC4SVFAGg1KRQvyHcmMa+8J6YWWLt21brHqqktmbb9P/KpD6+rLteGahVNa72fN51Tq9+qvPrk4Z7H8rPmcLgyMSZLu/Xxt0nv3Tbw3X5HMAAAAuElRQBr4SFpQM2uPdGjvCenFli7He4vK/Pri+qWzsv/56tA7F3VhYMxOYhLfYw5cyswAAABcxSgqk7zFig52ZV44xzaurtKOz9Vqx+dqFRyN6Nnmc7Mew3wSHBnXonJ/xvcuxeO/6tDRdvdO900yAwAA4DJG5eWKjvQrmsdnzqxeFtCFwbG87X8+GBpNnugh1XvzGWVmAAAAbmN45FlYq8jFDmm0QkbZEnNygDzbf6JbJ88F7dd3xo11eSGuTK2jx5xeura6RHeti40vSSxnW1dfnrSPox2DOniy134dKPLqqxsut1//rPmcFpX5dWFwzE621tWXq7zEZ6+XuE46T/yqwxGLNYbm0DsX1Xo2qLrqYrWeC2pRuV9fSlFy9+ODZxQo9qT8TJL2H+9Wa9z5qq0uscfb/PjgGQVHx+04GpYG1N4zkvTeXzTW6Je/7VJ7T2zK7r9at1h1NeZ5P/jORbW0DTiOY+M1C3W0fVAHJs7HgZO9OnCy1/7MTUhmAAAA3MhXIk/N1Yr0dSra/Z6M0kqpKCDDVzIrY2mOtg2oNm5Q/v4T3ZKkHZ8zx3e80NKlfz3Ro+1xSUNHT0irlwa043O1duJy6NRFbVhlNqBfbOlyJDhPHzrj3OdEIrNxdZWaasskmcnLjw+dcSQnreeCWldfri+tX6r9J7rV0jagQJFX907E9uNDZ/TLlq5JB+q3tA2YEw/UlOjQREJQXuJTU5253+DouC4MOcezxPvxwTOqKfOn3YeVyMSv/8SvOvTL35pxfXXj5frlb7s0PDbuSIbi3zMkHW0fVHtPKOVEAFYiYyU37d0h/bKlSxUTx9FUV6bHf9Whm1ZX2cflNpSZAQAAuNVED41RXKboYJeiPR8ocr51xnZ38GSvdr/eod2vd6ipvtzRq7JpTY02ramxXy8q99u9CPZ7ZX57mbrqEgWKvAqOmMsc6zBL5j51Zaw3ZtOaasf6v+8cVG11iZ3ISNKfLC9TcHTc0TNRW11iJ0jXXr4gaVt11cUaTogt0br6crt3Y8M1CxUo8uqjvhHHMul6XH588IzqqosnTZashCtew9KAuqdZupdq3Et7T0gNSwP2cdTVlGhRuV/vdc2dqb3pmQEAAHCpaDRizmw2OiRjwSKzZ8ZfOmP727i6Smtry7T/RLeOtg3oypoSx5TJTx86k5TATCZQFPtevT8UlqSMUzAvKHJ+F1+zwGzOdg+FVVedao3cCBRn1wfQEZdUZVJe4myKB4q9Uzp/kuweFatUrC6uVC04ElHrQNBRyiZJddXeKe2jkJHMAAAAuNH4iNTbYT5vpmaFjFmaplkye2E6ekb0mw8G7OTj2eZzqinza/s6s9zr0KmLOho3ViOTipLsmqWJA+C7h8wkyEpqZkpwJCJl8Wif2uoSrVhcqoMne3VZZfGk5VsDEwlcbB/jChRNPdGwSsYkc3ayfznerb9orFGg2KO66mL9RWNNhi24F2VmAAAALhONRhTt7ZDKFsuoWDariYxl9bKAOnpCdnlXMCHJ6OjOvodCktZOlI5ZY28k56QBklkm1dET0tGOWEnV7zsHtajMn/OHara0Dah94hgOvXNRwdFxu2Qtk6a6MjUsDejgyV57G4lqq0scA/Mls/Ssrrr4kuIOFHkVKDYTokUL/Em9Mqn0JyRVbkLPDAAAgNsMfCQVLZBRUpm3EDasWqijbQP6w5kh1VWX6M/XVOvFli7tft2cAWz10qlP3bxxdZUOnuy1Z0S7a91iR0KzYdVCBUfGdfBkrz0z2aKy1DOJXap19eWOfW9cXWWPPcnGpsYaDY1G9EJLV8pJAv7qk4v1s+ZzjhnTGpYGtGmKvSj/kjAjWl11iT0jmdUj83jcPiQ5Bvw3LA2opW1ALW0DrpzNzDjQ2hud3po5jiTHph5e7g+ouLdVI1UN2a8QNcN4841f6Yr6FTmPBwAAFI4P297Thls+L2OiUCbbmZWjo0NS/9lZLy3LhxlvbhZ4ezYT94Wf44gNyswAAADcZXRIKqmc84kMkA1+CwAAANxkbFgqCuQ7CqAgkMwAAAC4RTQqjQ3P6PTLgJuQzAAAALjF+Iii3iKJEjNAEskMAACAa0THQjJ8lzZ1LzCXkMwAAAC4RTgk+XP7PBXAzUhmAAAA3CA6ruhwn4zi9E+UB+YbkhkAAAAXiPafkxGolryUmQEWkhkAAIACFw31SeGQjAWL8h0KUFB8+Q4AAAAAaUSjig5+JI0MSgtrJcN9z3wHZhLJDAAAQCGJRqTwiKJjQXOMjK9Yqlkhg+mYgSQkM4UmGpUkfdj2Xp4DAQAAM2nD2lrpfKuiE6+tv2V4ZPhKpKKAjPIlMooY8A+kQzJTSKIRyYjqT9deqbr/eFQRrz/2DxsAAJgTjKghRSP60PNteauukOHxK2p4qSADpoFkpoBEDckYH5ckecaCMsZ9kviXDQCAuSQqyYhGpGhEnvCYokWeiRIy/s8HpopkpoAYkjwal6GIvCN9kmEoyj9sAADMKYYhKRqVEY3IiIzJiBQprIg8Hm++QwNch2Sm0ESjMhSVNxwU39AAADBXRWUYUUWjEUWjURnUmAHTQjJToIxoJN8hAJiiql0tCr35vIZfeeSSt1W+/RkZgUr1774jB5HNrood+xQN9mng6XvyHcqU+eqbVL5tj4ZffVSh5r3T3s7CB9/QWPsxDT13Xw6jw5wTjZq9NIbBGFlgmkhmAJep2LFP3po6x3uJDejSzQ+o5PotaT9P3EbvznVp91e+/Rn5ahvt1wN7tincdvSSjsGNEs+DJI22HiyYxupUrqnbZLqfAQDzFxOWAy4U7jiu3p3r1LtznUJvPq+S67fIV98kSSpZv1Ul12/R8KuP2svENwTLtz8jT2mlY/3y7c+k3M+Cux+Xr7bRXnb41UcVuOM7s3KMM6lixz4tuPvxKa833t3uOBdFDRtVsn7rDEQ4NZmuafn2Z9Je4+nsK1fbykam+xkAML/RMwO43NiJ18xkZlmDwm1HZUx8Ox9fIhP/Lb0RqNR4d7v9erJvuD0Lqh3Lhpr3XlLpzVwSat6r0lvvt893Pk3lmrpNpvsZADC/kcwALlf8mS9LijX2ohON2gV3P56yBCoa7JOvtlG++qaM5WKRoR4V1TaqZP3WtElMpjK0hQ++ISNQ6VjHKhOq2tWi4VcfVemt9zvWL/7Ml1XUsFGS2QuVOPZispKqih37NN71vryLr7KXiS8Hq9rVIkny1tSpaFdLyu1no3TzA5LMZDIda/xFvMSGePz5iwb7dPHhm1Nuq2LHPnlKK1N+Ptk1jT//VbtaNN7dbo/DWXD34/Z5lpzXzup9MQKV8tbUabT1oPx1a9NuK13M1jWIP8+pxpOkG2cz2f1csn6rSm+93xF3/JiX8NlW++f4e6x35zrHeU9VLmjU1Nn3iqSkMTSJpW+ZzgUAYGZQZga4kK+2UVW7WlS1q0VFDRs12nrQ/izUvFejrQdV1LBRVbta7Ea3ZeDpexQN9ql82x5HYy2Voefu03h3u0pvvV9Vu1rsUjZL+fZn5K2pc5Y3xTXey7c/o8hwn/15NNin0daDzvE9E43R3p3rNN7drvJte+RZUK3enes0sGebfLWNjmOo2LFPkuxtjrYe1MIH33DEVdSwUWOnj6QsB7P2M9p60NzHFBIZ70QDt2pXi0qu36Jwx/G0CaHVqA69+bwda7jjuOOcJ56/sfZjKcvfrGNOl+hMdk0vPnyzGedEaWJ8ImOdDyu2sq2POY+htlHjXe+rd+c6DT13X9ptpTz+2kb7GljX0drnWPsx+evWOs6Vt6ZOY8f3J21nsvs51LxX0WCfndBLZnIfDfY5E49b73fcg1W7WhQZ6pm0XLDk+i2Oe6z01vvt+99KZKz7tnfnOnlKK+3rBACYPSQzgAvFj5np3blORQ0bHeMYhp67z26glly/JWUD1+ohqNrVMukYiP7dd9iNwPJtexwNNl9to0IHfmy/tpIUq8HpranT2Okj9ufj3e3yLKh2bD/05vN2QjB2+ojj2/lw21Fzncql5v4mGr3Bfd+11x/59U9lBCodjdFwx3E7FqtRm4tysPgxM70718lbU5e2AVt6y70a7253JG7Drz0hSXasvtpGjcQ14Ieeuy+ph8Dqscj0rf9UrmmqfYXP/CGpB228u33aExzEX4Nw21GFO47Lu/gqScnXzL/mlqQEJDHWdPdzYmLkXXyVxtqPOdYffvVRx/Lxx2UlRIn3R/w61rL+NbdIkoobN2m09aAjkR05vj9pYg4AwMwjmQHmgNHWgykbUgNP32M3cFN942/1plglSpO5+PDNGn71UXlr6lSyfmvsW+qJXhvrT7zIcJ98l19rv/bVNioy1DPl47PXX9YgSXYPRNWulqQyrlSiwb5p73MymRqwifu1Gr/xDedo3FiXRN6auik3kKdyTRc++Iajp2kmxV93K0n1N26SJPlX3pCUgKSS6n6OT4ysZHfk1z/NefyJ1zLSd875+cR1zHTOAQC5xZgZYB6YrDE/WWM6Ufhsa+zniYZ5pudxWCVxkvlt/aVMZWzt3y3TQyf2dFgN3fhzPlmP0Xh3u4L7vqvybXtUuvmBrAf2Z3NNK3bs03h3uwYeNnvBEseA5Fpij9zom8/bpVuJvW2ZxN/PVq+Pv3GTvCuu03h3+4zcG4nX0uottD+3xga54L4EgLmEnhlgDihq2Gh/s12+/RnHuIKS9VvN2a7ee0uSknpP/I2bFA32pWyELXzwDcc3zYmTDYx3t6tokgawt6bOMa7gUh+iGG47qmiwT6W33HtJ25GSG9elmx9IOS5oMsWNmxTuOJ7ys7GJXpv4a1F6y72Ocqpwx3EVT/ROWDEk9qCF247a02+nmwY6m2ua1Bgvdb72r7wh3WEmSdxWKvFjnXz1TfYYGotV3lW29bFJE5BM97NknmtfbaP8dWsd+7gU8RMGWNfESibH2o+pqGGj83djknsBADBz6JkBXCi+t0NyzsY08PQ9SWVD8b0noTefd6w72QxaoQM/nnQ2rv7dd6hix76kxrS1TOKEAFLq2cmm4uLDN9vlUdkcQypWr0BVitnMJvtm3Zsww9VkxxJq3iujps5MQiauRWKcA0/f4zh/6Y5j+JVH5KlcqtJb71f4bGtSjJmu6fBrT9iledasW4N7v+WYMCBdqWJSLCm2lcpo60EVN26yjz1x4gcplhSkGvhvyXQ/S+a5LrnpqzIClTmbljrxnA7s2Wb/PPTcffJsf8Zxb1/qfQ0AmB7jQGtvdHpr5jiSHJt6eLk/oOLeVo1UNWS/QjQiTzgk/2C7Vr3ytZzHA8wmazavdNPmFtrzaqwpnS+lDA5TY5W25eK5MemmdgYK2anNP5KvfImiReWKeP0yDApmEs14c7PA27OZuC/8HEdsUGYGYIZYg/XjexHs9+LG3hQCq3yLRGZ2+VfekJPSrMmmdgYAzG2UmQGYEaHmvfKuuC6pBG341UcLbpB0qHlvwfUUzXVWAjL85qOZF84g1bNlAADzA8kMgBkz9Nx9Gsp3EChI4bajOSkvk+hRA4D5jDIzAAAAAK5EMgMAAADAlUhmAAAAALgSyQwAAAAAVyKZAQAAAOBKJDMAUqrYsU/l25+ZlX0tfPANlW5+YFb2NdeUrN+qql0t8tU3pV2mfPszqtixL6f7rdixT1W7WpKm3k4V04K7H9fCB9+45P0tuPvxS9rGVJRufiDlsQEACgvJDJAjVbtaUjbIp9qQ9NU3pd1WOhU79mXcx4K7H59242w6MbmJ1fi2Hp6Zb1W7Wma14T5VpZsfkLemTr0716l35zrX3R/Z/L4AANyBZAaYgxbc/fi8aKyVb39myr1HVuKC6fNULtV4d3u+w8iZ0s0PXHLPEQAgP3hoJlBgpvMwwf7dd2Rc5lIeYJnLBxwWolDz3oJ6enyhn2vPgmrHa7fdH9n8vgAA3IFkBphl8T0JvtpGSVK447gGnr7Hfr9qV4tCbz6v4VceUcn6rSq99X4Nv/qoSm+9314mvvFYvv0ZGYFK9e++QxU79slbU2dvJxrs08WHb1bp5gdUcv2WpPWsGBK3mSg+psT1JGlgzzaF245KkiOGVNtd+OAbMgKVkqTR1oNp9xm/b8t4d7v6d9/h2EbVrhb7fcnsmSpq2JgUW/z71jYH9mwzz8W2PRp+9VE7qbHOV6rjsyy4+3H569bq4sM32+9Z18s65sTtxO/DuheMQKW8NXUabT2ooefu08IH39BY+zH7yfa++iaVb9tjb8NaLp5/zS2OZVLFGy/TNUon8bxbscTfH9lIvIcS442PL9xxPGNM8ecr1b1esWOfosE+DTx9j+P3JT4O656IX8+6npLs36VUEq+zJMf5SPw88bPixk0aaz+mooaNjns58TyluvYAMJ9RZgbkga+2UZGhHvXuXKeBPdvkq23MON6g5Kav2mMUxrvb05aR9e++Q6OtBzXe3a7enevSNr7Ktz+j8Jk/ZLXNRANP32OvF+44rvHudkciI8n+fLT1oKOEJ/Fzz4Jqu3GcNs6O4/byViPv4sM3K9xx3P4sPpGJ336447jKtj4myeydGn71UefnKRr8VsNzYM829e5cp+FXH1Xgju8kLTfy65/KCFQ6xtr4GzfZje/SzQ/Id/m1jnMRn5BK5r0w3vW+eneuS9lI9dU3qWzrY/Y2hl99VEUNG5PG9xQ3bnIcc3xikyjTNZqMdd6t+2s6Devy7c84xtyE3nzeEW/i55GhHkfilWis/Zi8i6+yX/suv1bRYJ/jd8pbU6ex4/uT1h14+h6F3nxe0WCfvb94RRNJkfV+urLG4VcecRyP9Z6UfD8N7Nmmkuu3OK6hEaiUd/FVjns58TwM7NmmooaNBT2eCgBmG8kMkAfj3e12IzDcdlTRYJ88lUsnXWdw77di63e9L09p+gQgGwNP3+P4Fn062yzd/IB8tY0K7vuuJLPh7a2ps19LyQ1+b02dRuIalQNP36NosG/S/UzWkE009Nx9jgZ2+MwfJk2WUvGvvMFMlCYSnVDz3pSlSeG2oxrvbpe/cZP9nq+20W40D7/yiKPHbfy9t8xl4mYei78XUgm3HXUkpFavjpFwTuLvj+HXnpCklBMaZHONZpqvtlGhAz+2X8c3+iXZgw+gGwAAIABJREFUvVSWoefum3SMzvh7b8lbU2efV+se811+rSTzPESDfdMqJYy/7uPd7RnvJV99k0qu32InNJJ5P422HrTvp1T3TeK+fPVNSecp3HZU4Y7jjsQNAOY7ysyAHJmsQZ6psR4ZnvzzpOX7zk1p+XQSB8JnijOR1WizGmm+ZQ2SlLZXwGpsRqcweNwqC7JijS/TSie+FGq6IkM9WS03dvqIXT5UuvmBpEZzYjnXdCSWzWUyWXlZpms006x7oPTW+5N6qSxGoHJK93ioea9Kbvqq/GtukWT+Pg2/8ojd2+Rv3JSTCQsiQz3yZrivAnd8R+GO444vCjyllfI2bFRRwu9bODh5+Zwkhc+2JsXgv8T7CQDmEpIZIEciw332N8HxvDV1Gms/loeIJrfwwTcc9ffW+I9slW9/RuPd7Y5Gm9XwyjReY6qs3o3SzQ+o9Nb7FT7bmnb7FTv2aby7XQMPx9ZJHMuQjcRB7ukMv/KIXTLkX3mD41pbJUlWiVL8+ItslW5+QEUNGx3lT5lmY5vsmTMzdY2yZe1zsqR0qkm1ZJaa+S6/1pxpret9SebvZMn6rfLW1Dl6OGaKPWX1bmepWmS4T+NxY3qmwreswXGdPAuqp/zlBwDMZZSZATkydvqIfLWNjlKdBXc/LiNQqZFf/3TW48lUMpbYczGVRMYqL0ssvbJK5kpvuTftuuPd7SqKSy4qduzLuhfF6tGJb9wlrpt43P6VN6Tc1mQNfutaWsv46psmHU8U7jguf+Mms7wp7lonneOEsqJsJJYfphtbZY0LkqTSW+5NW1aVzTW6lGcSZSPxHkj1eXHcubLGjky6zffekq+2Ud7FV9nlfONd79vnPFNv3qX25FnlZdaYLEdsXe9PqWdNipWildz0Vcc+fLWNGjt9xH6valfLrD3cFgAKET0zQI7Ydf8J5TP5mLLWml0qfjazRNbsaFbpy2jrwawTGitBiG/wWrMzXXz4Zi188A3HZ/Ex9O++w/Hk+PixBakklozFNxaHX3tC5dv2OGYzG9z7Lfs967jiG8Kh5r0qun6LXWZlzWYWb/iVR+SpXJo0O1g6Y8f3q/TW+x0TIaQ61mxmbks09Nx98u7YZ28j3HE8Zc/FyPH9jnM+2X2X6RpZr2eKNeteYsJkxTzw9D2O+EZbD2ac0cwqNfPW1NmJy/h7b6no1vszrjv8yiMqbtyUcjazbBV/5suSnL//1iyFQ8/dJ6VIEDOVTFqz9qX6PQMAmIwDrb3R6a2Z40hybOrh5f6AintbNVLVkP0K0Yg84ZD8g+1a9crXch4PAGRj4YNvaOT4fhrNwAw7tflH8pUvUbSoXBGvX4ZBwUyiGW9uFnh7NhP3hZ/jiA3KzAAAcUo3P5A0FgoAgEJFmRkAwEYSAwBwE3pmAAAAALgSyQwAAAAAVyKZAQAAAOBKJDMAAAAAXIlkBgAAAIArkcwAAAAAcCWSGQDApKp2tah08wP5DgMAgCQ8ZwaAq1Xs2CdvTZ3jvfHudvXvviNPEeVPxY59kjQvjx0AMD+RzABwvXDHcQ08fU++w5hRpZsfUHHjJl18+Oacbnfhg29o5Ph+HpYJAHAlkhkAmCPokQEAzDckMwDmFV99k8q37Ul6f2DPNoXbjmZcv3TzAyq5fkvK9UrWb1Xprffbn0WDfY6elIod+zTe9b68i6+yS+NGWw9q6Ln7HMvEl8317lyn8u3PyFfbKMkcv2K9n6h8+zMyApV2UmP1uhQ3bpIRqJQkhd58XsOvPOI4DyXXb1HJ9VuSYklk7Tt+O1LsnGZaHwCAXCOZAeB6vtpGR0N7+NVHFWrem3LZsq2P2Y1uqxE+/OqjU0pkrASmZP1WBe74jvp332EnMvH7rtixTwsffMOR0BQ1bFTozecd64yv36pQ816Vbn5AntLKpERl4Ol7pl1mVnL9FjsmK/6xE68p3HZUvTvXZV1mFn/c1nai3e1pzzMAALOB2cwAuF6447h6d66z/6RrYPvqm2QEKjXy65+a67UdVTTYJyNhAoF0/CtvULjjuJ34hJr32r0gRddvUbjjuGPfo28+LyNQKV99kyNWK3Gwlo3ff+Lyl2q09aC9n7ETr0mSfMsapryd0JvP28c9/Mojigb75F1xnSTZiRG9MgCA2UbPDIB5w2qM+9fcYvesGIFKRbvbs95GZKgn68/CZ1slmclDup6faLDP/tlKcqzyr1yXbWXT+5StyHBf5oUAAJhhJDMA5h1rjIhk9jhMpVTKs6A668+sHhArqcnG8CuPOMa0RDY/UJAzjXlKKzWe7yAAAPMeZWYA5rSFD75hP3+lZP1WRYN9jpK0xEShaleLyrc/k3JbY6ePyFfbaJeB+eqb7G1bn5Ws32ovX3T9Fo13t0+rR8RaJ77XyBrEn2ueyqUZlym5fot93KWbH3CU60nmeV5w9+MzEh8AAOnQMwPA9RInAEicRcwSat4rf+Mmx7KSc2auyQy/8og8lUsds6EN7Nnm+Kz01vvtGc2m+vDO+FnLJOd4l+FXHlFxXOypZjObjpHj+1Vy/RYV7WqZtKwt9ObzjuNOnDRhphItAAAmYxxo7Y1Ob80cR5JjUw8v9wdU3NuqkaopDLSNRuQJh+QfbNeqV76W83iA+S7VjGDWzFy5Sg7mo5l6oCcw153a/CP5ypcoWlSuiNcvw6BgJtGMNzcLvD2bifvCz3HEBmVmAOYRT+XSpIHrnsqljkH4mLrixk0KHfhxvsMAAMxDlJkBmDeGnrtPFTv2JZWZ0StzaeiRAQDkC8kMgHllKmNYAABAYaPMDAAAAIAr0TNToE5t/lG+QwAAAAAKGslMoTEMRYqr5R0blDE+JkPTm2xuLnHfTB2XZr4dbzzDmF9HX3BHW3ABzV1TPtWuuzZTC9h1h5doigdg/s/uUdRXpIjhmQMnAMgfkpkCE5FH/pEeRSVF+ccN8w7Je15x+guX666N6wLOg4g0Hpa3pEoyPPPuyxwgV0hmCkg0Kslj/mP2887v5DcYAAAwo76w/LsKe73yRCWD7hlgWpgAoJAYUiTKt1kAAMwXY4oq6jEUpTcLmBaSmYJiKGrwjxkAAPNFVOOKRiMT5RkApopkppAYUpR/zAAAmDfM//f5vx+YLpIZAAAAAK5EMgMAAADAlUhmAAAAALgSyQwAAAAAVyKZAQAAAOBKJDMAAAAAXIlkBgAAAIAr+fIdAADk0o6bnlB9dYPjva7BTn3vtW2zHsuKRWv09Q3ft1+39bRq94F7Zz0OAADmKnpmAMw5XYOd+tYLm+w/kvTYXfu1YtGarLfxlRse0t/fsueS4vj6hu/rxNlmO45AUbk2XH37JW0z3+78xN/pH//yF/kOAwAASSQzAOaB7722TV2Dndqy7r5Z26eVOJ0+f9QRx6F3X5q1GAAAmOsoMwMwL7R+9FvdePVtjvf+/pY9Wly2XJI0NNqvf/gff5P0/mN37Xd8ducn/s6xnX1v/yhlgvLehROSpM9cfVvaBGbD1bfrjk98zX594myzfnLkIfv1V254SGuWrXesY5XMfeWGh3RZea0+Guiwl7HK2B67a7+9/FOHvm3Hkir+w+++rBff/qEjnn1v/8gRl9W7FV/CZ+3D+gwAgHygZwbAvNA92Ckp1mPy97fs0a/ffdlRirbjpickmT0oJ8422+Vq8YlMXdU19jonzjY7Gv2J9r39Iy0uW67H7tpvb9sSnzhY21uzbL3u/MTf2Z+vWbZeTx36tr2vodF+x9ifxWXLVV68UN96YZP2vf0j1Vc36LG79tvrtPW06m/X77SXtxIZ6/OnDn1bN159W1Lp2+c/9kU7pq7BTrvcbveBe3X43Zc1NNrvOG8AAOQLyQyAeSmx5OvC4BkFisonXefFt3/oGMBvlZClG4tz6N2X9K0XNunwuy/biYaVODTV3qy2nlZHDG09rWq47JOSpJVLmtQ12Gn3qpw+f1QLiioc2x8a7bfjOfTuSxoa7dfhd1+21zna8YZjnYbLPqkTZ5vtz9+7cEJdg51qqr3Zsd3/3rzL/vmjgY6M5wUAgHyhzAzAvFAzUTZmNeQTZxqTzBKuTOJL0LL14ts/1Itv/1B/f8seu+wsUFRu99qkiqE3eN5RYtZUe7OGRvuntN9EgaJyrVm2PmmfbT2tadfpDZ7XVTXXXtJ+AQCYKSQzAOaFhss+6UhWvr7h+47xIjtueiJjD4RVKmaVVyWOeckkODpg7yM4OpDVVM3xicellnUFRwf0fvcfHONyAABwM5IZAHOe1Zvy1KFvS0pdFlZf3ZDUM5OY3CS+TizPimeNr4lPVuqrG3TibLMkqb33Hd149W1asWiNY4C+pa7qmqQJAS5V/GQBlyKx3A0AgHwhmQEw5ySWb1kD+S3vXTihw+++rBuvvs2e2evE2WZdVl5rL/OTIw/psbv2O2Yz+95r2+z3rHXSscrK4uOIT06sHqHEUjert8ialSyxJOxSemd+cuQhfeWGh5K2mW5GtlRefPuHWld7E7OZAQAKgnGgtTc6vTVzHEmOTT283B9QcW+rRqoaMi84IaqowuMhlfW36eed3/n/27vX2Kiuu9/jv7HNOPgazG2I64KxG6gxsupIp0CF5Uo1oEeuCajkRGpAauI3oFRclLxASgoplfKCiBA1gjeQSjhH6kMqbo0eQThSLdAD5JHqCsX4mBRDXBcYsDHYHhtssOe8cPZm7z0znovHnhn7+5Haembf1lp7D13/vf577biXB0Dq2L3mqO71ddhGZnavOaqBob6wqWkAUsPrhR/oyawFyszIUpprhlwu5mVymvDuZpL3Z8NJveLHucQuZjMDgKSU5c7Vw4H7Ad/1DT5KUIkAAEg+pJkBQBL605Xf6+2qj2wvuGzvbuXhfQAALAhmACAJ3exq5nkUAADCIM0MAAAAQEoimAEAAACQkghmAAAAAKQkghkAAAAAKYlgBgAAAEBKIpgBMCGqStbrwMazWjynPOQ6u9cc1fbqg5NYqvjbV3tcb67cO2nH2lCxLeiyN1fu1b7a4xN6/EjOKQAAk4lgBojR7jVHdWDjWfM/E2FDxbak6jwe2Hh20jru4Rgd66qS9RFvs6/2eNjgaXv1wZiDgljKBAAAYkcwA8Rge/VBZblztevEOu06sU4X287YOsnbqw9GPeKwoWLbhN9Zh10s52m64HoEAKQCXpoJxCDLnasu3x3z88mrhybkOCevHpqwfccimV7ieKHttC60nY5qm/e/fC3sOp807oi1SDGVCQAAxI5gBojBwFCfFhYs1eI55brZ1Wxbtq/2uLLdeZJG07I6fbf14VdvSRp9rqF8wQpz3U8vvKObXc3aXn1QCwuWmttIo4FDVcl6vVqx1Vwv2D6CBRjGyJFxXGn0TntlUbXZoQ9VFmN7aTRom5tTqOa7V/TZ5dFnMm49aNFnl/dKkhbPKdfbVR+Z+zDWs6oorLKtYz1OMNb26x/qDRmAGMc+dfWwLrSdNuvX1NGo1SV1QbffveaoBob69EnjjpDn6c2Ve1U8uyxgu7k5hVGXybqdwXq+nMud59Jaxua7V0K2mZX1vFrLGuyaCFZXY91g16PhB/kltnPqLLfz2jLaI5h9tcfV1NGoyqJqW12N68j4DVxsO6PVJXW2Om2o2Gaea0m235oUeH0aPr3wjn6QXxJyv5H8NiSZbdR894oa//mXkG0SyzbB6nex7Yx5c8O43m89aFH5ghUBdQeA6YI0MyAGnzTuUP9Qr96u+ijgeZn3v3xN7d2tau9u1a4T62yBjCQzNa29u1W/WfE7c38X286of6jXXB6M0ckKld5m+EfH3zQ3p9D2rM3S+a/o1oOWsGUxLCxYqnt9Hdp1Yl1AgCKNdhR/s+J35j5OXT2s8gUrAp4XqSyqth0nWOfSsK/2uLp8d8z1u3x3tHvN0ZDrO2W787R0/iu2NgyVRhbqPDntXnNU/912JqJ9On341Vvmdp2+22rvbrXtV3p+DprvXrGldTmX52a+aHb2x6p/buaLtrIa+wl2TRTPLjOvCatw12PNj39tq5f1HDmv0VNXD+vViq1jPve1uqRO5//f/7FdR86JDozryBnIfHrhHfNYWe5cW1l+s+J3ar57RbtOrNOnF96RNBpYWYNp534j/W30DT4yf4PlC1bo7aqPQrZJLNs46/fphXe0uqTO9vvKdudpfm7RmNcvAEx1BDNAjN7/8jWzk3dg49mwHdzPLu+1BQX/evht2M6pU/HsMtsd+pNXDwVNi7rQdlr9Q72q/tGvJI0GHnNzCtX4z79EXJZO3+2gQYzhZlez7Y6+ced9tmMk4k9Xfm/+/dfmI5IU9AH5qpL1ynbn2eoTrAMejrVT1+W7oyx3bsTbhtqfdVQhln2+uXKv5uYUmnUzzsd/Nn1srtP4z78o251nts3cnEI1dTSay40Aeiz9Q7229mvqaDRHfoJdE9nuPPOaiIb1nN7r67C1R/HsMl1sO2N+dh43mOa7V8w2vtB2Wp2+2/rhrJdDHlMaDUKa716xBSbW+jrrd7OrWf1DvWNen1L0vw1jpOTU1cPm8tZ7fw+4RqLdZun8V2z1u9nVrE7fbf2k6Oe2/RLEAJjuSDMDxmnXiXXmXdRgaWdW1rShWD0cuB/RercetKh4dpkkqfpHv1Kn77atbPEoizMdJ5yx2sboZMZzZri+wUfjDmaCpSp1+m5HtX35ghW2jusP8kskKeQolRG8PYjiOME4tw93TcTi4cB9c5/S6GjB6pI6W3pUtAaG+iI+tpVRX+vvsKKwSje7ms1gOZI2jcdvY7yy3LkqX7Ai4PdgHd0DABDMAHERSQdp95qj6vLd0fuNwfP9IzUra15E6zX+8y8qX/CRFs8pV/HsMttd/niUZUPFNjOdyBAuEBlrhMVow2SaZEAaDTiszyoYz55E6n9X7lR7d6ttdOffPW2Swj8/NF7OUYjPLu81p452XhPx0j/Uq6aOxnFNXJHlzo0ooHH+Foz6WtvUGlhdbDsTdoKGeP1Ox2tgqM/2fBoAIDjSzIAYODvtPyn6ufqHem2dKGeH1/l56fxXAvYb7m6w8bCvoapkfcj0NiMt5Zfl9cp259k6l5GUJRxnRzLUyxytzxv8srxe/UO9QTuUxneT/R6bsQKTYMGX8QB3JN5cuVdZ7tyAVEAj5emX5fUht+303dbPLJ3o3WuORvTMjPV6qCyqDriT397dqpof/zrgmgi1v2h1+e6osqg6qm2sz1pVlazX3JxC/aPjb2NuY/wWrOfIWt+qkvW2Z352nVgXUYAVj99GPNzr64hq1NPw5sq9SfVuKgCYaIzMADG42HbGFtA4Z7j6a/MRc3IAY5ahP135vW3CgOa7V2wzWZ28ekiVRdVBZ48yfHZ5r7ZXH7Qde6yRjNZ7f9fqkrqADm24skTis8t7zReHSqOd5GDPdDR1NEZc3l0n1gW8hHQiZ2kKdp6sbnY1m7NdGXfnm+9e0fzcooj2Xzy7TNnuPFt9jJm93v/yNe2rPR7yOvrwq7dsbWF9DiUUI/3N2KbTdzsgkPpHx9/0asXWsOlKkVyPwXzSuCPgGpXGHoVqvntFNT/+tV6t2CopshEU47dgTdVr724163uh7bR+UvTzgHJYR9mCicdvIx4+u7zXDEysxpoZDgCmI1dj60N/bFvGuSRxFn3x4l+hzIetGpwV+V1cv/x6NvxEOb3t+vPtPXEvDwA4p49ONOd03/HinIrc+G51SV3SpTJi+nq98AM9mbVAmRlZSnPNkMtFwozThHc3k7w/G07qFT/OJXaRZgYA00r1j34VMtVvKpmVNS/guZtZWfPCzggHAEgtpJkBwDQS6t0yU40zDdLAqAwATC0EMwAwjVjTrpLBRJaHd7AAwNRHmhkAAACAlEQwAwAAACAlEcwAAAAASEkEMwAAAABSEsEMAAAAgJTEbGYA4qqqZL35JnerZHlJYyx2rzkqaerNjrW9+qDm5LyUdDOcGXavOaq5OYVMpwwACIlgBsCE+PTCO7rZ1ZzQMhzYeDbqIGr3mqO619cR9zfST7YNFdtUWVQd90BlstrH+X4YAACCIZgBgDCm2oiM4ZPGHYkuQlC71xxVp++2Wu/9XatL6hJdHABAEiOYAZBw26sPamHBUtt37d2tEXW231y5V+ULVpifT109LElmqturFVv1asVWXWw7o5NXD0my3/W3Hsf4fm5OoQ5sPGsu2159UFnuXFtQs6/2uLLdeWHL6ky7s44UOZf1D/XaRlKMUZD5uUWam1MoSWq+e8U2KmKkYhl2nVhna0+jTsFStd5cuVfFs8vMY4Y7Xqj2CSZUGzvPl5VRRqOdN1RsC7oeAAAGghkAE+Ltqo/Mvzt9t0OObmyo2KaFBUvNjqwROEQSyCyeU67yBSuCprRdaDsdNM3swMaz5rEWzynX21UfaUPFNp28eki7TqyLKI1qX+1xdfnu6P3G50FAVcn6gHQ2I1gxyrB4Trl+s+J3utB2OmCZsZ99tcdtAU35ghW62HZGH371lrmNcawNFduU5c4NCFQ+adwRc5rZWMeLtH3GauNUT98DACQXZjMDMCE+vfCOdp1Yp10n1o2ZpvXDWS+rvbvV/Pyvh98qy50b1bEqCqsiXtfa8b/Z1az+oV7NypoX8fZVJeuV7c7TX5uPmN99+NVbQZ/L+UnRz9Xpu20uu9nVbAYXPyupU3t3q227/247o2x3nhbPKTe/a+9uNUeUjHVnW0ZinOuPV7jjRWK8bQwAQKQYmQGQUH2Dj1Q8u8z8vHT+KxoY6oto25tdzfr0wjt6u+ojrS6pG3MEyLChYltcnsOIdHKDserSN/jI9vnfPW2SpB/kl4Tcf/9Qr/m3EXQYo2DOFLR4sB4vUmO1cSRpZgAARIpgBkDCZbvzzGcsnM+NhHOzq9nsBO+rPa7t1QfHfH5ldUmdLS1tX+3xmMq8eE55RAHNWKNMuZkv2j7/IL9E0vOgJhInrx7SyauHAtK5EiVcG5NmBgCIJ9LMAEyqDRXbdGDjWVWVrJckzc8t0sW2M2ZKmjOQeXPlXh3YeDaiVKqBob6A0Q5ripQzXcpIGXNyBhlWF9pOq3+oV78srze/21590KyP1T86/qa5OYW2ZUbHvvXe37WwYKlt2c++H12KZUprY5sHvtvmd8HqFg9jtU+kbTwe0VwTAICpjZEZABPCOgGAJNtsYlb/2fSxmSZmiHR0xpnO1Om7bbvz33z3ilaX1Gl1SZ15/B/OetksW6fvtjotnX9p9LmVVyu2jjlb1/tfvqYDG8+ao0nOZ18MF9pOa3ZOoTmjmvR8trWTVw9pVtY827JI0uSsnLPANd+9Ypbj5NVDqiyqHnM2s1iEa59I2jgc5wxtRh2S4d1FAIDk4mpsfeiPbcs4lyTOoi9e/CuU+bBVg7OWhl/xe3759Wz4iXJ62/Xn23viXh4gGe2rPa6mjkZboLOv9rhuPWghJQnAlPZ64Qd6MmuBMjOylOaaIZeLhBmnCe9uJnl/NpzUK36cS+wizQxAgmW782ypUcZ3DwfuJ6hEAAAgVZBmBiChTl09bEu1kkbTpRL5EDsAAEgNBDMAEupC2+mgz5sAAACEQ5oZAAAAgJREMAMAAAAgJRHMAAAAAEhJBDMAAAAAUhLBDAAAAICURDADAAAAICURzAAAAABISQQzAAAAAFISwQwAAACAlJSR6ALAzv/9/75e+EFCywEAACae3+8PvxKAkAhmkoh/5Pnff/wmN3EFAQAAE+63y/vkl0t+vyRXoksDpCbSzJLKiPwjnBIAAKaLEf8M+V1p8ruIZoBY0HNOKmlyudITXQgAADBpMuTyp8lFthkQE4KZJOJyubgzAwDAtJImcsyA2BHMJBkX/6ABADBtuFx0xYDx4BcEAAAAICURzAAAAABISQQzAAAAAFISwQwAAACAlEQwAwAAACAlEcwAAAAASEkEMwAAAABSEsEMAAAAgJREMAMAAAAgJWUkugAAEE87a4pUuTA35PI/fPmdrnsHJrwcW1Z5VFNWYH4+39KtY5e8E35cAACmE4IZAFPKx+c7zL+NgGLzkZa4HqOhvkyfX/bq3LXuoMvXLitQTVmBbZ2G+rKUD2b21BVLkj44cyvBJQEAYBRpZgAQZ/Pz3ZJkC3biHVABAABGZgBMU850NOcoSlN7nznKs6euWDmZ6fq/Ld16Y6VHkvTGSo/eWOkJmj52r2fIPIZ1pCjS40vS/k2l8nwfFBmMMu3fVKo7jwb10ouZ5jrnW7p1r2fILJ9vcFhbG67btt9TV6zSeTPNz9aUO2PURZK5zo37j81RmMOblygnM91sH2/PkN794kbQugEAMFkIZgBMO0YgYYyWrF1WoDdWevTdgye67h3Q+ZZu1ZQVaIknSz9dnKfSeTPNdc9d6w6bZnbuWrfKXspW5cJcNdSXBQQ84Y6/s6ZIOS+km8v3byqVb3DYFhhVLszV+ZZuvfuFVztrilRTViDf4LC5zeHNS7SnrtgMRvbUFcuT7zaXb1nl0Xu1i2wjRqXzZqqpvU+bj7RoiSdL79Uu0pZVHh275NXWhuukmQEAkg5pZgCmnZc9WTrf8jwQOXetW77BYf3H8tmSpGOXvLpx/7F2fB8kWNeN1MfnO7T5SItu3H+smrICNdSXRXz8l17M1LeWSQruPBo0R0UMN+4/NgOk//rmgSTpoCXY+dY7YNumdN5MnWrqND8b225Z5TG/8/YMmQHTde+AfIPDmp09I+q6AwAwWRiZATDt5GSmq6aswDbbmNMHZ26pob5MvsHhcT24b4xiNNSXmWln4Y7vGxzWSy9mmp9f9mTJ+33qWiyWeLIkPU+Ni5TvyXDMxwQAYDIQzACYdnyDw7rc1jNmkLJ/U6lu3H+s0nkzx3z2JZpjRnN8T77bHM3x9gyNK7XLeC5mrNQ4AABSEWlmAKYdb8+QVpbkh1y+ZZVHnny3PjhzS+dbulW5MNcc3TDMdzycb7WnrtiWvrV2WYFyMtPVcqcBHHLWAAALa0lEQVQ/ouN78t36/LJXm4+0aPORlrg8aO/tGdIvxhiJipQz3Q0AgERiZAbAtPPBmVvaU1dse45FGp3dS5LtOZljl7xaXpijHTVF5uxgTe19ZppYsNnMjBQ1axqZdVRkrONf9w7oVFNnQErYeGcPe/eLG9q/qTTgmNFMGf3n/7mn92oXMZsZACBpuBpbH/pj2zLOJYmz6IsX/wplPmzV4KylEa/v90tPR0aU2/ut/vhN6DeYA5jags2WFmxWNACp7bfL+9T/4suamZGm9DSXXK4k71wlwIS3SIo3eeoVP84ldpFmBgBJxUhn++7Bk4Dv7o1jEgAAAKYi0swAIIkY77l5r3aR7fvzLd08vA8AgAPBDAAkmWOXvKSTAQAQAdLMAAAAAKQkghkAAAAAKYlgBgAAAEBKIpgBAAAAkJIIZgAAAACkJIIZIAEOb16inTVFiS5G0lriyVJDfZnWLisIuc7OmiId3rxkEkuF8WioL1NDfZn2byqNaP1IroGpYO2yAjXUl5nvEgIARIepmYE427+pVJ58d9BlvsFhbW24PsklgtMST5beq12k8y3dKT8FcirUZU9dsbw9Q3r3ixsJLceWVR7VlAUGR3/48jtd9w6YyzcfaQlYZ2dNkSoX5tq+C/V7XrusQG+s9AQ9jqSkP18AkEoIZoA4s3bY9tQVKyczPeGduEQyOttGh3EqOrx5iS639Ux45zRV2zInM113Hg2GXG50/oMFERMh1uNEezMi2HliBAYA4otgBsC0c907MGkd54mWCnXJeSE90UVIGqlwvgAglRDMAAlkTUlzpp0Yd+ENN+4/1gdnboXclzO1pam9Tx+f7zCPIz0fNQqWTtNQX2b+HSwlyLrc2LdRxs8ve3XuWretHJuPtNjSeoy6WNe17jNY/ebnu23rWLcNZk9dsUrnzTQ/jzWC0VBfZra5UebPL3ttbWhtn2Dt+1/fPDDrVVNWoJqyArNt9m8q1Z1Hg3rZk6WczHTzWNbjSsFHW5zpUH/48jv9dHFeyLYMtU8ra1321BWbfxvt5Wz/aNrSmVpplMVajsqFuWqoLws4h9b0LeNcG+lYBus14CyHs61SIX3Leb6cUrFOAJAoBDNAglQuzDU7dkbn5eubvbruHQj6HIQxaYARoFhZO+PWQGHLKo+OXfLqyMU7eq92kbas8ujrm72qKSvQ55efd44a6ssCgp89dcVm59a5/PDmJRGlyxy75NXXN3uDpkY11JeZHWyjvkZ5DdaAa2dNkd5Y6dF3D54E7VTvqSuWJ99trr9llUfv1S6K6i74q5VzzfX3byrV/k2lZlD3auXcoJ3KzUdaQqaZVS7MjbojalwLRnutXVag+tUv6d0vboRsS6tg186eumJbe0ujQUxTe582H2kJaP+1ywpUOm9mRG1nBMrGutag79glr9k+33oHgl67H5/vCJpmZlxf1u/31BVrR02RmerlbCujHvd6hsYMesMF0YkUa50AYLpiNjMgQZra+8zOydc3eyVJi2a/IEn6j+Wz5e0ZsnWCv/UO6OUQAcSKknzduP/Y1tm5cf+xlhfmSBpNbTnf0q2asgLtqCmyrbtllUe+wWFbR/Ob2z7zrvyWVaMdU+vyrQ3Xx/3MhrXjet07IN/gsGZnz7CtYw24jOP/dHFe0P2VzpupU02d5mej7YzyR+KgpY53Hg0GpEcVz5np3GRMN+4/jvqO+vLCHN24/9hs33PXuqN65ur1/zU/4Nr58//ckyTbzGDeniGzTUO1f7iZxNYuK5An360jF++Y35271i1vz1DUbRWK9Rq41fVYOZnPz8nywhw1tfeZbXXdOyBvz5BWlOSPuc/NR1rM/0QTyORkppuzsjXUl9lGuIJ5r3aRuW6kM+/FWicAmK4YmQGSgDMwyJuZIY8jxUoafQA5mJzM9KDre3uGzL+PXfJqeWGOPPlus3MrSbOzZ5idtFBCHXc8Qs0sNZZQ5bDexQ82i1QsHvQ/tX3e2nBdhzcvMdtpIp976H38bFzbO9vJuL7mh5hlT5J8T55vYwS6RnuGG71wXr++wWFb0BEv9yzXszT6LI6RvmZ14/7juB9bis8EAOFMdp0AINURzABJqPfxs6imsvUNDoftcO6sKVLOC+ny9gyZaUvSaKc9XCctVMc01tGZtcsKbKk0kiK6cx2uHOGeqRkvo4321BXr8OYlMU2zHUlgmDdzfP80O9vJCPacwcBYzl3rtqUshkpxNPZvvRZyMtMnJAB28j0ZDpm+lqqmYp0AYCKRZgYkoZY7/fLkuyN+YeCtrscqnTcz5HMsSzxZqlyYq1NNnTpy8Y48+W4z/errm73KyUwPmY5lpCtZX/K5f1OpeSzf4LAtBSbUyIiRQicFjhCsXVYQNFCx7ss4fqi0LW/PkH4R5UhPrHofP7ONZEgKSNEKxfdk2Ez/k6QdjpenGil+Rvsu8WQFvGjS2pZOV9p6bOdXGk098w0Oxxzo+QaHA0aqpNGAxzc4rPrVL5nfGalnV9p6oj5OtNMW33k0GPDul1QXrk7GSzajSZ8EgKmMkRkgCTnTfAzWh/CtjA6+cwYr4yFw53MyTe19tgkH/vDld3qvdpEt7cs60mMsN1JfrDn9p5o69cZKj7nMOSPYde+Abtx/bNbl88teHbvkVfGcmWZ5vT1DtpQ4a/mdM1mF8u4XN7R/U2lAek480sHCzQ52ua1HNWUFARMlBGNMxhCqvY5d8mp29gzb8Yx6B2tLZ4By7lq35ue7zdnVpOjTo5wviBzr2Z+tDdfN50IM0Y6QnbvWrV+UFZh1Hus8W318vkM7a4oCznm444db37p8sl90G2udAGC6cjW2PvTHtmWcSxJn0Rcv/hVy99zQ09xF8qdFFjP6/dLTkRHl9n6rP34zte42AgAAu98u71P/iy9rZkaa0tNccrmSvHOVABPeIine5KlX/DiX2EWa2YTyuzLkGglMzQAAAAAwfgQzEyktQyKYAQAAACYEwcwEGpmRrfRn/YkuBgAAADAlEcxMoJGMbLmGCGYAAACAiUAwM4H86W4pLV1pz8b3pnQAAAAAgQhmJtizzAKlP+5KdDEAAACAKYdgZoKNZObJ5X+mtKe+RBcFAAAAmFIIZiacS8+yPMoY8Mrlf5bowgAAAABTBsHMJBjJyNJw5ixl9N+VFNs7SgEAAADYEcxMkuEXZktK0wzfvyX/SKKLAwAAAKQ8gplJ9DSnUP40t2b4OuQaHkx0cQAAAICURjAzyZ5lzdeIO08z+v6ljMedcjFKAwAAAMQkI9EFmI6GM2dpxJ2njMedmtFzQ/6MLA27c+VPnymX35Xo4gEAAAApgWAmQfyudD3N8kgz5yntaZ/Sh3zSyCPNGHma6KIBAAAAKYFgJtFcaRpx52vEnS+/X3o6MqLc3m8TXSoAAAAg6RHMJKnfLu9LdBEAAACApEYwk2RcculB9o80+GxEwyN+uXiERtOtCaZbfa1c0+yCT7raJl2Bpq6omzrlzk10BU656jnFUAGXX8pIl15wuabdv31APBHMJBW/XJLSXNKMdJfS04K/YnO6/ZM34fVNsgZNsuJMKtc0q33S1XaSC5R09U9mKddYBDNj8ktpaVKaK03paa7R7QlogJgQzCQVl9LS/HKnpSvD75d/JFgoMwX+0Y8Swcz0Md3uTiZdbQlmJg0jM+NZOwnFUgGXlOZyKc3lV1qMuwBAMJNURvtxLqVLSne55A/xFqDp9g8ewcz0QTCTYAQzk4ZgZjxrJ6FY0szk0mj+BWlmwHgQzCQZl/lfoVNupts/eQQz08d0+z/0pKstwcykIZgZz9pJKOYKpHzNgYQLce8fAAAAAJIbwQwAAACAlEQwAwAAACAlEcwAAAAASEkEMwAAAABSEsEMAAAAgJREMAMAAAAgJRHMAAAAAEhJ/x/5KT629JQiqgAAAABJRU5ErkJggg==