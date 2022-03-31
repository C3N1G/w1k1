> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [wiki.xazlsec.com](https://wiki.xazlsec.com/project-15/doc-246/)

> 我们从隔离、访问控制、异常检测、随机化这四种方式来介绍内核中的防御机制。 ## 参考 - https://linuxplumbersconf.org/event/7/contributions/7

我们从隔离、访问控制、异常检测、随机化这四种方式来介绍内核中的防御机制。

参考
--

*   [https://linuxplumbersconf.org/event/7/contributions/775/attachments/610/1096/Following_the_Linux_Kernel_Defence_Map.pdf](https://linuxplumbersconf.org/event/7/contributions/775/attachments/610/1096/Following_the_Linux_Kernel_Defence_Map.pdf)
    
*   [https://github.com/a13xp0p0v/linux-kernel-defence-map](https://github.com/a13xp0p0v/linux-kernel-defence-map)
    
*   [https://outflux.net/slides/2018/lca/kspp.pdf](https://outflux.net/slides/2018/lca/kspp.pdf)
    
*   [https://www.kernel.org/doc/html/latest/security/self-protection.html](https://www.kernel.org/doc/html/latest/security/self-protection.html)
    
*   [https://powerofcommunity.net/poc2019/x82.pdf](https://powerofcommunity.net/poc2019/x82.pdf)
    
*   [https://samsung.github.io/kspp-study/infoleak.html](https://samsung.github.io/kspp-study/infoleak.html)
    

访问控制是指内核通过对某些对象添加访问控制，使得内核中相应的对象具有一定的访问控制要求，比如不可写，或者不可读。

信息泄露
----

### dmesg_restrict

考虑到内核日志中可能会有一些地址信息或者敏感信息，研究者提出需要对内核日志的访问进行限制。

该选项用于控制是否可以使用 `dmesg` 来查看内核日志。当 `dmesg_restrict` 为 0 时，没有任何限制；当该选项为 1 时，只有具有 `CAP_SYSLOG` 权限的用户才可以通过 `dmesg` 命令来查看内核日志。

```
dmesg_restrict:
This toggle indicates whether unprivileged users are prevented
from using dmesg(8) to view messages from the kernel's log buffer.
When dmesg_restrict is set to (0) there are no restrictions. When
dmesg_restrict is set set to (1), users must have CAP_SYSLOG to use
dmesg(8).
The kernel config option CONFIG_SECURITY_DMESG_RESTRICT sets the
default value of dmesg_restrict.

```

### kptr_restrict

该选项用于控制在输出内核地址时施加的限制，主要限制以下接口

*   通过 /proc 获取的内核地址
*   通过其它接口（有待研究）获取的地址

具体输出的内容与该选项配置的值有关

*   0：默认情况下，没有任何限制。
*   1：使用 `％pK` 输出的内核指针地址将被替换为 0，除非用户具有 CAP_ SYSLOG 特权，并且 group id 和真正的 id 相等。
*   2：使用 `％pK` 输出的内核指针都将被替换为 0 ，即与权限无关。

```
kptr_restrict:
This toggle indicates whether restrictions are placed on
exposing kernel addresses via /proc and other interfaces.
When kptr_restrict is set to 0 (the default) the address is hashed before
printing. (This is the equivalent to %p.)
When kptr_restrict is set to (1), kernel pointers printed using the %pK
format specifier will be replaced with 0's unless the user has CAP_SYSLOG
and effective user and group ids are equal to the real ids. This is
because %pK checks are done at read() time rather than open() time, so
if permissions are elevated between the open() and the read() (e.g via
a setuid binary) then %pK will not leak kernel pointers to unprivileged
users. Note, this is a temporary solution only. The correct long-term
solution is to do the permission checks at open() time. Consider removing
world read permissions from files that use %pK, and using dmesg_restrict
to protect against uses of %pK in dmesg(8) if leaking kernel pointer
values to unprivileged users is a concern.
When kptr_restrict is set to (2), kernel pointers printed using
%pK will be replaced with 0's regardless of privileges.

```

当开启该保护后，攻击者就不能通过 `/proc/kallsyms` 来获取内核中某些敏感的地址了，如 commit_creds、prepare_kernel_cred。

### 参考

*   [https://blog.csdn.net/gatieme/article/details/78311841](https://blog.csdn.net/gatieme/article/details/78311841)

### __ro_after_init

Linux 内核中有很多数据都只会在 `__init` 阶段被初始化，而且之后不会被改变。使用 `__ro_after_init` 标记的内存，在 init 阶段结束后，不能够被再次修改。

#### 攻击

我们可以使用 `set_memory_rw(unsigned long addr, int numpages)` 来修改对应页的权限。

### mmap_min_addr

mmap_min_addr 是用来对抗 NULL Pointer Dereference 的，指定用户进程通过 mmap 可以使用的最低的虚拟内存地址。

### 参考

*   [https://lwn.net/Articles/676145/](https://lwn.net/Articles/676145/)
*   [https://lwn.net/Articles/666550/](https://lwn.net/Articles/666550/)
*   [https://lore.kernel.org/patchwork/patch/621386/](https://lore.kernel.org/patchwork/patch/621386/)

通过对内核中发生的异常行为进行检测，我们可以缓解一定的攻击。

Canary 是一种典型的检测机制。在 Linux 内核中，Canary 的实现是与架构相关的，所以这里我们分别从不同的架构来介绍。

x86
---

### 介绍

在 x86 架构中，同一个 task 中使用相同的 Canary。

### 发展历史

TODO。

### 实现

TODO。

### 使用

#### 开启

在编译内核时，我们可以设置 CONFIG_CC_STACKPROTECTOR 选项，来开启该保护。

#### 关闭

我们需要重新编译内核，并关闭编译选项才可以关闭 Canary 保护。

### 状态检查

我们可以使用如下方式来检查是否开启了 Canary 保护

1.  `checksec`
2.  人工分析二进制文件，看函数中是否有保存和检查 Canary 的代码

### 特点

可以发现，x86 架构下 Canary 实现的特点是同一个 task 共享 Canary。

### 攻击

根据 x86 架构下 Canary 实现的特点，我们只要泄漏了一次系统调用中的 Canary，同一 task 的其它系统调用中的 Canary 也就都被泄漏了。

参考
--

*   [https://www.workofard.com/2018/01/per-task-stack-canaries-for-arm64/](https://www.workofard.com/2018/01/per-task-stack-canaries-for-arm64/)
*   [PESC: A Per System-Call Stack Canary Design for Linux Kernel](https://yajin.org/papers/pesc.pdf)

在内核的防御机制中，根据隔离的主体，我们将隔离分为两种

*   内核态和用户态的隔离
*   内核自身内部不同对象间的隔离

内核态隔离
-----

### 堆块隔离

#### SLAB_ACCOUNT

根据描述，如果在使用 `kmem_cache_create` 创建一个 cache 时，传递了 `SLAB_ACCOUNT` 标记，那么这个 cache 就会单独存在，不会与其它相同大小的 cache 合并。

```
Currently, if we want to account all objects of a particular kmem cache,
we have to pass __GFP_ACCOUNT to each kmem_cache_alloc call, which is
inconvenient. This patch introduces SLAB_ACCOUNT flag which if passed to
kmem_cache_create will force accounting for every allocation from this
cache even if __GFP_ACCOUNT is not passed.
This patch does not make any of the existing caches use this flag - it
will be done later in the series.
Note, a cache with SLAB_ACCOUNT cannot be merged with a cache w/o
SLAB_ACCOUNT, i.e. using this flag will probably reduce the number of
merged slabs even if kmem accounting is not used (only compiled in).

```

在早期，许多结构体（如 **cred 结构体**）对应的堆块并不单独存在，会和相同大小的堆块使用相同的 cache。在 Linux 4.5 版本引入了这个 flag 后，许多结构体就单独使用了自己的 cache。然而，根据上面的描述，这一特性似乎最初并不是为了安全性引入的。

```
Mark those kmem allocations that are known to be easily triggered from
userspace as __GFP_ACCOUNT/SLAB_ACCOUNT, which makes them accounted to
memcg.  For the list, see below:
 - threadinfo
 - task_struct
 - task_delay_info
 - pid
 - cred
 - mm_struct
 - vm_area_struct and vm_region (nommu)
 - anon_vma and anon_vma_chain
 - signal_struct
 - sighand_struct
 - fs_struct
 - files_struct
 - fdtable and fdtable->full_fds_bits
 - dentry and external_name
 - inode for all filesystems. This is the most tedious part, because
   most filesystems overwrite the alloc_inode method.
The list is far from complete, so feel free to add more objects.
Nevertheless, it should be close to "account everything" approach and
keep most workloads within bounds.  Malevolent users will be able to
breach the limit, but this was possible even with the former "account
everything" approach (simply because it did not account everything in
fact).

```

### 参考

*   [https://lore.kernel.org/patchwork/patch/616610/](https://lore.kernel.org/patchwork/patch/616610/)
*   [https://github.com/torvalds/linux/commit/5d097056c9a017a3b720849efb5432f37acabbac#diff-3cb5667a88a24e8d5abc7042f5c4193698d6b962157f637f9729e61198eec63a](https://github.com/torvalds/linux/commit/5d097056c9a017a3b720849efb5432f37acabbac#diff-3cb5667a88a24e8d5abc7042f5c4193698d6b962157f637f9729e61198eec63a)
*   [https://github.com/torvalds/linux/commit/230e9fc2860450fbb1f33bdcf9093d92d7d91f5b#diff-cc9aa90e094e6e0f47bd7300db4f33cf4366b98b55d8753744f31eb69c691016](https://github.com/torvalds/linux/commit/230e9fc2860450fbb1f33bdcf9093d92d7d91f5b#diff-cc9aa90e094e6e0f47bd7300db4f33cf4366b98b55d8753744f31eb69c691016)

用户态隔离
-----

这里主要有

*   默认：用户态不可直接访问内核态的数据、执行内核态的代码
*   SMEP：内核态不可执行用户态的代码
*   SMAP：内核态不可访问用户态的数据
*   KPTI：用户态不可看到内核态的页表；内核态不可执行用户态的代码（模拟）

### KPTI - Kernel Page Table Isolation

KPTI 机制最初的主要目的是为了缓解 KASLR 的绕过以及 CPU 侧信道攻击。

在 KPTI 机制中，内核态空间的内存和用户态空间的内存的隔离进一步得到了增强。

*   内核态中的页表包括用户空间内存的页表和内核空间内存的页表。
*   用户态的页表只包括用户空间内存的页表以及必要的内核空间内存的页表，如用于处理系统调用、中断等信息的内存。

![][img-0]

在 x86_64 的 PTI 机制中，内核态的用户空间内存映射部分被全部标记为不可执行。也就是说，之前不具有 SMEP 特性的硬件，如果开启了 KPTI 保护，也具有了类似于 SMEP 的特性。此外，SMAP 模拟也可以以类似的方式引入，只是现在还没有引入。因此，在目前开启了 KPTI 保护的内核中，如果没有开启 SMAP 保护，那么内核仍然可以访问用户态空间的内存，只是不能跳转到用户态空间执行 Shellcode。

Linux 4.15 中引入了 KPTI 机制，并且该机制被反向移植到了 Linux 4.14.11，4.9.75，4.4.110。

### 发展历史

TODO。

### 实现

TODO。

### 开启与关闭

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `kpti=1` 来开启 KPTI。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `nopti` 来关闭 KPTI。

### 状态查看

我们可以通过以下两种方式来查看 KPTI 机制是否开启。

```
/home/pwn # dmesg | grep 'page table'
[    0.000000] Kernel/User page tables isolation: enabled
/home/pwn # cat /proc/cpuinfo | grep pti
fpu_exception   : yes
flags           : ... pti smep smap

```

### Attack KPTI

KPTI 机制和 SMAP 、SMEP 不太一样，由于与源码紧密结合，似乎没有办法在运行时刻关闭。

#### 修改页表

在开启 KPTI 后，用户态空间的所有数据都被标记了 NX 权限，但是，我们可以考虑修改对应的页表权限，使其拥有可执行权限。当内核没有开启 smep 权限时，我们在修改了页表权限后就可以返回到用户态，并执行用户态的代码。

#### SWITCH_TO_USER_CR3_STACK

在开启 KPTI 机制后，用户态进入到内核态时，会进行页表切换；当从内核态恢复到用户态时，也会进行页表切换。那么如果我们可以控制内核执行返回用户态时所执行的切换页表的代码片段，也就可以正常地返回到用户态。

通过分析内核态到用户态切换的代码，我们可以得知，页表的切换主要靠`SWITCH_TO_USER_CR3_STACK` 汇编宏。因此，我们只需要能够调用这部分代码即可。

```
.macro SWITCH_TO_USER_CR3_STACK    scratch_reg:req
    pushq    %rax
    SWITCH_TO_USER_CR3_NOSTACK scratch_reg=\scratch_reg scratch_reg2=%rax
    popq    %rax
.endm
.macro SWITCH_TO_USER_CR3_NOSTACK scratch_reg:req scratch_reg2:req
    ALTERNATIVE "jmp .Lend_\@", "", X86_FEATURE_PTI
    mov    %cr3, \scratch_reg
    ALTERNATIVE "jmp .Lwrcr3_\@", "", X86_FEATURE_PCID
    /*
     * Test if the ASID needs a flush.
     */
    movq    \scratch_reg, \scratch_reg2
    andq    $(0x7FF), \scratch_reg        /* mask ASID */
    bt    \scratch_reg, THIS_CPU_user_pcid_flush_mask
    jnc    .Lnoflush_\@
    /* Flush needed, clear the bit */
    btr    \scratch_reg, THIS_CPU_user_pcid_flush_mask
    movq    \scratch_reg2, \scratch_reg
    jmp    .Lwrcr3_pcid_\@
.Lnoflush_\@:
    movq    \scratch_reg2, \scratch_reg
    SET_NOFLUSH_BIT \scratch_reg
.Lwrcr3_pcid_\@:
    /* Flip the ASID to the user version */
    orq    $(PTI_USER_PCID_MASK), \scratch_reg
.Lwrcr3_\@:
    /* Flip the PGD to the user version */
    orq     $(PTI_USER_PGTABLE_MASK), \scratch_reg
    mov    \scratch_reg, %cr3
.Lend_\@:
.endm

```

事实上，我们不仅希望切换页表，还希望能够返回到用户态，因此我们这里也需要复用内核中返回至用户态的代码。内核返回到用户态主要有两种方式：iret 和 sysret。下面详细介绍。

##### iret

```
SYM_INNER_LABEL(swapgs_restore_regs_and_return_to_usermode, SYM_L_GLOBAL)
#ifdef CONFIG_DEBUG_ENTRY
    /* Assert that pt_regs indicates user mode. */
    testb    $3, CS(%rsp)
    jnz    1f
    ud2
1:
#endif
    POP_REGS pop_rdi=0
    /*
     * The stack is now user RDI, orig_ax, RIP, CS, EFLAGS, RSP, SS.
     * Save old stack pointer and switch to trampoline stack.
     */
    movq    %rsp, %rdi
    movq    PER_CPU_VAR(cpu_tss_rw + TSS_sp0), %rsp
    UNWIND_HINT_EMPTY
    /* Copy the IRET frame to the trampoline stack. */
    pushq    6*8(%rdi)    /* SS */
    pushq    5*8(%rdi)    /* RSP */
    pushq    4*8(%rdi)    /* EFLAGS */
    pushq    3*8(%rdi)    /* CS */
    pushq    2*8(%rdi)    /* RIP */
    /* Push user RDI on the trampoline stack. */
    pushq    (%rdi)
    /*
     * We are on the trampoline stack.  All regs except RDI are live.
     * We can do future final exit work right here.
     */
    STACKLEAK_ERASE_NOCLOBBER
    SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi
    /* Restore RDI. */
    popq    %rdi
    SWAPGS
    INTERRUPT_RETURN

```

可以看到，通过伪造如下的栈，然后跳转到 `movq %rsp, %rdi`，我们就可以同时切换页表和返回至用户态。

```
fake rax
fake rdi
RIP
CS
EFLAGS
RSP
SS

```

##### sysret

在使用 sysret 时，我们首先需要确保 rcx 和 r11 为如下的取值

```
rcx, save the rip of the code to be executed when returning to userspace
r11, save eflags

```

然后构造如下的栈

```
fake rdi
rsp, the stack of the userspace

```

最后跳转至 entry_SYSCALL_64 的如下代码，即可返回到用户态。

```
    SWITCH_TO_USER_CR3_STACK scratch_reg=%rdi
    popq    %rdi
    popq    %rsp
    swapgs
    sysretq

```

#### signal handler

我们也可以考虑在用户态注册 signal handler 来执行位于用户态的代码。在这种方式下，我们无需切换页表。

### 参考

*   [https://github.com/pr0cf5/kernel-exploit-practice/tree/master/bypass-smep#bypassing-smepkpti-via-rop](https://github.com/pr0cf5/kernel-exploit-practice/tree/master/bypass-smep#bypassing-smepkpti-via-rop)
*   [https://outflux.net/blog/archives/2018/02/05/security-things-in-linux-v4-15/](https://outflux.net/blog/archives/2018/02/05/security-things-in-linux-v4-15/)

### 用户代码不可执行

起初，在内核态执行代码时，可以直接执行用户态的代码。那如果攻击者控制了内核中的执行流，就可以执行处于用户态的代码。由于用户态的代码是攻击者可控的，所以更容易实施攻击。为了防范这种攻击，研究者提出当位于内核态时，不能执行用户态的代码。在 Linux 内核中，这个防御措施的实现是与指令集架构相关的。

#### x86 - SMEP - Supervisor Mode Execution Protection

x86 下对应的保护机制的名字为 SMEP。CR4 寄存器中的第 20 位用来标记是否开启 SMEP 保护。

![][img-1]

##### 发展历史

TODO。

##### 实现

TODO。

##### 开启与关闭

###### 开启

默认情况下，SMEP 保护是开启的。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `+smep` 来开启 SMEP。

###### 关闭

在 `/etc/default/grub` 的如下两行中添加 nosmep

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet"  
GRUB_CMDLINE_LINUX="initrd=/install/initrd.gz"

```

然后运行 `update-grub` 并且重启系统就可以关闭 smep。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `nosmep` 来关闭 SMEP。

##### 状态查看

通过如下命令可以检查 SMEP 是否开启，如果发现了 smep 字符串就说明开启了 smep 保护，否则没有开启。

```
grep smep /proc/cpuinfo
```

##### Attack SMEP

把 CR4 寄存器中的第 20 位置为 0 后，我们就可以执行用户态的代码。一般而言，我们会使用 0x6f0 来设置 CR4，这样 SMAP 和 SMEP 都会被关闭。

内核中修改 cr4 的代码最终会调用到 `native_write_cr4`，当我们能够劫持控制流后，我们可以执行内核中的 gadget 来修改 CR4。从另外一个维度来看，内核中存在固定的修改 cr4 的代码，比如在 `refresh_pce` 函数、 `set_tsc_mode` 等函数里都有。

#### ARM - PXN

TODO。

### 参考

*   [https://duasynt.com/slides/smep_bypass.pdf](https://duasynt.com/slides/smep_bypass.pdf)
*   [https://github.com/torvalds/linux/commit/15385dfe7e0fa6866b204dd0d14aec2cc48fc0a7](https://github.com/torvalds/linux/commit/15385dfe7e0fa6866b204dd0d14aec2cc48fc0a7)

### 用户数据不可访问

如果内核态可以访问用户态的数据，也会出现问题。比如在劫持控制流后，攻击者可以通过栈迁移将栈迁移到用户态，然后进行 ROP，进一步达到提权的目的。在 Linux 内核中，这个防御措施的实现是与指令集架构相关的。

#### x86 - SMAP - Supervisor Mode Access Protection

##### 介绍

x86 下对应的保护机制的名字为 SMAP。CR4 寄存器中的第 21 位用来标记是否开启 SMEP 保护。

![][img-2]

##### 发展历史

TODO。

##### 实现

TODO。

##### 开启与关闭

###### 开启

默认情况下，SMAP 保护是开启的。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `+smap` 来开启 SMAP。

###### 关闭

在 `/etc/default/grub` 的如下两行中添加 nosmap

```
GRUB_CMDLINE_LINUX_DEFAULT="quiet"  
GRUB_CMDLINE_LINUX="initrd=/install/initrd.gz"

```

然后运行 `update-grub` ，重启系统就可以关闭 smap。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `nosmap` 来关闭 SMAP。

##### 状态查看

通过如下命令可以检查 SMAP 是否开启，如果发现了 smap 字符串就说明开启了 smap 保护，否则没有开启。

```
grep smap /proc/cpuinfo
```

##### Attack SMEP

这里给出几种方式。

###### 设置 CR4 寄存器

把 CR4 寄存器中的第 21 位置为 0 后，我们就可以访问用户态的数据。一般而言，我们会使用 0x6f0 来设置 CR4，这样 SMAP 和 SMEP 都会被关闭。

内核中修改 cr4 的代码最终会调用到 `native_write_cr4`，当我们能够劫持控制流后，我们就可以执行内核中对应的 gadget 来修改 CR4。从另外一个维度来看，内核中存在固定的修改 cr4 的代码，比如在 `refresh_pce` 函数、 `set_tsc_mode` 等函数里都有。

###### copy_from/to_user

在劫持控制流后，攻击者可以调用 `copy_from_user` 和 `copy_to_user` 来访问用户态的内存。这两个函数会临时清空禁止访问用户态内存的标志。

#### ARM - PAN

TODO。

我们可以通过增加内核的随机性来提高安全性。

FGKASLR
-------

鉴于 KASLR 的不足，有研究者实现了 FGKASLR。FGKASLR 在 KASLR 基地址随机化的基础上，在加载时刻，以函数粒度重新排布内核代码。

### 实现

FGKASLR 的实现相对比较简单，主要在两个部分进行了修改。目前，FGKASLR 只支持 x86_64 架构。

#### 编译阶段

FGKASLR 利用 gcc 的编译选项 `-ffunction-sections` 把内核中不同的函数放到不同的 section 中。 在编译的过程中，任何使用 C 语言编写的函数以及不在特殊输入节的函数都会单独作为一个节；使用汇编编写的代码会位于一个统一的节中。

编译后的 vmlinux 保留了所有的节区头（Section Headers），以便于知道每个函数的地址范围。同时，FGKASLR 还有一个重定位地址的扩展表。通过这两组信息，内核在解压缩后就可以乱序排列函数。

最后的 binary 的第一个段包含了一个合并节（由若干个函数合并而成）、以及若干其它单独构成一个节的函数。

#### 加载阶段

在解压内核后，会首先检查保留的符号信息，然后寻找需要随机化的 `.text.*` 节区。其中，第一个合并的节区 (`.text`) 会被跳过，不会被随机化。后面节区的地址会被随机化，但仍然会与 `.text` 节区相邻。同时，FGKASLR 修改了已有的用于更新重定位地址的代码，不仅考虑了相对于加载地址的偏移，还考虑了函数节区要被移动到的位置。

为了隐藏新的内存布局，/proc/kallsyms 中符号使用随机的顺序来排列。在 v4 版本之前，该文件中的符号按照字母序排列。

通过分析代码，我们可以知道，在 `layout_randomized_image` 函数中计算了最终会随机化的节区，存储在 sections 里。

```
    /*
     * now we need to walk through the section headers and collect the
     * sizes of the .text sections to be randomized.
     */
    for (i = 0; i < shnum; i++) {
        s = &sechdrs[i];
        sname = secstrings + s->sh_name;
        if (s->sh_type == SHT_SYMTAB) {
            /* only one symtab per image */
            if (symtab)
                error("Unexpected duplicate symtab");
            symtab = malloc(s->sh_size);
            if (!symtab)
                error("Failed to allocate space for symtab");
            memcpy(symtab, output + s->sh_offset, s->sh_size);
            num_syms = s->sh_size / sizeof(*symtab);
            continue;
        }
        if (s->sh_type == SHT_STRTAB && i != ehdr->e_shstrndx) {
            if (strtab)
                error("Unexpected duplicate strtab");
            strtab = malloc(s->sh_size);
            if (!strtab)
                error("Failed to allocate space for strtab");
            memcpy(strtab, output + s->sh_offset, s->sh_size);
        }
        if (!strcmp(sname, ".text")) {
            if (text)
                error("Unexpected duplicate .text section");
            text = s;
            continue;
        }
        if (!strcmp(sname, ".data..percpu")) {
            /* get start addr for later */
            percpu = s;
            continue;
        }
        if (!(s->sh_flags & SHF_ALLOC) ||
            !(s->sh_flags & SHF_EXECINSTR) ||
            !(strstarts(sname, ".text")))
            continue;
        sections[num_sections] = s;
        num_sections++;
    }
    sections[num_sections] = NULL;
    sections_size = num_sections;

```

可以看到，只有同时满足以下条件的节区才会参与随机化

*   节区名以 .text 开头
*   section flags 中包含`SHF_ALLOC`
*   section flags 中包含`SHF_EXECINSTR`

因此，通过以下命令，我们可以知道

*   __ksymtab 不会参与随机化
*   .data 不会参与随机化

```
> readelf --section-headers -W vmlinux| grep -vE " .text|AX"
...
  [36106] .rodata           PROGBITS        ffffffff81c00000 e1e000 382241 00  WA  0   0 4096
  [36107] .pci_fixup        PROGBITS        ffffffff81f82250 11a0250 002ed0 00   A  0   0 16
  [36108] .tracedata        PROGBITS        ffffffff81f85120 11a3120 000078 00   A  0   0  1
  [36109] __ksymtab         PROGBITS        ffffffff81f85198 11a3198 00b424 00   A  0   0  4
  [36110] __ksymtab_gpl     PROGBITS        ffffffff81f905bc 11ae5bc 00dab8 00   A  0   0  4
  [36111] __ksymtab_strings PROGBITS        ffffffff81f9e074 11bc074 027a82 01 AMS  0   0  1
  [36112] __init_rodata     PROGBITS        ffffffff81fc5b00 11e3b00 000230 00   A  0   0 32
  [36113] __param           PROGBITS        ffffffff81fc5d30 11e3d30 002990 00   A  0   0  8
  [36114] __modver          PROGBITS        ffffffff81fc86c0 11e66c0 000078 00   A  0   0  8
  [36115] __ex_table        PROGBITS        ffffffff81fc8740 11e6738 001c50 00   A  0   0  4
  [36116] .notes            NOTE            ffffffff81fca390 11e8388 0001ec 00   A  0   0  4
  [36117] .data             PROGBITS        ffffffff82000000 11ea000 215d80 00  WA  0   0 8192
  [36118] __bug_table       PROGBITS        ffffffff82215d80 13ffd80 01134c 00  WA  0   0  1
  [36119] .vvar             PROGBITS        ffffffff82228000 14110d0 001000 00  WA  0   0 16
  [36120] .data..percpu     PROGBITS        0000000000000000 1413000 02e000 00  WA  0   0 4096
  [36122] .rela.init.text   RELA            0000000000000000 149eec0 000180 18   I 36137 36121  8
  [36124] .init.data        PROGBITS        ffffffff822b6000 14a0000 18d1a0 00  WA  0   0 8192
  [36125] .x86_cpu_dev.init PROGBITS        ffffffff824431a0 162d1a0 000028 00   A  0   0  8
  [36126] .parainstructions PROGBITS        ffffffff824431c8 162d1c8 01e04c 00   A  0   0  8
  [36127] .altinstructions  PROGBITS        ffffffff82461218 164b214 003a9a 00   A  0   0  1
  [36129] .iommu_table      PROGBITS        ffffffff82465bb0 164fbb0 0000a0 00   A  0   0  8
  [36130] .apicdrivers      PROGBITS        ffffffff82465c50 164fc50 000038 00  WA  0   0  8
  [36132] .smp_locks        PROGBITS        ffffffff82468000 1651610 007000 00   A  0   0  4
  [36133] .data_nosave      PROGBITS        ffffffff8246f000 1658610 001000 00  WA  0   0  4
  [36134] .bss              NOBITS          ffffffff82470000 165a000 590000 00  WA  0   0 4096
  [36135] .brk              NOBITS          ffffffff82a00000 1659610 02c000 00  WA  0   0  1
  [36136] .init.scratch     PROGBITS        ffffffff82c00000 1659620 400000 00  WA  0   0 32
  [36137] .symtab           SYMTAB          0000000000000000 1a59620 30abd8 18     36138 111196  8
  [36138] .strtab           STRTAB          0000000000000000 1d641f8 219a29 00      0   0  1
  [36139] .shstrtab         STRTAB          0000000000000000 1f7dc21 0ed17b 00      0   0  1
Key to Flags:
  W (write), A (alloc), X (execute), M (merge), S (strings), I (info),
  L (link order), O (extra OS processing required), G (group), T (TLS),
  C (compressed), x (unknown), o (OS specific), E (exclude),
  l (large), p (processor specific)

```

### 性能开销

FGKASLR 对于性能的影响主要来自于两个阶段：启动，运行。

#### 启动阶段

在启动阶段，FGKASLR

*   需要解析内核的 ELF 文件来获取需要随机化的节区。
*   会调用随机数生成器来确定每个节区需要存储的地址，并进行布局。
*   会将原有解压的内核拷贝到另外一个地方，以便于避免内存破坏。
*   会增加内核需要重定位的次数。
*   需要检查每一个需要重定位的地址是否位于随机化的节区，如果是的话，需要调整一个新的偏移。
*   会重新排列那些需要按照地址排序的数据表。

在一个现代化的系统上，启动一个测试的 VM，大概花费了 1s。

#### 运行阶段

运行阶段的开销其实主要取决于具体的负载。不过由于原先相邻的函数可能被随机化被放在不同的地址，所以相对而言，整体性能应该会有所降低。

### 内存开销

在启动阶段，FGKASLR 需要较多的堆内存。因此，FGKASLR 可能不适用于具有较小内存的系统上。这些内存会在内核解压后被释放。

### 程序大小影响

FGKASLR 会引入额外的节区头部信息，因此会增加 vmlinux 文件的大小。在标准的配置下，vmlinux 的大小会增加 3%。压缩后的镜像大小大概会增加 15%。

### 开启与关闭

#### 开启

如果想要开启内核的 FGKASLR，你需要开启 `CONFIG_FG_KASLR=y` 选项。

FGKASLR 也支持模块的随机化，尽管 FGKASLR 只支持 x86_64 架构下的内核，但是该特性可以支持其它架构下的模块。我们可以使用 `CONFIG_MODULE_FG_KASLR=y` 来开启这个特性。

#### 关闭

通过在命令行使用 `nokaslr` 关闭 KASLR 也同时会关闭 FGKASLR。当然，我们可以单独使用 `nofgkaslr` 来关闭 FGKASLR。

### 缺点

根据 FGKASLR 的特点，我们可以发现它具有以下缺陷

*   函数粒度随机化，如果函数内的某个地址知道了，函数内部的相对地址也就知道了。
*   `.text` 节区不参与函数随机化。因此，一旦知道其中的某个地址，就可以获取该节区所有的地址。有意思的是系统调用的入口代码都在该节区内，主要是因为这些代码都是汇编代码。此外，该节区具有以下一些不错的 gadget
    *   swapgs_restore_regs_and_return_to_usermode，该部分的代码可以帮助我们绕过 KPTI 防护
    *   memcpy 内存拷贝
    *   sync_regs，可以把 RAX 放到 RDI 中
*   `__ksymtab` 相对于内核镜像的偏移是固定的。因此，如果我们可以泄露数据，那就可以泄露出其它的符号地址，如 prepare_kernel_cred、commit_creds。具体方式如下
    *   基于内核镜像地址获取 __ksymtab 地址
    *   基于 __ksymtab 获取对应符号记录项的地址
    *   根据符号记录项中具体的内容来获取对应符号的地址
*   data 节区相对于内核镜像的偏移也是固定的。因此在获取了内核镜像的基地址后，就可以计算出数据区数据的地址。这个节区有一些可以重点关注的数据
    *   modprobe_path

#### __ksymtab 格式

__ksymtab 中每个记录项的名字的格式为 `__ksymtab_func_name`，以 `prepare_kernel_cred` 为例，对应的记录项的名字为 `__ksymtab_prepare_kernel_cred`，因此，我们可以直接通过该名字在 IDA 里找到对应的位置，如下

```
__ksymtab:FFFFFFFF81F8D4FC __ksymtab_prepare_kernel_cred dd 0FF5392F4h
__ksymtab:FFFFFFFF81F8D500                 dd 134B2h
__ksymtab:FFFFFFFF81F8D504                 dd 1783Eh

```

`__ksymtab` 每一项的结构为

```
struct kernel_symbol {
    int value_offset;
    int name_offset;
    int namespace_offset;
};

```

第一个表项记录了重定位表项相对于当前地址的偏移。那么，`prepare_kernel_cred` 的地址应该为 `0xFFFFFFFF81F8D4FC-(2**32-0xFF5392F4)=0xffffffff814c67f0`。实际上也确实如此。

```
.text.prepare_kernel_cred:FFFFFFFF814C67F0                 public prepare_kernel_cred
.text.prepare_kernel_cred:FFFFFFFF814C67F0 prepare_kernel_cred proc near           ; CODE XREF: sub_FFFFFFFF814A5ED5+52↑p

```

### 参考

*   [https://lwn.net/Articles/832434/](https://lwn.net/Articles/832434/)
*   [https://github.com/kaccardi/linux/compare/fg-kaslr](https://github.com/kaccardi/linux/compare/fg-kaslr)
*   [https://elixir.bootlin.com/linux/latest/source/include/linux/export.h#L60](https://elixir.bootlin.com/linux/latest/source/include/linux/export.h#L60)
*   [https://www.youtube.com/watch?v=VcqhJKfOcx4](https://www.youtube.com/watch?v=VcqhJKfOcx4)
*   [https://www.phoronix.com/scan.php?page=article&item=kaslr-fgkaslr-benchmark&num=1](https://www.phoronix.com/scan.php?page=article&item=kaslr-fgkaslr-benchmark&num=1)

KASLR
-----

### 介绍

在开启了 KASLR 的内核中，内核的代码段基地址等地址会整体偏移。

### 发展历史

TODO。

### 实现

TODO。

### 开启与关闭

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `kaslr` 来开启 KASLR。

如果是使用 qemu 启动的内核，我们可以在 `-append` 选项中添加 `nokaslr` 来关闭 KASLR。

### Attack

通过泄漏内核某个段的地址，就可以得到这个段内的所有地址。比如当我们泄漏了内核的代码段地址，就知道内核代码段的所有地址。

### 参考

*   [https://outflux.net/slides/2013/lss/kaslr.pdf](https://outflux.net/slides/2013/lss/kaslr.pdf)
*   [https://bneuburg.github.io/volatility/kaslr/2017/04/26/KASLR1.html](https://bneuburg.github.io/volatility/kaslr/2017/04/26/KASLR1.html)

[img-0]:data:image/png;base64,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JjYuX40tMYkCJYpSu0Vjl9tA3NetZKVyVKhVPc1DEzJiwrCR/DTkq5lxMbHtrvKjgxq3u3vwOz+OvKaeiLYkG9vWrufk4WMEBAVStnplItyaV21JNnZt3MyJw0fxD8hC8fJlPHbmPH3sODvW/0NiQiK5C+SjdNVKjnPMhXPnOXbgEKUqV/DYtyPN/DZt4eThI/hlSTu/4a+9y6aVa/hmwTS2rF7L6aMnKF6hLEXKlExzftq04m+iTp+lWPnSFC1Tij1btpMjdy6XoExJSWH72o2cOHSEwOCslK9Z1dHqZ3fq6HF2bvC8bldjyAuvpswcN2koMPAWnBPGZNr7cH18fa8YtkCGnq50PZ/AlJFpXanjUkZ7Efv4+l4xlPV0qczHy8uLKg3qXLZ/gX9AliuOAxCWK8LxsAhP3EPusvOrX5sqbr2QPSlXo8plb6Wr1qge1RrVc3nP3o/Bvdm1TLXK17xumaKJ0c/X6mtR9/LjlKtZ9YoPesiZLy858+X1OCwke2iaS1yXnd8V9iGAt7f3ZfuJ+Pj6ptnPJSqU9Tid8rWqUd6tM5+zXPnzkit/3kz/3dazlEVERG5GAUub4CaUary9WXLugDaE3LGCQ7Mx4PMPKOihpip3lnY9utDswXbaEApcEbkVAgID75hbN+TyCpYoqo1wrZUvbQIREREFroiIiAJXREREFLgiIiIKXBEREQWuiIiIKHBFREQUuCIiIqLAFRERUeCKiIgocEVERESBKyIiosAVERFR4IqIiIgCV0RERIErIiIiClwREREFroiIiAJXREREFLgiIiIKXBEREVHgioiIKHBFREQUuCIiIqLAFRERUeCKiIgocEVERESBKyIiosAVERERBa6IiIgCV0RERIErIiIiClwREREFroiIiChwRUREFLgiIiIKXBEREVHgioiIKHBFREQUuCIiIqLAFRERUeCKiIiIAldERESBKyIiosAVERERBa6IiIgCV0RERBS4IiIiClwREREFroiIiChwRUREFLgiIiIKXBEREVHgioiIKHBFREREgSsiIqLAFRERUeCKiIiIAldERESBKyIiIgpcERERBa6IiIgCV0RERBS4IiIiClwREREFroiIiChwRUREFLgiIiKiwBUREVHgioiIKHBFREREgSsiIqLAFREREQWuiIiIAldERESBKyIiIgpcERERBa6IiIgC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

[img-1]:data:image/png;base64,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

[img-2]:data:image/png;base64,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