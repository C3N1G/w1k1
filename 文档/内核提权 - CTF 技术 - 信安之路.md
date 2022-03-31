> 本文由 [简悦 SimpRead](http://ksria.com/simpread/) 转码， 原文地址 [wiki.xazlsec.com](https://wiki.xazlsec.com/project-15/doc-245/)

> 内核提权指的是普通用户可以获取到 root 用户的权限，访问原先受限的资源。这里从两种角度来考虑如何提权 - 改变自身：通过改变自身进程的权限，使其具有 root 权限。 - 改变别人：通过影响高权

内核提权指的是普通用户可以获取到 root 用户的权限，访问原先受限的资源。这里从两种角度来考虑如何提权

*   改变自身：通过改变自身进程的权限，使其具有 root 权限。
*   改变别人：通过影响高权限进程的执行，使其完成我们想要的功能。

参考文献
----

*   [https://en.wikipedia.org/wiki/Privilege_escalation](https://en.wikipedia.org/wiki/Privilege_escalation)

内核会通过进程的 `task_struct` 结构体中的 cred 指针来索引 cred 结构体，然后根据 cred 的内容来判断一个进程拥有的权限，如果 cred 结构体成员中的 uid-fsgid 都为 0，那一般就会认为进程具有 root 权限。

```
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC    0x43736564
#define CRED_MAGIC_DEAD    0x44656144
#endif
    kuid_t        uid;        /* real UID of the task */
    kgid_t        gid;        /* real GID of the task */
    kuid_t        suid;        /* saved UID of the task */
    kgid_t        sgid;        /* saved GID of the task */
    kuid_t        euid;        /* effective UID of the task */
    kgid_t        egid;        /* effective GID of the task */
    kuid_t        fsuid;        /* UID for VFS ops */
    kgid_t        fsgid;        /* GID for VFS ops */
  ...
}

```

因此，思路就比较直观了，我们可以通过以下方式来提权

*   直接修改 cred 结构体的内容
*   修改 task_struct 结构体中的 cred 指针指向一个满足要求的 cred

无论是哪一种方法，一般都分为两步：定位，修改。这就好比把大象放到冰箱里一样。

直接改 cred
--------

### 定位具体位置

我们可以首先获取到 cred 的具体地址，然后修改 cred。

#### 定位

定位 cred 的具体地址有很多种方法，这里根据是否直接定位分为以下两种

##### 直接定位

cred 结构体的最前面记录了各种 id 信息，对于一个普通的进程而言，uid-fsgid 都是执行进程的用户的身份。因此我们可以通过扫描内存来定位 cred。

```
struct cred {
    atomic_t    usage;
#ifdef CONFIG_DEBUG_CREDENTIALS
    atomic_t    subscribers;    /* number of processes subscribed */
    void        *put_addr;
    unsigned    magic;
#define CRED_MAGIC    0x43736564
#define CRED_MAGIC_DEAD    0x44656144
#endif
    kuid_t        uid;        /* real UID of the task */
    kgid_t        gid;        /* real GID of the task */
    kuid_t        suid;        /* saved UID of the task */
    kgid_t        sgid;        /* saved GID of the task */
    kuid_t        euid;        /* effective UID of the task */
    kgid_t        egid;        /* effective GID of the task */
    kuid_t        fsuid;        /* UID for VFS ops */
    kgid_t        fsgid;        /* GID for VFS ops */
  ...
}

```

**在实际定位的过程中，我们可能会发现很多满足要求的 cred，这主要是因为 cred 结构体可能会被拷贝、释放。**一个很直观的想法是在定位的过程中，利用 usage 不为 0 来筛除掉一些 cred，但仍然会发现一些 usage 为 0 的 cred。这是因为 cred 从 usage 为 0， 到释放有一定的时间。此外，cred 是使用 rcu 延迟释放的。

##### 间接定位

###### task_struct

进程的 `task_struct` 结构体中会存放指向 cred 的指针，因此我们可以

1.  定位当前进程 `task_struct` 结构体的地址
    
2.  根据 cred 指针相对于 task_struct 结构体的偏移计算得出 `cred` 指针存储的地址
    
3.  获取 `cred` 具体的地址
    

###### comm

comm 用来标记可执行文件的名字，位于进程的 `task_struct` 结构体中。我们可以发现 comm 其实在 cred 的正下方，所以我们也可以先定位 comm ，然后定位 cred 的地址。

```
    /* Process credentials: */
    /* Tracer's credentials at attach: */
    const struct cred __rcu        *ptracer_cred;
    /* Objective and real subjective task credentials (COW): */
    const struct cred __rcu        *real_cred;
    /* Effective (overridable) subjective task credentials (COW): */
    const struct cred __rcu        *cred;
#ifdef CONFIG_KEYS
    /* Cached requested key. */
    struct key            *cached_requested_key;
#endif
    /*
     * executable name, excluding path.
     *
     * - normally initialized setup_new_exec()
     * - access it with [gs]et_task_comm()
     * - lock it with task_lock()
     */
    char                comm[TASK_COMM_LEN];

```

然而，在进程名字并不特殊的情况下，内核中可能会有多个同样的字符串，这会影响搜索的正确性与效率。因此，我们可以使用 prctl 设置进程的 comm 为一个特殊的字符串，然后再开始定位 comm。

#### 修改

在这种方法下，我们可以直接将 cred 中的 uid-fsgid 都修改为 0。当然修改的方式有很多种，比如说

*   在我们具有任意地址读写后，可以直接修改 cred。
*   在我们可以 ROP 执行代码后，可以利用 ROP gadget 修改 cred。

### 间接定位

虽然我们确实想要修改 cred 的内容，但是不一定非得知道 cred 的具体位置，我们只需要能够修改 cred 即可。

#### UAF 使用同样堆块

如果我们在进程初始化时能控制 cred 结构体的位置，并且我们可以在初始化后修改该部分的内容，那么我们就可以很容易地达到提权的目的。这里给出一个典型的例子

1.  申请一块与 cred 结构体大小一样的堆块
2.  释放该堆块
3.  fork 出新进程，恰好使用刚刚释放的堆块
4.  此时，修改 cred 结构体特定内存，从而提权

非常有意思的是，在这个过程中，我们不需要任何的信息泄露。

修改 cred 指针
----------

### 定位具体位置

在这种方式下，我们需要知道 cred 指针的具体地址。

#### 定位

##### 直接定位

显然，cred 指针并没有什么非常特殊的地方，所以很难通过直接定位的方式定位到 cred 指针。

##### 间接定位

###### task_struct

进程的 `task_struct` 结构体中会存放指向 cred 的指针，因此我们可以

1.  定位当前进程 `task_struct` 结构体的地址
    
2.  根据 cred 指针相对于 task_struct 结构体的偏移计算得出 `cred` 指针存储的地址
    

###### common

comm 用来标记可执行文件的名字，位于进程的 `task_struct` 结构体中。我们可以发现 comm 其实在 cred 指针的正下方，所以我们也可以先定位 comm ，然后定位 cred 指针的地址。

```
    /* Process credentials: */
    /* Tracer's credentials at attach: */
    const struct cred __rcu        *ptracer_cred;
    /* Objective and real subjective task credentials (COW): */
    const struct cred __rcu        *real_cred;
    /* Effective (overridable) subjective task credentials (COW): */
    const struct cred __rcu        *cred;
#ifdef CONFIG_KEYS
    /* Cached requested key. */
    struct key            *cached_requested_key;
#endif
    /*
     * executable name, excluding path.
     *
     * - normally initialized setup_new_exec()
     * - access it with [gs]et_task_comm()
     * - lock it with task_lock()
     */
    char                comm[TASK_COMM_LEN];

```

然而，在进程名字并不特殊的情况下，内核中可能会有多个同样的字符串，这会影响搜索的正确性与效率。因此，我们可以使用 prctl 设置进程的 comm 为一个特殊的字符串，然后再开始定位 comm。

#### 修改

在具体修改时，我们可以使用如下的两种方式

*   修改 cred 指针为内核镜像中已有的 init_cred 的地址。这种方法适合于我们能够直接修改 cred 指针以及知道 init_cred 地址的情况。
*   伪造一个 cred，然后修改 cred 指针指向该地址即可。这种方式比较麻烦，一般并不使用。

### 间接定位

#### commit_creds(prepare_kernel_cred(0))

我们还可以使用 commit_creds(prepare_kernel_cred(0)) 来进行提权，该方式会自动生成一个合法的 cred，并定位当前线程的 task_struct 的位置，然后修改它的 cred 为新的 cred。该方式比较适用于控制程序执行流后使用。

![][img-0]

在整个过程中，我们并不知道 cred 指针的具体位置。

如果我们可以改变特权进程的执行轨迹，也可以实现提权。这里我们从以下角度来考虑如何改变特权进程的执行轨迹。

*   改数据
*   改代码

改数据
---

这里给出几种通过改变特权进程使用的数据来进行提权的方法。

### 符号链接

如果一个 root 权限的进程会执行一个符号链接的程序，并且该符号链接或者符号链接指向的程序可以由攻击者控制，攻击者就可以实现提权。

### call_usermodehelper

`call_usermodehelper` 是一种内核线程执行用户态应用的方式，并且启动的进程具有 root 权限。因此，如果我们能够控制具体要执行的应用，那就可以实现提权。在内核中，`call_usermodehelper` 具体要执行的应用往往是由某个变量指定的，因此我们只需要想办法修改掉这个变量即可。不难看出，这是一种典型的数据流攻击方法。一般常用的主要有以下几种方式。

#### 修改 modprobe_path

修改 modprobe_path 实现提权的基本流程如下

1.  获取 modprobe_path 的地址。
2.  修改 modprobe_path 为指定的程序。
3.  触发执行 `call_modprobe` ，从而实现提权 。这里我们可以利用以下几种方式来触发
    1.  执行一个非法的可执行文件。非法的可执行文件需要满足相应的要求（参考 call_usermodehelper 部分的介绍）。
    2.  使用未知协议来触发。

这里我们也给出使用 modprobe_path 的模板。

```
// step 1. modify modprobe_path to the target value
// step 2. create related file
system("echo -ne '#!/bin/sh\n/bin/cp /flag /home/pwn/flag\n/bin/chmod 777 /home/pwn/flag\ncat flag' > /home/pwn/catflag.sh");
system("chmod +x /home/pwn/catflag.sh");
// step 3. trigger it using unknown executable
system("echo -ne '\\xff\\xff\\xff\\xff' > /home/pwn/dummy");
system("chmod +x /home/pwn/dummy");
system("/home/pwn/dummy");
// step 3. trigger it using unknown protocol
socket(AF_INET,SOCK_STREAM,132);

```

在这个过程中，我们着重关注下如何定位 modprobe_path。

##### 直接定位

由于 modprobe_path 的取值是确定的，所以我们可以直接扫描内存，寻找对应的字符串。这需要我们具有扫描内存的能力。

##### 间接定位

考虑到 modprobe_path 相对于内核基地址的偏移是固定的，我们可以先获取到内核的基地址，然后根据相对偏移来得到 modprobe_path 的地址。

#### 修改 poweroff_cmd

1.  修改 poweroff_cmd 为指定的程序。
2.  劫持控制流执行 `__orderly_poweroff`。

关于如何定位 poweroff_cmd，我们可以采用类似于定位 `modprobe_path` 的方法。

改代码
---

在程序运行时，如果我们可以修改 root 权限进程执行的代码，那其实我们也可以实现提权。

### 修改 vDSO 代码

内核中 vDSO 的代码会被映射到所有的用户态进程中。如果有一个高特权的进程会周期性地调用 vDSO 中的函数，那我们可以考虑把 vDSO 中相应的函数修改为特定的 shellcode。当高权限的进程执行相应的代码时，我们就可以进行提权。

在早期的时候，Linux 中的 vDSO 是可写的，考虑到这样的风险，Kees Cook 提出引入 `post-init read-only` 的数据，即将那些初始化后不再被写的数据标记为只读，来防御这样的利用。

在引入之前，vDSO 对应的 raw_data 只是标记了对齐属性。

```
    fprintf(outfile, "/* AUTOMATICALLY GENERATED -- DO NOT EDIT */\n\n");
    fprintf(outfile, "#include <linux/linkage.h>\n");
    fprintf(outfile, "#include <asm/page_types.h>\n");
    fprintf(outfile, "#include <asm/vdso.h>\n");
    fprintf(outfile, "\n");
    fprintf(outfile,
        "static unsigned char raw_data[%lu] __page_aligned_data = {",
        mapping_size);

```

引入之后，vDSO 对应的 raw_data 则被标记为了初始化后只读。

```
    fprintf(outfile, "/* AUTOMATICALLY GENERATED -- DO NOT EDIT */\n\n");
    fprintf(outfile, "#include <linux/linkage.h>\n");
    fprintf(outfile, "#include <asm/page_types.h>\n");
    fprintf(outfile, "#include <asm/vdso.h>\n");
    fprintf(outfile, "\n");
    fprintf(outfile,
        "static unsigned char raw_data[%lu] __ro_after_init __aligned(PAGE_SIZE) = {",
        mapping_size);

```

通过修改 vDSO 进行提权的基本方式如下

*   定位 vDSO
*   修改 vDSO 的特定函数为指定的 shellcode
*   等待触发执行 shellcode

这里我们着重关注下如何定位 vDSO。

#### ida 里定位

这里我们介绍一下如何在 vmlinux 中找到 vDSO 的位置。

1.  在 ida 里定位 init_vdso 函数的地址

```
__int64 init_vdso()
{
  init_vdso_image(&vdso_image_64 + 0x20000000);
  init_vdso_image(&vdso_image_x32 + 0x20000000);
  cpu_maps_update_begin();
  on_each_cpu((char *)startup_64 + 0x100003EA0LL, 0LL, 1LL);
  _register_cpu_notifier(&sdata + 536882764);
  cpu_maps_update_done();
  return 0LL;
}

```

2.  可以看到 `vdso_image_64` 和 `vdso_image_x32`。以`vdso_image_64` 为例，点到该变量的地址

```
.rodata:FFFFFFFF81A01300                 public vdso_image_64
.rodata:FFFFFFFF81A01300 vdso_image_64   dq offset raw_data      ; DATA XREF: arch_setup_additional_pages+18↑o
.rodata:FFFFFFFF81A01300                                         ; init_vdso+1↓o

```

3.  点击 `raw_data` 即可知道 64 位 vDSO 在内核镜像中的地址，可以看到，vDSO 确实是以页对齐的。

```
.data:FFFFFFFF81E04000 raw_data        db  7Fh ;              ; DATA XREF: .rodata:vdso_image_64↑o
.data:FFFFFFFF81E04001                 db  45h ; E
.data:FFFFFFFF81E04002                 db  4Ch ; L
.data:FFFFFFFF81E04003                 db  46h ; F

```

从最后的符号来看，我们也可以直接使用 `raw_data` 来寻找 vDSO。

#### 内存中定位

##### 直接定位

vDSO 其实是一个 ELF 文件，具有 ELF 文件头。同时，vDSO 中特定位置存储着导出函数的字符串。因此我们可以根据这两个特征来扫描内存，定位 vDSO 的位置。

##### 间接定位

考虑到 vDSO 相对于内核基地址的偏移是固定的，我们可以先获取到内核的基地址，然后根据相对偏移来得到 vDSO 的地址。

#### 参考

*   [https://lwn.net/Articles/676145/](https://lwn.net/Articles/676145/)
*   [https://lwn.net/Articles/666550/](https://lwn.net/Articles/666550/)

[img-0]:data:image/png;base64,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hHTIEDc9wnnbFLX/zpzRftWkiW7/4IPAW2/5L8dJf7l8Wc++DRoAERFAfDzwy19qOYWZMwfo2hWoX99OCw0F+vQBli8Hzp1z0QjyA/ENRNLSJCAbN4qEhorExYk884zI7NkiDz0kAoiMGOFrGxkpEhsrMmaMyNNPi9SvL5KYqPY7drizExFJTRVJThZp2VJ9SE0Vycvz72tGhuabnCwyZYrIvHkiXbponuPG2Xavvy7yi19oer9+altU/atWFUlKEnnuOZGxY9XXkBCRDRvclSsikpKi9Y6LE2nbVmTUKJEaNdT2vvtEwsNF+vQRGThQpHp1kZgYke+/L/221vaNGun3hQtFOnfWbfv3F1m0SFzjpG0C7b+jR3V/16olMn68tlvHjurPiy+WrF/9+tciYWEiTz0lsnixyPPPi9SurWV78sUXut3Eib51WrJE161cWXTd4+NFhg7V747FNHy4SESESE6OnZaXJ9K4sb1jREQKCkRat9YdeOyYnZ6dLRIVZVfaqZ1Faqqm9eolkpsb2M/8fJE2bTTfkye903v21APCzp2+jZaRUXSerVuLREeLHD5sp2dl6U579FH35aakaLnTp9tpmzdrWmSkyL59dvq4cZr+ySel39ba3nOfzZypNpmZ4honbVPU/uvXT9O3b7fTrl8X6dFD2yw7212/unpVpEoVkUce8fYzPV1tPPfBvHmatnixb722btV1gwcXXX9PMTm+zJs4US9hoqLstEuX9FLm4kU7bds2YO9eYNQooFEjO71hQ2DoUPd2hUlLA6pWDbx+1y77UisuzvvUPWCAjmU2bnRx6oYGJvbuBXr08J4+OilJr7nvv79k5YaGAk8/bf9u2VKXHToAt95qp3fqpMv//MfMtiZx0jaeeO6/c+f0UjAlRT8WYWHA8OHaZqtXa5rT/iKi23/4oV4SWgwdquHutm3ttKNHddm0qW+9rDbcv995W1RxapicDJw+rWOMrVv12vfIERVUdLRtZxXepo1vHi1auLfzpG5d4I47ivbz4EFddu7su65dO10eOOC8gQC99wAAP/+577rBg3VpjQ/clBsfr9f0FpGRukxI8LYL/eGQl5dnZluTOGkbi8L7z+oDOTlAr17etpcv6/LIEW/b4vpLZKRGKidMADp2BBo31gPcL36hgvdss9OndelPTDExQL16wKlTztvC8Zlp+nQ9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