# DebugFromEntryPoint with Cheat Engine
+ this program calls MessageBoxW before target process executes anything
+ if you set BP at MessageBoxW's ret code, you can debug and trace EntryPoint with CE
+ how to use
	+ drag and drop PE file to DebugFromEntryPoint.exe
	+ set BP at MessageBoxW's ret code by CE
	+ Press OK to close MessageBox

## Injected code
### x86 version
+ x86 process needs to hold initial eax and ebx to inject code before executing EntryPoint
```x86asm
01100000 - 50                    - push eax
01100001 - 53                    - push ebx
01100002 - 68 35001001           - push 01100035 { ("user32.dll") }
01100007 - FF 15 29001001        - call dword ptr [01100029] { ->KERNEL32.LoadLibraryW }
0110000D - 6A 00                 - push 00 { 0 }
0110000F - 68 35011001           - push 01100135 { ("DebugFromEntryPoint") }
01100014 - 68 35021001           - push 01100235 { ("Please set BP at ret code of Me") }
01100019 - 6A 00                 - push 00 { 0 }
0110001B - FF 15 2D001001        - call dword ptr [0110002D] { ->USER32.MessageBoxW }
01100021 - 5B                    - pop ebx
01100022 - 58                    - pop eax
01100023 - FF 25 31001001        - jmp dword ptr [01100031] { ->ntdll.RtlUserThreadStart }
```

### x64 version
```x86asm
1C761550000 - 50                    - push rax
1C761550001 - 53                    - push rbx
1C761550002 - 51                    - push rcx
1C761550003 - 52                    - push rdx
1C761550004 - 56                    - push rsi
1C761550005 - 57                    - push rdi
1C761550006 - 55                    - push rbp
1C761550007 - 41 50                 - push r8
1C761550009 - 41 51                 - push r9
1C76155000B - 41 52                 - push r10
1C76155000D - 41 53                 - push r11
1C76155000F - 41 54                 - push r12
1C761550011 - 41 55                 - push r13
1C761550013 - 41 56                 - push r14
1C761550015 - 41 57                 - push r15
1C761550017 - 48 83 EC 30           - sub rsp,30 { 48 }
1C76155001B - 48 8D 0D 59000000     - lea rcx,[1C76155007B] { ("user32.dll") }
1C761550022 - FF 15 3B000000        - call qword ptr [1C761550063] { ->KERNEL32.LoadLibraryW }
1C761550028 - 4D 31 C9              - xor r9,r9
1C76155002B - 4C 8D 05 49010000     - lea r8,[1C76155017B] { ("DebugFromEntryPoint") }
1C761550032 - 48 8D 15 42020000     - lea rdx,[1C76155027B] { ("Please set BP at ret code of Me") }
1C761550039 - 48 31 C9              - xor rcx,rcx
1C76155003C - FF 15 29000000        - call qword ptr [1C76155006B] { ->USER32.MessageBoxW }
1C761550042 - 48 83 C4 30           - add rsp,30 { 48 }
1C761550046 - 41 5F                 - pop r15
1C761550048 - 41 5E                 - pop r14
1C76155004A - 41 5D                 - pop r13
1C76155004C - 41 5C                 - pop r12
1C76155004E - 41 5B                 - pop r11
1C761550050 - 41 5A                 - pop r10
1C761550052 - 41 59                 - pop r9
1C761550054 - 41 58                 - pop r8
1C761550056 - 5D                    - pop rbp
1C761550057 - 5F                    - pop rdi
1C761550058 - 5E                    - pop rsi
1C761550059 - 5A                    - pop rdx
1C76155005A - 59                    - pop rcx
1C76155005B - 5B                    - pop rbx
1C76155005C - 58                    - pop rax
1C76155005D - FF 25 10000000        - jmp qword ptr [1C761550073] { ->ntdll.RtlUserThreadStart }
```