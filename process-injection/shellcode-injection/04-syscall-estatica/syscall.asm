.code

NtOpenProcess proc
  mov r10, rcx
  mov eax, 026h
  syscall
  ret
NtOpenProcess endp

NtWriteVirtualMemory proc
  mov r10, rcx
  mov eax, 03Ah
  syscall
  ret
NtWriteVirtualMemory endp

NtAllocateVirtualMemory proc
  mov r10, rcx
  mov eax, 018h
  syscall
  ret
NtAllocateVirtualMemory endp

NtAllocateVirtualMemoryEx proc
  mov r10, rcx
  mov eax, 076h
  syscall
  ret
NtAllocateVirtualMemoryEx endp

NtCreateThreadEx proc
  mov r10, rcx
  mov eax, 0C1h
  syscall
  ret
NtCreateThreadEx endp

end