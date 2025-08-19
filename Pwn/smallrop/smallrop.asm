global _start
section .text

_start:
call vuln
mov eax, 0xe7
syscall

vuln:
sub rsp, 0x80
mov eax, 1
mov edi, 1
mov rsi, prompt
mov edx, prompt_len
syscall
xor eax, eax
xor edi, edi
mov rsi, rsp
mov rdx, 0x800
syscall
add rsp, 0x80
ret

prompt: db "> "
prompt_len: equ $-prompt