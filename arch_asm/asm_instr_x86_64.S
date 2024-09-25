.text

.global syscall_instr_start
.global syscall_instr_end

.global func_call_instr_start
.global func_call_instr_end

syscall_instr_start:
	syscall	
syscall_instr_end:


func_call_instr_start:
	call *%r9
	int $3
func_call_instr_end:
