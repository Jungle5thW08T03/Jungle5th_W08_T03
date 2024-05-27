#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "userprog/process.h"
#include "filesys.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

bool check_address (void *ptr);
void exit (int status);
tid_t fork (const char *thread_name, struct intr_frame *f);
tid_t exec (const char *cmd_line);
bool create (const char *file, uint64_t initial_size);
bool remove (const char *file);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {
	// TODO: Your implementation goes here.

	int syscall_type = f->R.rax;
	switch (syscall_type)
	{
	case SYS_HALT:
		power_off();
		break;
	
	case SYS_EXIT:
		exit(f->R.rdi);
		break;

	case SYS_FORK:
		f->R.rax = fork(f->R.rdi, f);
		break;
	
	case SYS_EXEC:
		char *file_name = f->R.rdi;
		if (!check_address(file_name)) exit(-1);
		f->R.rax = exec(file_name);
		break;

	case SYS_WAIT:
		f->R.rax = process_wait (f->R.rdi);
		break;

	case SYS_CREATE:
		f->R.rax = create(f->R.rdi, f->R.rsi);
		break;

	case SYS_REMOVE:
		f->R.rax = remove(f->R.rdi);
		break;

	default:
		break;
	}
	
	printf ("system call!\n");
	thread_exit ();
}

bool check_address (void *addr)
{
	if (addr == NULL) {
		exit(-1);
		return false;
	}

	if (!is_user_vaddr(addr)) {
		exit(-1);
		return false;
	}

	return true;
}

void exit(status)
{
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", cur->name, status);
	thread_exit();
	return 0;
}

tid_t fork (const char *thread_name, struct intr_frame *f)
{
	return process_fork(thread_name, f);
}

tid_t exec (const char *cmd_line)
{
	check_address(cmd_line);
	process_exec(cmd_line);
	
}

bool create (const char *file, uint64_t initial_size)
{
	check_address(file);
	return filesys_create(file, initial_size);
}

bool remove (const char *file)
{
	check_address(file);
	return filesys_remove(file);
}