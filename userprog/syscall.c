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
#include "file.h"

void syscall_entry (void);
void syscall_handler (struct intr_frame *);

bool check_address (void *ptr);
void exit (int status);
tid_t fork (const char *thread_name, struct intr_frame *f);
tid_t exec (const char *cmd_line);
bool create (const char *file, uint64_t initial_size);
bool remove (const char *file);
int open (const char *file);
int filesize (int fd);
off_t read (int fd, void *buffer, unsigned size);
off_t write (int fd, const void *buffer, unsigned size);



int set_fd(struct file *file);
struct file *get_file(int fd);
void close_file(int fd);

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

struct lock filesys_lock;

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

	lock_init(&filesys_lock);
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

	case SYS_OPEN:
		f->R.rax = open(f->R.rdi);
		break;

	case SYS_FILESIZE:
		f->R.rax = filesize(f->R.rdi);
		break;

	case SYS_READ:
		f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
		break;

	case SYS_WRITE:
		f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
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
	lock_acquire(&filesys_lock);
	bool succ = filesys_remove(file);
	lock_release(&filesys_lock);
	return succ;
}

int open (const char *file)
{
	check_address(file);
	lock_acquire(&filesys_lock);
	struct file *f_open = NULL;
	f_open = filesys_open(file);
	if (f_open ==NULL) {
		lock_release(&filesys_lock);
		return -1;
	}
	int fd = set_fd(f_open);
	if (fd == -1) {
		file_close(f_open);
	}

	lock_release(&filesys_lock);
	return fd;
}

int filesize (int fd)
{
	struct file *file = get_file(fd);
	if (file == NULL) return -1;
	return file_length(file);
}

off_t read(int fd, void *buffer, unsigned size)
{
	check_address(buffer);
	int readbytes = -1;
	char *buf = buffer;
	lock_acquire(&filesys_lock);
	struct file *file = get_file(fd);
	if (fd == 0) {
		readbytes = 0;
		while (readbytes <= size) {
			*buf = input_getc();
			buf++;
			readbytes++;
		}
	}
	else if ((1 < fd <= FD_MAX) && file) {
		readbytes = file_read(file, buffer, size);
	}

	lock_release(&filesys_lock);
	return readbytes;
}

off_t write (int fd, const void *buffer, unsigned size)
{
	check_address(buffer);
	int writtenbytes = -1;
	lock_acquire(&filesys_lock);
	struct file *file = get_file(fd);
	if (fd == 1) {
		putbuf(buffer, size);
		writtenbytes = size;
	}
	else if ((1 < fd <= FD_MAX) && file)
	{
		writtenbytes = file_write(file, buffer, size);
	}
	
	lock_release(&filesys_lock);
	return writtenbytes;
}


// fd 인덱스 부여
int set_fd(struct file *file)
{
	struct thread *cur = thread_current();
	struct file **fdt = cur->fdt;
	int fd = 2;
	while (fdt[fd] != NULL) 
	{
		if (fd == FD_MAX) return -1;
		fd += 1;
	}
	fdt[fd] = file;
	return fd;
}

struct file *get_file(int fd)
{
	if (fd < 2 || fd > FD_MAX) return NULL;
	struct file *file = NULL;
	struct thread *cur = thread_current();
	file = cur->fdt[fd];
	return file;
}

void close_file(int fd)
{
	if (fd < 2 || fd > FD_MAX) return NULL;
	struct thread *cur = thread_current();
	cur->fdt[fd] = NULL;
}