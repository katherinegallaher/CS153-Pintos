#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "userprog/process.h"
#include "userprog/pagedir.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
 
struct file* get_file(int fd);
static int sys_halt (void);
static int sys_exec (const char *ufile);
static int sys_wait (tid_t);
static bool sys_create(const char *file, unsigned initial_size);
static bool sys_remove (const char *ufile);
static int sys_open(const char * file);
static int sys_filesize (int handle);
static int sys_read (int fd, void *buffer, unsigned size);
static int sys_write (int handle, void *usrc_, unsigned size);
static void sys_seek (int handle, unsigned position);
static int sys_tell (int handle);
static void sys_close (int handle);
static bool verify_user(const void *);
static void syscall_handler (struct intr_frame *);
static void copy_in (void *, const void *, size_t);
int newfd = 3;
 
void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Copies a byte from user address USRC to kernel address DST.
 *    USRC must be below PHYS_BASE.
 *       Returns true if successful, false if a segfault occurred. */
static inline bool
get_user (uint8_t *dst, const uint8_t *usrc)
{
	  int eax;
	  asm ("movl $1f, %%eax; movb %2, %%al; movb %%al, %0; 1:"
		    : "=m" (*dst), "=&a" (eax) : "m" (*usrc));
	  return eax != 0;
}

static void
copy_in (void *dst_, const void *usrc_, size_t size) 
{
	  uint8_t *dst = dst_;
	  const uint8_t *usrc = usrc_;
	  for (; size > 0; size--, dst++, usrc++) 
	  	if (usrc >= (uint8_t *) PHYS_BASE || !get_user (dst, usrc)) 
			thread_exit ();
}

/* Creates a copy of user string US in kernel memory
 *    and returns it as a page that must be freed with
 *       palloc_free_page().
 *          Truncates the string at PGSIZE bytes in size.
 *             Call thread_exit() if any of the user accesses are invalid. */
static char *
copy_in_string (const char *us) 
{
	char *ks;
	size_t length;
		 
	ks = palloc_get_page (0);
	if (ks == NULL) 
		thread_exit ();
					  
	for (length = 0; length < PGSIZE; length++)
	{
		if (us >= (char *) PHYS_BASE || !get_user (ks + length, us++)) 
		{
			palloc_free_page (ks);
			thread_exit (); 
		}
																					         
		if (ks[length] == '\0')
			return ks;
	}
	ks[PGSIZE - 1] = '\0';
	return ks;
}

void checkPtr(const void *v)
{
	if (!is_user_vaddr(v) || v < 0x08048000 )
		sys_exit(-1);
}


/* System call handler. */
static void
syscall_handler (struct intr_frame *f) 
{
	int args[3];

 	 checkPtr((const void *) f->esp);
 
 	 unsigned syscallnum; 
 	 copy_in(&syscallnum, f->esp, sizeof(syscallnum) );
 	 memset(args, 0, sizeof(args) );
 

 	 if(!verify_user(f->esp)){
	 	sys_exit(-1);
 	}

 	switch(syscallnum)
 	{
		case SYS_HALT:
		{
			sys_halt();
			break;
		}
		case SYS_EXIT:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1  );
			sys_exit(args[0]);
			break;
		}
		case SYS_EXEC:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1  );
			if(!verify_user( (const char*)args[0] ) )
				sys_exit(-1);
			f->eax = sys_exec((const char*) args[0] );
			break;
		}
		case SYS_WAIT:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1  );
			f->eax = sys_wait(args[0]);
			break;
		}
		case SYS_CREATE:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 2 );
			
		    if(!verify_user( (const char*)args[0] ) )
				sys_exit(-1);
	
			f->eax = sys_create( (const char*)args[0], (unsigned) args[1]);
			break;
		}	
		case SYS_REMOVE:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1 );
			if(!verify_user( (const char*)args[0] ) )
				sys_exit(-1);
			f->eax = sys_remove( (const char *) args[0]);
			break;
		}
		case SYS_OPEN:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1 );
			if(!verify_user(args[0] ) )
				sys_exit(-1);
			f->eax = sys_open( (const char *) args[0] );
			break;
		}
		case SYS_CLOSE:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1 );
			sys_close(args[0]);
			break;
		}
		case SYS_FILESIZE:
		{	
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1 );
			f->eax = sys_filesize(args[0]);
			break;
		}
		case SYS_READ:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 3 );
			if(!verify_user((void *)args[1]) )
				sys_exit(-1);
			f->eax = sys_read(args[0], (void *) args[1], (unsigned) args[2] );
			break;
		}
		case SYS_WRITE:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 3 );
			if(!verify_user((const void *)args[1]) || !verify_user((const void*) args[1] + (unsigned) args[2]))
				sys_exit(-1);
			f->eax = sys_write(args[0], (const void*) args[1], (unsigned) args[2]);
			break;
		}	
		case SYS_TELL:
		{
			copy_in(args, (uint32_t *) f->esp +1, sizeof *args * 1 );
		    f->eax = sys_tell(args[0]);
			break;
		}
		default:
		{
			sys_exit(-1);
		}
	}	
}
 
/* Returns true if UADDR is a valid, mapped user address,
   false otherwise. */
static bool
verify_user (const void *uaddr) 
{
	return (uaddr < PHYS_BASE
		    && pagedir_get_page (thread_current ()->pagedir, uaddr) != NULL);
}

/* Remove system call. */
static bool
sys_remove(const char* file){
	return filesys_remove(file);
 }

/* Halt system call. */
static int
sys_halt (void)
{
  shutdown_power_off ();
}
 
/* Exit system call. */
int
sys_exit (int exit_code) 
{
  thread_current ()->wstatus->exit_status = exit_code;
  thread_exit ();
  NOT_REACHED ();
}
 
/* Exec system call. */
static int
sys_exec (const char *exec) 
{
  if(exec == NULL)
	  return -1;
  char *str = copy_in_string(exec);
  return process_execute(str); 
}
 
/* Wait system call. */
static int
sys_wait (tid_t child) 
{
	return process_wait(child);
}

/* Filesize system call. */
static int
sys_filesize (int fd) 
{
	struct file *file = get_file(fd);
	if(file)
		return file_length(file);
	else
		return -1;
}

/* Create system call. */
static bool sys_create(const char *file, unsigned initial_size)
{
	return filesys_create(file, initial_size);
}
 
/* Open system call. */
static int sys_open(const char * file)
{
	char *copy = copy_in_string(file);

	if(!copy)
	{
		sys_exit(-1);
	}

	struct file *f = filesys_open(copy);
	if(!f)
	{
		return -1;
	}
	
	f->fd = ++newfd;
	struct thread *curr = thread_current();
	list_push_back(&curr->file_list, &f->file_elem);
	return f->fd;	
}

/* Read system call. */
static int sys_read (int fd, void *buffer, unsigned size)
{
	uint8_t *mybuffer = buffer;
	if(size <= 0)
	  return 0;
	else if(fd == STDIN_FILENO){
		int i = 0;
		for(; i != size; ++i)
			mybuffer[i] = input_getc();
		return size;
	}
	else {
		struct file *f = get_file(fd);
		if(!f) //file doesn't exist
		{
			return -1;
		}
		return file_read(f, buffer, size);
	}
}

/* Write system call. */
static int
sys_write (int fd, void *usrc_, unsigned size) 
{  
	if(size <= 0)
	  return 0;
	else if(fd == STDOUT_FILENO){
		putbuf(usrc_, size);
		return size;
	}
	else {
		struct file *f = get_file(fd);
		if(!f) //file doesn't exist
		{
			return -1;
		}
		return file_write(f, usrc_, size);
	}


}
 
/* Tell system call. */
static int
sys_tell (int fd) 
{
  struct file *file = get_file(fd);
  if (fd == NULL){
	  sys_exit(-1);
  }
  return file_tell(file);
}
 
/* Close system call. */
static void 
sys_close (int fd) 
{
  struct file *file = get_file(fd);

  if(file)
	  file_close(file);
  else
	  return;
}
 
struct file* get_file(int fd)
{
	struct thread* curr = thread_current();
	struct list_elem *e = list_begin(&curr->file_list);
	while(e != list_end(&curr->file_list) )
	{
		struct file *f =  list_entry(e, struct file, file_elem);
		if(f->fd == fd)
			return f;
		e = list_next(e);
		}
		return NULL;
}
