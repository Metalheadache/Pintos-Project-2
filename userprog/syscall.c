#include "userprog/syscall.h"
#include "userprog/pagedir.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <stdlib.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/block.h"

typedef int pid_t;

struct file_descriptor
{
  int fd;
  struct file *file;
  struct list_elem elem;

};

// struct list open_list;

static struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);

// helper
bool is_valid_ptr(const void *ptr);
bool is_valid_filename(const void *file);

static void halt(void);

static pid_t exec(const char *cmd_line);
static int wait(pid_t pid);

static bool create(const char *file, unsigned initial_size);
static bool remove(const char *file);

static int open(const char *file);
static void close(int fd);

static filesize(int fd);
static int read(int fd, void *buffer, unsigned size);
static int write(int fd, const void *buffer, unsigned size);

static void seek(int fd, unsigned position);
static unsigned tell(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{
  // printf("%04x\n", f->cs);
  uint32_t *esp = f->esp;
  if (!is_valid_ptr(esp) || !is_valid_ptr(esp + 1) 
    || !is_valid_ptr(esp + 2) || !is_valid_ptr(esp + 3)) 
  {
    exit(-1);
  }

  uint32_t syscall_num = *esp;
  // printf("System call : %d\n", syscall_num);
  // printf("System call : %x\n", esp);
  // printf("argv number : %d\n", *(esp + 5));
  // hex_dump(esp, esp, 64, true);
  switch (syscall_num) 
  {
  	case SYS_HALT:
      halt();
  		break;
  	case SYS_EXIT:
      exit(*(esp + 1));
  		break;
  	case SYS_EXEC:
      f->eax = exec((char *)*(esp + 1));
  		break;
  	case SYS_WAIT:
      f->eax = wait(*(esp + 1));
  		break;
  	case SYS_CREATE:
      f->eax = create((char *)*(esp + 1), *(esp + 2));
  		break;
  	case SYS_REMOVE:
      f->eax = remove((char *)*(esp + 1));
  		break;
  	case SYS_OPEN:
      f->eax = open((char *)*(esp + 1));
  		break;
  	case SYS_FILESIZE:
      f->eax = filesize(*(esp + 1));
  		break;
  	case SYS_READ:
      f->eax = read(*(esp + 1), (void *)*(esp + 2), *(esp + 3));
  		break;
  	case SYS_WRITE:
  		f->eax = write(*(esp + 1), (void *)*(esp + 2), *(esp + 3));
  		break;
  	case SYS_SEEK:
      seek(*(esp + 1), *(esp + 2));
  		break;
  	case SYS_TELL:
      f->eax = tell(*(esp + 1));
  		break;
  	case SYS_CLOSE:
      close(*(esp + 1));
  		break; 
  	default:
  		break; 		  	
  }
  // thread_exit ();
  // hex_dump(f->eip, f->eip, 64, true);
}


bool 
is_valid_ptr(const void *ptr) 
{
  struct thread *t = thread_current();
  if (ptr == NULL || !is_user_vaddr(ptr))
    return false;
  if (pagedir_get_page(t->pagedir, ptr) == NULL)
    return false;
  return true;
}

bool 
is_valid_filename(const void *file)
{
  if (!is_valid_ptr(file)) 
  {
    exit(-1);
  }

  int len = strlen(file);
  return len > 0 && len <= 14;
}

struct file_descriptor *
get_openfile(int fd)
{
  struct list *list = &thread_current()->open_fd;
  for (struct list_elem *e = list_begin (list); 
                          e != list_end (list); 
                          e = list_next (e))
  {
    struct file_descriptor *f = 
        list_entry(e, struct file_descriptor, elem);
    if (f->fd == fd)
      return f;
    else if (f->fd > fd)
      return NULL;
  }
  return NULL;
}

void 
close_openfile(int fd)
{
  struct list *list = &thread_current()->open_fd;
  for (struct list_elem *e = list_begin (list); 
                          e != list_end (list); 
                          e = list_next (e))
  {
    struct file_descriptor *f = 
        list_entry(e, struct file_descriptor, elem);
    if (f->fd == fd)
    { 
      list_remove(e);
      file_close(f->file);
      free(f);
      return;
    }
    else if (f->fd > fd)
      return ;
  }
  return ;
}

static void 
halt(void) 
{
  shutdown_power_off();
}

void 
exit(int status)
{
  struct thread *cur = thread_current();
  printf("%s: exit(%d)\n", cur->name, status);
  if (cur->parent != NULL)
  {
    cur->parent->child_exit_status = status;
    // printf("parent %s: child_exit(%d)\n", cur->parent->name, cur->parent->child_exit_status);
  }

  // mmb -- the key to multi-oom
  while (!list_empty(&cur->open_fd)) 
  {
    close(list_entry(list_begin(&cur->open_fd), struct file_descriptor, elem)->fd);  
  }

  thread_exit();
}

static pid_t 
exec(const char *cmd_line)
{  

  // printf("exec %s\n", cmd_line);

  if (cmd_line == NULL || !is_valid_ptr(cmd_line))
    exit(-1);

  for (char *p = cmd_line; *p != '\0'; p++)
    if (!is_valid_ptr(p + 1))
      exit(-1);

  lock_acquire(&filesys_lock);
  tid_t tid = process_execute(cmd_line);
  lock_release(&filesys_lock);
  
  return tid;
}

static int 
wait(pid_t pid)
{
  return process_wait(pid);
}

static bool 
create(const char *file, unsigned initial_size)
{
  if (!is_valid_filename(file))
    return false;

  lock_acquire(&filesys_lock);
  // status = filesys_create(file, initial_size);
  // status goes wrong !!! I don't know why ... 

  block_sector_t inode_sector = 0;
  struct dir *dir = dir_open_root ();
  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size)
                  && dir_add (dir, file, inode_sector));
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  lock_release(&filesys_lock);

  return success;
}

static bool 
remove(const char *file)
{
  if (!is_valid_filename(file))
    return false;

  bool status;

  lock_acquire(&filesys_lock);
  status = filesys_remove(file);
  lock_release(&filesys_lock);

  return status;
}

int 
assign_fd() 
{
  struct list *list = &thread_current()->open_fd;
  if (list_empty(list)) 
    return 2; 
  else
  {
    struct file_descriptor *f = 
        list_entry(list_back(list), struct file_descriptor, elem);
    // printf("fd : %d\n", f->fd);
        // assume there are sufficient fd space
    return f->fd + 1;
  }
}

bool 
cmp_fd(const struct list_elem *a, const struct list_elem *b, void *aux)
{
  struct file_descriptor *left = list_entry(a, struct file_descriptor, elem);
  struct file_descriptor *right = list_entry(b, struct file_descriptor, elem);
  return left->fd < right->fd;
}

static int 
open(const char *file)
{
  // printf("hahaha\n");
  int fd = -1;

  if (!is_valid_filename(file))
    return fd;

  lock_acquire(&filesys_lock);
  struct list *list = &thread_current()->open_fd;
  struct file *file_struct = filesys_open(file);
  if (file_struct != NULL) 
  {
    struct file_descriptor *tmp = malloc(sizeof(struct file_descriptor));    
    tmp->fd = assign_fd();
    tmp->file = file_struct;
    // tmp->tid = thread_current()->tid;
    fd = tmp->fd;
    list_insert_ordered(list, &tmp->elem, (list_less_func *)cmp_fd, NULL);
  }
  lock_release(&filesys_lock);

  // printf("open %d\n", fd);
  return fd;
}

static void 
close(int fd)
{
  lock_acquire(&filesys_lock);
  close_openfile(fd);
  lock_release(&filesys_lock);

}

static int
filesize(int fd)
{
  int size = -1;

  lock_acquire(&filesys_lock);
  struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      size = file_length(file_descriptor->file);

  lock_release(&filesys_lock);
  
  return size;
}

static int 
read(int fd, void *buffer, unsigned size)
{
  // printf("reading\n");
  int status = -1;

  if (buffer == NULL || !is_valid_ptr(buffer) || !is_valid_ptr(buffer + size - 1)) 
    exit(-1);

  lock_acquire(&filesys_lock);
  if (fd == STDIN_FILENO)
  {
    uint8_t *p = buffer;
    uint8_t c;
    unsigned counter = 0;
    while (counter < size && (c = input_getc()) != 0)
    {
      *p = c;
      p++;
      counter++;
    }
    *p = 0;
    status = size - counter;

  } else if (fd != STDOUT_FILENO)
  { 
    struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      status = file_read(file_descriptor->file, buffer, size);
  }

  lock_release(&filesys_lock);

  // printf("read %d\n", fd);
  return status;
}

static int
write(int fd, const void *buffer, unsigned size) 
{
  int status = 0;

  if (buffer == NULL || !is_valid_ptr(buffer) || !is_valid_ptr(buffer + size - 1)) 
    exit(-1);

  lock_acquire(&filesys_lock);
	if (fd == STDOUT_FILENO)
	{
		putbuf(buffer, size);
		// hex_dump(buffer, buffer, 64, true);
		status = size;
	} else if (fd != STDIN_FILENO)
  {
    struct file_descriptor *file_descriptor = get_openfile(fd);
    // printf("file %d\n", file_descriptor->file->deny_write);
    if (file_descriptor != NULL)
      status = file_write(file_descriptor->file, buffer, size);
  }

  lock_release(&filesys_lock);

  // printf("write %d %d\n", fd, status);
  return status;
}

static void 
seek(int fd, unsigned position)
{
  lock_acquire(&filesys_lock);
  struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      file_seek(file_descriptor->file, position);
  lock_release(&filesys_lock);

  return ;
}

static unsigned 
tell(int fd)
{
  int status = -1;

  lock_acquire(&filesys_lock);

  struct file_descriptor *file_descriptor = get_openfile(fd);
    if (file_descriptor != NULL)
      status = file_tell(file_descriptor->file);

  lock_release(&filesys_lock);

  return status;
}