#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static struct lock files_sys_lock;               /* lock for syschronization between files */

static void syscall_handler (struct intr_frame *);

struct open_file* get_file(int fd);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");

  lock_init(&files_sys_lock);
}

static void
syscall_handler (struct intr_frame *f) 
{ 
  validate_void_ptr(f->esp);

  switch (*(int*)f->esp)
  {
  case SYS_HALT:
    shutdown_power_off();
    break;
  
  case SYS_EXIT:
    validate_void_ptr(f->esp+4);
    int status = *((int*)f->esp + 1);
    sys_exit(status);

    break;

  case SYS_EXEC:
    validate_void_ptr(f->esp+4);
    char* cmdName = (char*)(*((int*)f->esp + 1));

    if (cmdName == NULL) sys_exit(-1);
    lock_acquire(&files_sys_lock);
    f->eax = process_execute(cmdName);
    lock_release(&files_sys_lock);
    break;

 case SYS_WAIT:
    validate_void_ptr(f->esp+4);
    int tid = *((int*)f->esp + 1);
    f->eax = process_wait(tid);
    break;

  case SYS_CREATE:
      validate_void_ptr(f->esp + 4);
      validate_void_ptr(f->esp + 8);

      char* name = (char*)(*((int*)f->esp + 1));
      size_t size = *((int*)f->esp + 2);

      if (name == NULL) sys_exit(-1);

      lock_acquire(&files_sys_lock);
      f->eax = filesys_create(name,size);
      lock_release(&files_sys_lock);

    break;

  case SYS_REMOVE:
      validate_void_ptr(f->esp + 4);

      char* rem_name = (char*)(*((int*)f->esp + 1));

      if (rem_name == NULL) sys_exit(-1);

        lock_acquire(&files_sys_lock);

  f->eax = filesys_remove(rem_name);

  lock_release(&files_sys_lock);

    break;

  case SYS_OPEN:
    validate_void_ptr(f->esp + 4);

    char* open_name = (char*)(*((int*)f->esp + 1));

    if (open_name == NULL) sys_exit(-1);

      struct open_file* open = palloc_get_page(0);
      if (open == NULL) 
      {
        palloc_free_page(open);
        return -1;
      }
      lock_acquire(&files_sys_lock);
      open->ptr = filesys_open(name);
      lock_release(&files_sys_lock);
      if (open->ptr == NULL)
      {
        f->eax = -1;
      }
      open->fd = ++thread_current()->fd_last;
      list_push_back(&thread_current()->open_file_list,&open->elem);
      f->eax = open->fd;

    break;

  case SYS_FILESIZE:
    validate_void_ptr(f->esp + 4);
    int fd = *((int*)f->esp + 1);

    struct thread* t = thread_current();
    struct file* my_file = get_file(fd)->ptr;

    if (my_file == NULL)
    {
      f->eax = -1;
    }
    int res;
    lock_acquire(&files_sys_lock);
    res = file_length(my_file);
    lock_release(&files_sys_lock);
    f->eax =  res;

    break;

  case SYS_READ:
    validate_void_ptr(f->esp + 4);
    validate_void_ptr(f->esp + 8);
    validate_void_ptr(f->esp + 12);

    int fd_read, size_read;
    void* buffer;
    fd_read = *((int*)f->esp + 1);
    buffer = (void*)(*((int*)f->esp + 2));
    size_read = *((int*)f->esp + 3);

    validate_void_ptr(buffer + size_read);

      if (fd_read == 0)
  {
    
    for (size_t i = 0; i < size_read; i++)
    {
      lock_acquire(&files_sys_lock);
      ((char*)buffer)[i] = input_getc();
      lock_release(&files_sys_lock);
    }
    f->eax = size_read;
    
  } else {
    struct thread* t = thread_current();
    struct file* my_file = get_file(fd_read)->ptr;

    if (my_file == NULL)
    {
      f->eax = -1;
    }
    int res;
    lock_acquire(&files_sys_lock);
    res = file_read(my_file,buffer,size);
    lock_release(&files_sys_lock);
    f->eax = res;
    
  }
    
    break;

  case SYS_WRITE:

    validate_void_ptr(f->esp + 4);
    validate_void_ptr(f->esp + 8);
    validate_void_ptr(f->esp + 12);

    int fd_write, size_write;
    void* write_buffer;
    fd_write = *((int*)f->esp + 1);
    write_buffer = (void*)(*((int*)f->esp + 2));
    size_write = *((int*)f->esp + 3);

    if (write_buffer == NULL) sys_exit(-1);

      if (fd_write == 1)
  {
    
    lock_acquire(&files_sys_lock);
    putbuf(write_buffer,size_write);
    lock_release(&files_sys_lock);
    f->eax = size_write;

  } else {
    
    struct thread* t = thread_current();
    struct file* my_file = get_file(fd_write)->ptr;

    if (my_file == NULL)
    {
      f->eax = -1;
    }
    int res;
    lock_acquire(&files_sys_lock);
    res = file_write(my_file,write_buffer,size_write);
    lock_release(&files_sys_lock);
    f->eax = res;
  }
    
    break;

  case SYS_SEEK:


  validate_void_ptr(f->esp + 4);
  validate_void_ptr(f->esp + 8);

  int fd_seek;
  unsigned pos;
  fd_seek = *((int*)f->esp + 1);
  pos = *((unsigned*)f->esp + 2);

  
  struct thread* tc = thread_current();
  struct file* my_file_seek = get_file(fd_seek)->ptr;

  if (my_file_seek == NULL)
  {
    return;
  }

  lock_acquire(&files_sys_lock);
  file_seek(my_file_seek,pos);
  lock_release(&files_sys_lock);

    break;

  case SYS_TELL:

    validate_void_ptr(f->esp + 4);
    int fd_tell = *((int*)f->esp + 1);

    struct thread* t_c = thread_current();
    struct file* my_file_tell = get_file(fd_tell)->ptr;

    if (my_file_tell == NULL)
    {
      f->eax = -1;
    }

    unsigned res_tell;
    lock_acquire(&files_sys_lock);
    res_tell = file_tell(my_file_tell);
    lock_release(&files_sys_lock);
    f->eax = res;

    break;

  case SYS_CLOSE:
    validate_void_ptr(f->esp + 4);
    int fd_close = *((int*)f->esp + 1);
    struct thread* t_curr = thread_current();
    struct open_file* my_file_close = get_file(fd);

    if (my_file_close == NULL)
    {
      return;
    }

    lock_acquire(&files_sys_lock);
    file_close(my_file_close->ptr);
    lock_release(&files_sys_lock);
    list_remove(&my_file_close->elem);
    palloc_free_page(my_file_close);
    break;

  default:
    break;
  }

}

void 
validate_void_ptr(const void* pt)
{
  if (pt == NULL || !is_user_vaddr(pt) || pagedir_get_page(thread_current()->pagedir, pt) == NULL) 
  {
    sys_exit(-1);
  }
}

void
sys_exit(int status)
{
  struct thread* parent = thread_current()->parent_thread;
  printf("%s: exit(%d)\n", thread_current()->name, status);
  if(parent) parent->child_status = status;
  thread_exit();
}


struct open_file* get_file(int fd){
    struct thread* t = thread_current();
    struct file* my_file = NULL;
    for (struct list_elem* e = list_begin (&t->open_file_list); e != list_end (&t->open_file_list);
    e = list_next (e))
    {
      struct open_file* opened_file = list_entry (e, struct open_file, elem);
      if (opened_file->fd == fd)
      {
        return opened_file;
      }
    }
    return NULL;
}