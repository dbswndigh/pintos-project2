#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/init.h"
#include "userprog/process.h"
#include "filesys/filesys.h"

struct lock filesys_lock;

static void syscall_handler (struct intr_frame *);
static int get_user(const uint8_t *uaddr);
static bool put_user(uint8_t *udst, uint8_t byte);
int valid_pointer(void* esp, uint8_t num_byte);
int valid_string(void* str);
void halt(void);
void exit(int status);
pid_t wait(pid_t pid);
int write(int fd, const void *buffer, unsigned size);
bool create(const char *file, unsigned initial_size);

static int
get_user(const uint8_t *uaddr)
{
  printf("get_user\n");
  int result;
  if((!is_user_vaddr(uaddr)) || uaddr == NULL || uaddr < (void *) 0x08048000) 
    return -1;
  printf("get_user2\n");
  asm ("movl $1f, %0; movzbl %1, %0; 1:"
    : "=&a" (result) : "m" (*uaddr));
  printf("%d\n",result);
  return result;
}

static bool
put_user(uint8_t *udst, uint8_t byte)
{
  int error_code;
  if(!is_user_vaddr(udst) || udst == NULL) return -1;
  asm ("movl $1f, %0; movb %b2, %1; 1:"
      : "=&a" (error_code), "=m" (*udst) : "r" (byte));
  return error_code != -1;
}

int valid_pointer(void* esp, uint8_t num_byte)
{
  /*.........................................
  printf("valid_pointer\n");
  uint8_t i;
  for(i = 0;i < num_byte;i++)
    if(get_user(((uint8_t *)esp) + i) == -1)
      return 0;
  return 1;
  ..........................................*/
  void *ptr;
  uint8_t i;
  for(i = 0;i < num_byte;i++){
    if(!is_user_vaddr(esp+i) || esp+i == NULL || esp+i < (void *) 0x08048000)
      return 0;
    ptr = pagedir_get_page(thread_current()->pagedir, esp+i);
    if(!ptr)
      return 0;
  }
  return 1;
}

void halt()
{
  power_off();
}

void exit(int status)
{
  struct thread* curr;
  curr = thread_current();
  curr->exit_status = status;
 
  struct list* parent_list = &(curr->parent)->child_list;
  struct list_elem* elem;
  struct child_elem *ce1;
  struct child_elem *ce2;
 
  ce2 = NULL;
  for(elem = list_begin(parent_list); elem != list_end(parent_list); elem=list_next(elem)){
    ce1 = list_entry(elem, struct child_elem, e);
    if(curr->tid == ce1->tid){
      ce2 = ce1;
      ce2->exit_status = status;
      break;
    }
  }
  curr->exit_status = status;
  if(curr->parent->waiting_tid == curr->tid)
  {
    sema_up(&curr->parent->child_lock);
    curr->parent->waiting_tid = -1;
  }
  thread_exit();
}

pid_t exec(const char *cmd_line){
  
  char *fn, *saveptr;
  struct file * f;

  lock_acquire(&filesys_lock);
  
  fn = malloc(strlen(cmd_line)+1);
  strlcpy(fn, cmd_line, strlen(cmd_line)+1);
  fn = strtok_r(fn," ",&saveptr);

  f = filesys_open(fn);

  if(f=NULL){
    lock_release(&filesys_lock);
    return -1;
  }
  
  file_close(f);
  lock_release(&filesys_lock);
  
  return process_execute(cmd_line);
}

pid_t wait(pid_t pid)
{
  return process_wait(pid);
}

bool create(const char *file, unsigned initial_size)
{
  bool success;
  lock_acquire(&filesys_lock);
  success = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return success;
}

bool remove(const char *file)
{
  bool success;
  lock_acquire(&filesys_lock);
  success = filesys_remove(file);
  lock_release(&filesys_lock);
  return success;
}
int open(const char *file)
{
  struct fd_elem *fd1 = malloc(sizeof(*fd1));
  struct thread * curr;
  struct file * f;
  
  lock_acquire(&filesys_lock);
  f = filesys_open(file);
  lock_release(&filesys_lock);
  
  if(f==NULL)
    return -1;
  
  curr = thread_current();
  fd1->fd = curr->fd_count;
  fd1->f = f;
  list_push_back(&curr->fd_list, &fd1->e);
  curr->fd_count ++;
  return fd1->fd;
}

struct fd_elem * find_fd(struct list * l, int fd){
  struct list_elem * elem;
  struct fd_elem * fd1;
  for(elem = list_begin(l); elem != list_end(l); elem = list_next(elem)){
    fd1 = list_entry(elem, struct fd_elem, e);
    if(fd1->fd == fd){
      return fd1;
    }
  }
  return NULL;
}

int filesize(int fd){
  struct fd_elem * fd1;
  int leng;

  fd1 = find_fd(&thread_current()->fd_list,fd);
  if(fd1==NULL)
    return -1;
  else{
    lock_acquire(&filesys_lock);
    leng = file_length(fd1->f);
    lock_release(&filesys_lock);
    return leng;
  }
}

int read(int fd, const void *buffer, unsigned size){
  struct fd_elem * fd1 = NULL;
  int i;
  int readbyte;

  if(fd == 0){
    for(i=0; i<size; i++){
      *((char *)buffer+i)= input_getc();
    }
    return size;
  }
  
  fd1 = find_fd(&thread_current()->fd_list,fd);
  if(fd1 == NULL)
    return -1;
 
  lock_acquire(&filesys_lock);
  readbyte = file_read(fd1->f, buffer, size);
  lock_release(&filesys_lock);
  return readbyte;
}

int write(int fd, const void *buffer, unsigned size)
{
  struct fd_elem * fd1;
  int writebyte;
  
  if(fd == 1)
  {
    putbuf(buffer, size);
    return size;
  }
  
  fd1 = find_fd(&thread_current()->fd_list,fd);
  if(fd1 == NULL)
    return -1;

  lock_acquire(&filesys_lock);
  writebyte = file_write(fd1->f,buffer,size);
  lock_release(&filesys_lock);
  return writebyte;
}

void seek(int fd, unsigned pos){
  struct fd_elem * fd1;

  fd1 = find_fd(&thread_current()->fd_list,fd);
  lock_acquire(&filesys_lock);
  file_seek(fd1->f,pos);
  lock_release(&filesys_lock);
}

unsigned tell(int fd){
  struct fd_elem * fd1;
  unsigned pos; 
  fd1 = find_fd(&thread_current()->fd_list,fd);
  lock_acquire(&filesys_lock);
  pos = file_tell(fd1->f);
  lock_release(&filesys_lock);
  return pos;
}

void close(int fd){
  struct fd_elem * fd1;
  
  fd1 = find_fd(&thread_current()->fd_list,fd);
  if(fd1 != NULL){ 
    file_close(fd1->f);
    list_remove(&fd1->e);
    free(fd1);
  }
  return;
}

void close_all()
{
  struct list *f_list = &thread_current()->fd_list;
  struct fd_elem *f1;
  struct list_elem *elem;

  elem = list_begin(f_list);
  while(elem != list_end(f_list)){
    f1 = list_entry(elem, struct fd_elem, e);
    elem = list_next(elem);
    close(f1->fd);
  }
  file_close(thread_current()->executable);
}

void free_all_child(){
  struct list * c_list = &thread_current()->child_list;
  struct child_elem *ce1;
  struct list_elem *elem1;
  struct list_elem *elem2;

  elem1 = list_begin(c_list);
  while(elem1 != list_end(c_list)){
    ce1 = list_entry(elem1, struct child_elem, e);
    elem2 = list_next(elem1);
    list_remove(elem1);
    elem1 = elem2;
  }
}

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int sys_type;
  int status;
  int fd;
  void *buffer;
  char *str;
  char *file;
  unsigned pos;
  unsigned size;
  unsigned initial_size;
  pid_t pid;
  
  if(valid_pointer(f->esp, 4) == 0){
    exit(-1);
    return;
  }
  
  sys_type = *(int*)f->esp;
  switch(sys_type)
  {
    case SYS_HALT:
      halt();
      break;

    case SYS_EXIT:
      if(valid_pointer((f->esp) + 4, 4)){
        status = *(((int *)f->esp)+1);
        exit(status);
      }
      else
        exit(-1);
      break;
    
    case SYS_EXEC:
      if(valid_pointer(f->esp + 4, 4) && valid_pointer(*(char **)(f->esp + 4), 1)){
        str = *(char **)(f->esp + 4);
        f->eax = exec(str);
      }
      else
        exit(-1);
      break;
    
    case SYS_WAIT:
      if(valid_pointer((f->esp) + 4, 4)){
        pid = *((int *)((f->esp) + 4));
        f->eax = wait(pid);
      }
      else
        exit(-1);
      break;
    
    case SYS_CREATE:
      if(valid_pointer((f->esp) + 4, 4) && valid_pointer(*(char **)(f->esp + 4), 1) && valid_pointer((f->esp) + 8, 4)){
        file = *(char **)(f->esp + 4);
        initial_size = *(int *)(f->esp + 8);
        f->eax = create(file, initial_size);
      }
      else
        exit(-1);
      break;
    
    case SYS_REMOVE:
      if(valid_pointer(f->esp + 4, 4) && valid_pointer(*(char **)(f->esp + 4), 1)){
        file = *(char **)(f->esp + 4);
        f->eax = remove(file);
      }
      else
        exit(-1);
      break;
    
    case SYS_OPEN:
      if(valid_pointer((f->esp) + 4, 4) && valid_pointer(*(char **)(f->esp + 4), 1)){
        file = *(char **)(f->esp + 4);
        f->eax = open(file);
      }
      else
        exit(-1);
      break;
    
    case SYS_FILESIZE:
      if(valid_pointer(f->esp + 4, 4)){
        fd = *(int *)(f->esp + 4);
        f->eax = filesize(fd);
      }
      else
        exit(-1);
      break;
    
    case SYS_READ:
      if(valid_pointer((f->esp) + 4, 12) && valid_pointer(*(char **)(f->esp + 8), 1)){
        fd = *((int *)((f->esp) + 4));
        buffer = *(char**)(f->esp + 8);
        size = *((unsigned *)((f->esp) + 12));
        f->eax = read(fd, buffer, size);
      }
      else
        exit(-1);
      break;

    case SYS_WRITE:
      if(valid_pointer((f->esp) + 4, 12) && valid_pointer(*(char **)(f->esp + 8), 1)){
        fd = *((int *)((f->esp) + 4));
        buffer = *(char**)(f->esp + 8);
        size = *((unsigned *)((f->esp) + 12));
        f->eax = write(fd, buffer, size);
      }
      else
        exit(-1);
      break;

    case SYS_SEEK:
      if(valid_pointer(f->esp + 4, 8)){
        fd = *(int *)(f->esp + 4);
        pos = *(unsigned *)(f->esp + 8);
        seek(fd,pos);
      }
      else
        exit(-1);
      break;
    
    case SYS_TELL:
      if(valid_pointer(f->esp + 4, 4)){
        fd = *(int *)(f->esp + 4);
        f->eax = tell(fd);
      }
      else
        exit(-1);
      break;

    case SYS_CLOSE:
      if(valid_pointer(f->esp + 4, 4)){
        fd = *(int *)(f->esp + 4);
        lock_acquire(&filesys_lock);
        close(fd);
        lock_release(&filesys_lock);
      }
      else
        exit(-1);
      break;
    
    default:
      exit(-1);
  }
}
