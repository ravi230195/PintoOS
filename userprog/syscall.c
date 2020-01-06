#include "userprog/syscall.h"
#include <stdio.h>
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/shutdown.h"
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include <string.h>
static void syscall_handler (struct intr_frame *);
static struct lock lock_file;
void
syscall_init (void) 
{
 lock_init(&lock_file);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

void check_buffer (void *buff, unsigned size)
{
  int i = 0;
  char *ptr  = (char*)buff;
  while (i < size)
    {
      check_valid_addr((const void *) ptr);
      ptr++;
      i++;
    }
}


void check_valid_addr (const void *ptr)
{
  if(ptr == NULL || !is_user_vaddr(ptr) || ptr < (void *) 0x08048000)
  {
     exit(-1);
  }
}


void exit(int exit_code)
{
  thread_current()->exit_status = exit_code;
  thread_current()->valid =  true;
  printf("%s: exit(%d)\n", thread_current()->name, exit_code);
  struct thread *parent_thread = NULL;
  parent_thread = thread_current()->parent;
  parent_thread->exit_status = exit_code;
  thread_exit();
}

syscall_handler (struct intr_frame *f UNUSED) 
{
  int* p = (int*)f->esp;
  check_valid_addr((const void *) p);
  if (*p == SYS_WRITE)
  {
          int args[3];
          int i = 0;
          int *p;
          while (i < 3)
          {
      		p = (int *) f->esp + i + 1;
      		check_valid_addr((const void *) p);
      		args[i] = *p;
		i++;
          }
          if ((int*)args[1] == NULL)
          {
             exit(-1);
          }
        check_buffer((void *)args[1], (unsigned)args[2]);
        void* phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        if (phys_page_ptr == NULL)
        {
	    exit(-1);
        }
        args[1] = (int) phys_page_ptr;
        if(args[0] == 1)
        {
                lock_acquire(&lock_file);
                putbuf((const void* )args[1], (unsigned)args[2]);
                lock_release(&lock_file);
                f->eax = (unsigned) args[2];
                return;
        }
        if (args[0] == 0)
        {
           f->eax = 0;
           return;
        }
        if (list_empty(&thread_current()->file_list))
        {
                f->eax = 0;
                return;
        }
        lock_acquire(&lock_file);
        struct list_elem *ele =list_front(&thread_current()->file_list);
        struct list_elem *next_element;
        while (ele != list_end(&thread_current()->file_list))
        {
                struct fileFd *ct = list_entry(ele, struct fileFd, f_elem);
                if (ct->fd_val == (int)args[0])
                {
                    f->eax = (int)file_write(ct->file_orig, (const char*)args[1], (unsigned)args[2]);
                    lock_release(&lock_file);
                    return;
                }
                ele = ele->next;
        }
        f->eax = 0;
        lock_release(&lock_file);

   }
   else if (*p == SYS_EXIT)
   {
          int args[1];
          int i = 0;
          int *p;
          while (i < 1)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }

          exit(args[0]);

   }
   else if (*p == SYS_HALT)
   {
      shutdown_power_off();
   }
   else if (*p == SYS_CREATE)
   { 
          int args[2];
          int i = 0;
          int *p;
          while (i < 2)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
        void* phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
            exit(-1);
        }
        args[0] = (int) phys_page_ptr;
        lock_acquire(&lock_file);
        bool s = filesys_create((const char*)args[0], (unsigned)args[1]);
        lock_release(&lock_file);
        f->eax = s;
   }
   else if (*p == SYS_REMOVE)
   {
          int args[1];
          int i = 0;
          int *p;
          while (i < 1)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
        void* phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
            exit(-1);
        }
        args[0] = (int) phys_page_ptr;
        lock_acquire(&lock_file);
        bool s = filesys_remove((const char*)args[0]);
        lock_release(&lock_file);
        f->eax = s;

   }
   else if (*p == SYS_OPEN)
   {
	  int args[1];
          int i = 0;
          int *p;
          while (i < 1)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
        void* phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL)
        {
            exit(-1);
        }
        args[0] = (int) phys_page_ptr;
        lock_acquire(&lock_file);
        struct file* File = filesys_open((const char *)args[0]);
        if (File == NULL)
        {
           lock_release(&lock_file);
           f->eax = -1;
           return ;
        }
        struct fileFd* fl = malloc(sizeof(struct fileFd));
/*        if (strcmp(thread_current()->name, (const char *)args[0]) == 0)
        {
           fl->fd_val = 2;
        }
        else*/
        {
           fl->fd_val = thread_current()->fd;
           thread_current()->fd = thread_current()->fd + 1;
        }
        memcpy(fl->f_name, (const char *)args[0], strlen((const void *) args[0]) + 1);
        fl->file_orig = File;
        list_push_front(&thread_current()->file_list, &fl->f_elem); 
        f->eax = fl->fd_val;
	lock_release(&lock_file);
   }
   else if (*p == SYS_FILESIZE)
   {
         int args[1];
         int i = 0;
         int *p;
         p = (int *) f->esp + i + 1;
         args[0] = *p;
        if (list_empty(&thread_current()->file_list))
        {
		f->eax = -1;
                return;
        }
        lock_acquire(&lock_file);
  	struct list_elem *ele =list_front(&thread_current()->file_list);
	struct list_elem *next_element;
  	while (ele != list_end(&thread_current()->file_list))
    	{
      		struct fileFd *ct = list_entry(ele, struct fileFd, f_elem);
   		if (ct->fd_val == (int)args[0])
                {
                    f->eax = (int)file_length(ct->file_orig);
		    lock_release(&lock_file);
                    return;
                }
      		ele = ele->next;
        }
        f->eax = -1;
        lock_release(&lock_file);

   }
   else if (*p == SYS_READ)
   {
          int args[3];
          int i = 0;
          int *p;
          while (i < 3)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
        check_buffer((void *)args[1], (unsigned)args[2]);
        void* phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[1]);
        if (phys_page_ptr == NULL)
        {
            exit(-1);
        }
        args[1] = (int) phys_page_ptr;
        if (args[0] == 0)
        {
             lock_acquire(&lock_file);
             f->eax =  (int) input_getc();
             lock_release(&lock_file);
             return;
        }
        if (args[0] == 1)
        {

           f->eax = 0;
           return;
        }
        if (list_empty(&thread_current()->file_list))
        {

           f->eax = 0;
           return;
        }
        lock_acquire(&lock_file);
        struct list_elem *ele = list_front(&thread_current()->file_list);
        struct list_elem *next_element;
        while (ele != list_end(&thread_current()->file_list))
        {
                struct fileFd *ct = list_entry(ele, struct fileFd, f_elem);
                if (ct->fd_val == (int)args[0])
                {
                    f->eax = (int)file_read(ct->file_orig, (void*)args[1], (unsigned)args[2]);
                    lock_release(&lock_file);
                    return;
                }
                ele = list_next(ele);
        }
        f->eax = -1;
        lock_release(&lock_file);        

   }
   else if (*p == SYS_CLOSE)
   {
         int args[1];
         int i = 0;
         int *p;
         p = (int *) f->esp + i + 1;
         args[0] = *p;
        if (list_empty(&thread_current()->file_list))
        {
                return;
        }
        lock_acquire(&lock_file);
        struct list_elem *ele =list_front(&thread_current()->file_list);
        struct list_elem *next_element;
        while (ele != list_end(&thread_current()->file_list))
        {
                struct fileFd *ct = list_entry(ele, struct fileFd, f_elem);
                if (ct->fd_val == (int)args[0])
                {
                    file_close(ct->file_orig);
		    list_remove(ele);
                    lock_release(&lock_file);
                    return;
                }
                ele = ele->next;
        }
        lock_release(&lock_file);

   }
   else if(*p == SYS_SEEK)
   {
          int args[2];
          int i = 0;
          int *p;
          while (i < 2)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
        if (list_empty(&thread_current()->file_list))
        {
                return;
        }
        lock_acquire(&lock_file);
        struct list_elem *ele =list_front(&thread_current()->file_list);
        struct list_elem *next_element;
        while (ele != list_end(&thread_current()->file_list))
        {
                struct fileFd *ct = list_entry(ele, struct fileFd, f_elem);
                if (ct->fd_val == (int)args[0])
                {
                    file_seek(ct->file_orig, (unsigned)args[1]);
                    lock_release(&lock_file);
                    return;
                }
                ele = ele->next;
        }
        lock_release(&lock_file);
   }
   else if(*p == SYS_TELL)
   {
          int args[1];
          int i = 0;
          int *p;
          while (i < 1)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
        if (list_empty(&thread_current()->file_list))
        {
		f->eax = -1;
                return;
        }
        lock_acquire(&lock_file);
        struct list_elem *ele =list_front(&thread_current()->file_list);
        struct list_elem *next_element;
        while (ele != list_end(&thread_current()->file_list))
        {
                struct fileFd *ct = list_entry(ele, struct fileFd, f_elem);
                if (ct->fd_val == (int)args[0])
                {
                    f->eax = (int)file_tell(ct->file_orig);
                    lock_release(&lock_file);
                    return;
                }
                ele = ele->next;
        }
        f->eax = -1;
        lock_release(&lock_file);
   }
   else if (*p == SYS_EXEC)
   {
          int args[1];
          int i = 0;
          int *p;
          while (i < 1)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
        void* phys_page_ptr = pagedir_get_page(thread_current()->pagedir, (const void *) args[0]);
        if (phys_page_ptr == NULL )
        {
            exit(-1);
        }
        args[0] = (int) phys_page_ptr;
	char * token = malloc (strlen( (const void *) args[0])+1);
	strlcpy(token,  (const void *) args[0], strlen( (const void *) args[0])+1);
	char * save_ptr;
	token = strtok_r(token," ",&save_ptr);
        struct file* cf = filesys_open(token);
        if (cf == NULL)
        {
 	   f->eax = -1;
	   return ;
	}
        file_close(cf);
        int pid = process_execute((const char*)args[0]);
        f->eax = pid;
   }
   else if (*p == SYS_WAIT)
   {
          int args[1];
          int i = 0;
          int *p;
          while (i < 1)
          {
                p = (int *) f->esp + i + 1;
                check_valid_addr((const void *) p);
                args[i] = *p;
                i++;
          }
          f->eax = process_wait((unsigned)args[0]);
    }

}
