#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
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
void syscall_init (void);
struct fileFd
{
    struct list_elem f_elem;
    int fd_val;
    struct file* file_orig;
    char f_name[14];
};

#endif /* userprog/syscall.h */
