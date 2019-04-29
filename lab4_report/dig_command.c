#include<string.h>
#include<stdio.h>
#include<stdlib.h>
/*
int main(){
	int i=0;
	char random[6];
	FILE *fd  = fopen("E:\WorkSpace\documents\Junior1\Network_Security\labs\shared_file\lab3\16307130271_lab4_NanHailong\m.txt",'w+');
	while(i<10000){
		char command[30]="/f1ag0000.html\n";
		sprintf(random,"%.4d",i);
		command[5]=random[0];
		command[6]=random[1];
		command[7]=random[2];
		command[8]=random[3];
		fputs(command,fd);
		i++;
	}
	fclose(fd);
	return 0;
}
*/
#include <stdio.h>
 
int main()
{
   FILE *fp = NULL;
 
   fp = fopen("/tmp/test.txt", "w+");
   fprintf(fp, "This is testing for fprintf...\n");
   fputs("This is testing for fputs...\n", fp);
   fclose(fp);
} 
