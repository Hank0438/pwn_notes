// ROPWN.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "pch.h"
#include <iostream>
#include <windows.h>
#include <stdio.h>
#include <io.h>
#include <stdlib.h>

void read_input(char *buf, unsigned int size) {
	HANDLE hStdin;
	hStdin = GetStdHandle(STD_INPUT_HANDLE);
	BOOL ret;
	DWORD rw;
	ret = ReadFile(hStdin,buf,size,&rw,NULL);
	if (!ret) {
		puts("read error");
		_exit(1);
	}
};

int main()
{
	char buf[0x20];
	memset(buf, 0, 0x20);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stdout, NULL, _IONBF, 0);
	puts("========== ROPWN ==========");
	printf("magic:0x%p\n", &main);
	printf("Input:");
	read_input(buf,0x100);

}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
