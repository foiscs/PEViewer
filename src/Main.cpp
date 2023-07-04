#pragma warning(disable:4996)

#include "PE_Structure.h"
#include "PEFile.h"

#include <iostream>
#include <fstream>
#include <conio.h>

void PrintHxD(FILE* FileName, long Size)
{
	for (int i = 0; i < 16; i++)
	{
		printf(" %02X", i);
	}
	printf("\n\n");
	fseek(FileName, 0, SEEK_SET);
	for (int j = 0; j < 500; j++)
	{
		BYTE temp;
		fread(&temp, sizeof(BYTE), 1, FileName);

		if (j != 0 && j % 16 == 0)
		{
			printf("\n");
		}
		printf(" %02X", temp);
		
	}
}

int main(int argc, char* argv[])
{
	int i = 0;
	char* filename = argv[1];
	FILE* file = fopen(filename, "rb");
	long size = 0;
	char* data;

	if (file == NULL)
	{
		fprintf(stderr, "[ERROR] Failed to open file.\n");
		return EXIT_FAILURE;
	}
	else
		printf("File open\n");

	fseek(file, 0, SEEK_END);
	size = ftell(file);			//get file byte size 
	rewind(file);				//reset read pointer
	
	data = (char*)malloc(size * sizeof(char));

	if (data == NULL)
	{
		fprintf(stderr, "[ERROR] Failed to allocate memory.\n");
		return EXIT_FAILURE;
	}
	// allocate memory check

	int bytes_read = fread(data, sizeof(char), size, file);
	if (bytes_read < size)
		fprintf(stderr, "[ERROR] Failed to read file.\n");
	// same byte check

	// http://www.phreedom.org/research/tinype/
	// Smallest possible PE file
	int resultParser = INITPARSE(file);
	if (size <= 133 || resultParser == 1)
	{
		fprintf(stderr, "[ERROR] Not a valid PE file.\n");
		return EXIT_SUCCESS;
	}
	else if (resultParser == 32)
	{

	}
	else if (resultParser == 64)
	{
		PE64 PE64File(filename, file);
		PE64File.PrintInfo();
		fclose(file);
	}
	
	//PrintHxD(file, size);

	_getch();

	return 0;
}