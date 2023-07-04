#pragma once

#include "PE_Structure.h"
#include <string>

class PE32
{
public:
	PE32(char* _Name, FILE* _peFile);

	void PrintInfo();

private:
	char* Name;
	FILE* peFile;

	//Headers
	_IMAGE_DOS_HEADER	imageDosHeader;
	_IMAGE_NT_HEADER	imageNTHeader;

	//Parsers
	void ParserFile();
	void ParserDOSHeader();
	void ParserNTHeader();
	void ParserSectionHeader();

	//Print Info
	void PrintFileInfo();
	void PrintDOSHeader();
	void PrintNTHeader();
	void PrintSectionHeader();

};

