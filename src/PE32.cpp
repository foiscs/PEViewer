#include "PE32.h"

PE32::PE32(char* _Name, FILE* _peFile)
{
	this->Name = _Name;
	this->peFile = _peFile;

	ParserFile();
}

void PE32::PrintInfo()
{
	PrintFileInfo();
	PrintDOSHeader();
	PrintNTHeader();
	PrintSectionHeader();
}

void PE32::ParserFile()
{
	ParserDOSHeader();
	ParserNTHeader();
	ParserSectionHeader();
}

void PE32::ParserDOSHeader()
{
}

void PE32::ParserNTHeader()
{
}

void PE32::ParserSectionHeader()
{
}

void PE32::PrintFileInfo()
{
}

void PE32::PrintDOSHeader()
{
}

void PE32::PrintNTHeader()
{
}

void PE32::PrintSectionHeader()
{
}
