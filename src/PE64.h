#pragma once

#include "PE_Structure.h"
#include <string>

class PE64
{
public:
	PE64(char* _Name, FILE* _peFile);
	
	void PrintInfo();

private:
	char* Name;
	FILE* peFile;

	//Headers
	_IMAGE_DOS_HEADER	DosHeader;
	_IMAGE_NT_HEADER64	NTHeader;
	_IMAGE_FILE_HEADER  FileHeader;
	_IMAGE_OPTIONAL_HEADER64 OptionalHeader;

	_IMAGE_DATA_DIRECTORY ExportHeader;
	_IMAGE_DATA_DIRECTORY ImportHeader;
	_IMAGE_DATA_DIRECTORY ResourceHeader;
	_IMAGE_DATA_DIRECTORY ExceptionHeader;
	_IMAGE_DATA_DIRECTORY SecurityHeader;
	_IMAGE_DATA_DIRECTORY RelocationHeader;
	_IMAGE_DATA_DIRECTORY DebugHeader;
	_IMAGE_DATA_DIRECTORY ArchitectureHeader;
	_IMAGE_DATA_DIRECTORY GlobalPTRHeader;
	_IMAGE_DATA_DIRECTORY TLSDirectory;
	_IMAGE_DATA_DIRECTORY ConfigurationDirectory;
	_IMAGE_DATA_DIRECTORY BoundImportDirectory;
	_IMAGE_DATA_DIRECTORY ImportAddressTableDirectory;
	_IMAGE_DATA_DIRECTORY DelayImportDirectory;
	_IMAGE_DATA_DIRECTORY NETMetaDataDirectory;

	PIMAGE_SECTION_HEADER SectionHeders;

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

	void FindSection(DWORD RVA);
};

