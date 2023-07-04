#include "PE64.h"

PE64::PE64(char* _Name, FILE* _peFile)
{
	this->Name = _Name;
	this->peFile = _peFile;

	ParserFile();
}

void PE64::ParserFile()
{
	ParserDOSHeader();
	ParserNTHeader();
	ParserSectionHeader();
}

void PE64::ParserDOSHeader()
{
	fseek(peFile, 0, SEEK_SET);
	fread(&DosHeader, sizeof(_IMAGE_DOS_HEADER), 1, peFile);
}

void PE64::ParserNTHeader()
{
	fseek(peFile, DosHeader.e_lfanew, SEEK_SET);
	fread(&NTHeader, sizeof(NTHeader), 1, peFile);

	FileHeader = NTHeader.FileHeader;
	OptionalHeader = NTHeader.OptionalHeader;

	ExportHeader = OptionalHeader.DataDirectory[0];
	ImportHeader = OptionalHeader.DataDirectory[1];
	ResourceHeader = OptionalHeader.DataDirectory[2];
	ExceptionHeader = OptionalHeader.DataDirectory[3];
	SecurityHeader = OptionalHeader.DataDirectory[4];
	RelocationHeader = OptionalHeader.DataDirectory[5];
	DebugHeader = OptionalHeader.DataDirectory[6];
	ArchitectureHeader = OptionalHeader.DataDirectory[7];
	GlobalPTRHeader = OptionalHeader.DataDirectory[8];
	TLSDirectory = OptionalHeader.DataDirectory[9];
	ConfigurationDirectory = OptionalHeader.DataDirectory[10];
	BoundImportDirectory = OptionalHeader.DataDirectory[11];
	ImportAddressTableDirectory = OptionalHeader.DataDirectory[12];
	DelayImportDirectory = OptionalHeader.DataDirectory[13];
	NETMetaDataDirectory = OptionalHeader.DataDirectory[14];
}

void PE64::ParserSectionHeader()
{
	SectionHeders = new _IMAGE_SECTION_HEADER[FileHeader.NumberOfSections];
	for (int i = 0; i < FileHeader.NumberOfSections; i++)
	{
		int offset = (DosHeader.e_lfanew + sizeof(NTHeader)) + (i * sizeof(_IMAGE_SECTION_HEADER));
		fseek(peFile, offset, SEEK_SET);
		fread(&SectionHeders[i], sizeof(_IMAGE_SECTION_HEADER), 1, peFile);
	}
}


void PE64::PrintInfo()
{
	PrintFileInfo();
	PrintDOSHeader();
	PrintNTHeader();
	PrintSectionHeader();
}
void PE64::PrintFileInfo()
{
	printf(" FILE : %s\n", Name);
	printf(" TYPE : 0x%X (PE32+)\n", IMAGE_NT_OPTIONAL_HDR64_MAGIC);
}

void PE64::PrintDOSHeader()
{
	printf(" DOS Header : \n");
	printf(" -------------\n");
	printf(" Member		Value\n");
	printf(" e_magic	: 0x%04X\n", DosHeader.e_magic);
	printf(" e_cblp		: 0x%04X\n", DosHeader.e_cblp);
	printf(" e_cp		: 0x%04X\n", DosHeader.e_cp);
	printf(" e_crlc		: 0x%04X\n", DosHeader.e_crlc);
	printf(" e_cparhdr	: 0x%04X\n", DosHeader.e_cparhdr);
	printf(" e_minalloc	: 0x%04X\n", DosHeader.e_minalloc);
	printf(" e_maxalloc	: 0x%04X\n", DosHeader.e_maxalloc);
	printf(" e_ss		: 0x%04X\n", DosHeader.e_ss);
	printf(" e_sp		: 0x%04X\n", DosHeader.e_sp);
	printf(" e_csum		: 0x%04X\n", DosHeader.e_csum);
	printf(" e_ip		: 0x%04X\n", DosHeader.e_ip);
	printf(" e_lfarlc	: 0x%04X\n", DosHeader.e_lfarlc);
	printf(" e_ovno		: 0x%04X\n", DosHeader.e_ovno);
	printf(" e_res		: 0x%04X\n", DosHeader.e_res[0]);
	printf("		: 0x%04X\n", DosHeader.e_res[1]);
	printf("		: 0x%04X\n", DosHeader.e_res[2]);
	printf("		: 0x%04X\n", DosHeader.e_res[3]);
	printf(" e_oemid	: 0x%04X\n", DosHeader.e_oemid);
	printf(" e_oeminfo	: 0x%04X\n", DosHeader.e_oeminfo);
	printf(" e_res2		: 0x%04X\n", DosHeader.e_res2[0]);
	printf("		: 0x%04X\n", DosHeader.e_res2[1]);
	printf("		: 0x%04X\n", DosHeader.e_res2[2]);
	printf("		: 0x%04X\n", DosHeader.e_res2[3]);
	printf("		: 0x%04X\n", DosHeader.e_res2[4]);
	printf("		: 0x%04X\n", DosHeader.e_res2[5]);
	printf("		: 0x%04X\n", DosHeader.e_res2[6]);
	printf("		: 0x%04X\n", DosHeader.e_res2[7]);
	printf("		: 0x%04X\n", DosHeader.e_res2[8]);
	printf("		: 0x%04X\n", DosHeader.e_res2[9]);
	printf(" e_lfanew	: 0x%08X\n", DosHeader.e_lfanew);


	printf(" e_lfanew Value => NT Header Start Address\n\n");
}

void PE64::PrintNTHeader()
{
	printf(" NT Header : \n");
	printf(" -------------\n");
	printf(" Member		Value\n");
	printf(" Signature	: 0x%08X\n\n", NTHeader.Signature);

	printf(" File Header : \n");
	printf(" -------------\n");
	printf(" Machine		: 0x%04X\n", FileHeader.Machine);
	printf(" NumberOfSections	: 0x%04X\n", FileHeader.NumberOfSections);
	printf(" TimeDateStamp		: 0x%08X\n", FileHeader.TimeDateStamp);
	printf(" PointerToSymbolTable	: 0x%08X\n", FileHeader.PointerToSymbolTable);
	printf(" NumberOfSymbols	: 0x%08X\n", FileHeader.NumberOfSymbols);
	printf(" SizeOfOptionalHeader	: 0x%04X\n", FileHeader.SizeOfOptionalHeader);
	printf(" Characteristics	: 0x%04X\n\n", FileHeader.Characteristics);

	printf(" Optional Header : \n");
	printf(" Magic				: 0x%04X\n", OptionalHeader.Magic);
	printf(" MajorLinkerVersion		: 0x%02X\n", OptionalHeader.MajorLinkerVersion);
	printf(" MinorLinkerVersion		: 0x%02X\n", OptionalHeader.MinorLinkerVersion);
	printf(" SizeOfCode			: 0x%08X\n", OptionalHeader.SizeOfCode);
	printf(" SizeOfInitializedData		: 0x%08X\n", OptionalHeader.SizeOfInitializedData);
	printf(" SizeOfUninitializedData	: 0x%08X\n", OptionalHeader.SizeOfUninitializedData);
	printf(" AddressOfEntryPoint		: 0x%08X\n", OptionalHeader.AddressOfEntryPoint);
	printf(" BaseOfCode			: 0x%08X\n", OptionalHeader.BaseOfCode);
	printf(" ImageBase			: 0x%016X\n", OptionalHeader.ImageBase);
	printf(" SectionAlignment		: 0x%08X\n", OptionalHeader.SectionAlignment);
	printf(" FileAlignment			: 0x%08X\n", OptionalHeader.FileAlignment);
	printf(" MajorOperatingSystemVersion	: 0x%04X\n", OptionalHeader.MajorOperatingSystemVersion);
	printf(" MinorOperatingSystemVersion	: 0x%04X\n", OptionalHeader.MinorOperatingSystemVersion);
	printf(" MajorImageVersion		: 0x%04X\n", OptionalHeader.MajorImageVersion);
	printf(" MinorImageVersion		: 0x%04X\n", OptionalHeader.MinorImageVersion);
	printf(" MajorSubsystemVersion		: 0x%04X\n", OptionalHeader.MajorSubsystemVersion);
	printf(" MinorSubsystemVersion		: 0x%04X\n", OptionalHeader.MinorSubsystemVersion);
	printf(" Win32VersionValue		: 0x%08X\n", OptionalHeader.Win32VersionValue);
	printf(" SizeOfImage			: 0x%08X\n", OptionalHeader.SizeOfImage);
	printf(" SizeOfHeaders			: 0x%08X\n", OptionalHeader.SizeOfHeaders);
	printf(" CheckSum			: 0x%08X\n", OptionalHeader.CheckSum);
	printf(" Subsystem			: 0x%04X\n", OptionalHeader.Subsystem);
	printf(" DllCharacteristics		: 0x%04X\n", OptionalHeader.DllCharacteristics);
	printf(" SizeOfStackReserve		: 0x%016X\n", OptionalHeader.SizeOfStackReserve);
	printf(" SizeOfStackCommit		: 0x%016X\n", OptionalHeader.SizeOfStackCommit);
	printf(" SizeOfHeapReserve		: 0x%016X\n", OptionalHeader.SizeOfHeapReserve);
	printf(" SizeOfHeapCommit		: 0x%016X\n", OptionalHeader.SizeOfHeapCommit);
	printf(" LoaderFlags			: 0x%08X\n", OptionalHeader.LoaderFlags);
	printf(" NumberOfRvaAndSizes		: 0x%08X\n\n", OptionalHeader.NumberOfRvaAndSizes);

	printf(" DATA Directories:\n");
	printf("\n   * Export Directory:\n");
	printf("       RVA	: 0x%08X\n", ExportHeader.RVA);
	printf("       Size	: 0x%08X\n", ExportHeader.Size);
	FindSection(ExportHeader.RVA);

	printf("\n   * Import Directory:\n");
	printf("       RVA	: 0x%08X\n", ImportHeader.RVA);
	printf("       Size	: 0x%08X\n", ImportHeader.Size);
	FindSection(ImportHeader.RVA);

	printf("\n   * Resource Directory:\n");
	printf("       RVA	: 0x%08X\n", ResourceHeader.RVA);
	printf("       Size	: 0x%08X\n", ResourceHeader.Size);
	FindSection(ResourceHeader.RVA);


	printf("\n   * Exception Directory:\n");
	printf("       RVA	: 0x%08X\n", ExceptionHeader.RVA);
	printf("       Size	: 0x%08X\n", ExceptionHeader.Size);
	FindSection(ExceptionHeader.RVA);

	printf("\n   * Relocation Directory:\n");
	printf("       RVA	: 0x%08X\n", RelocationHeader.RVA);
	printf("       Size	: 0x%08X\n", RelocationHeader.Size);
	FindSection(RelocationHeader.RVA);

	printf("\n   * Debug Directory:\n");
	printf("       RVA	: 0x%08X\n", DebugHeader.RVA);
	printf("       Size	: 0x%08X\n", DebugHeader.Size);
	FindSection(DebugHeader.RVA);

}

void PE64::PrintSectionHeader()
{
	printf("\n Section Headders:\n");
	printf(" ----------------\n\n");

	for (int i = 0; i < FileHeader.NumberOfSections; i++)
	{
		printf("   * %.8s:\n", SectionHeders[i].Name);
		printf("        VirtualAddress:		0x%X\n", SectionHeders[i].VirtualAddress);
		printf("        VirtualSize:		0x%X\n", SectionHeders[i].VirtualSize);
		printf("        PointerToRawData:	0x%X\n", SectionHeders[i].PointerToRawData);
		printf("        SizeOfRawData:		0x%X\n", SectionHeders[i].SizeOfRawData);
		printf("        Characteristics:	0x%X\n\n", SectionHeders[i].Characteristics);
	}
}

void PE64::FindSection(DWORD RVA)
{
	BYTE tempName[8];
	for (int i = 0; i < FileHeader.NumberOfSections; i++)
	{
		if (RVA >= SectionHeders[i].VirtualAddress)
			memcpy(tempName, SectionHeders[i].Name, sizeof(QWORD));
	}
	printf("       Section : %.8s:\n ", tempName);
}
