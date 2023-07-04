#include "PEFile.h"

int INITPARSE(FILE* PpeFile) 
{
	_IMAGE_DOS_HEADER TMP_DOS_HEADER;
	uint16_t PEFile_type;

	fseek(PpeFile, 0, SEEK_SET);
	fread(&TMP_DOS_HEADER, sizeof(_IMAGE_DOS_HEADER), 1, PpeFile);

	if (TMP_DOS_HEADER.e_magic != IMAGE_DOS_SIGNATURE)
		return 1;

	fseek(PpeFile, (TMP_DOS_HEADER.e_lfanew + sizeof(uint32_t) + sizeof(_IMAGE_FILE_HEADER)), SEEK_SET);
	fread(&PEFile_type, sizeof(uint16_t), 1, PpeFile);

	if (PEFile_type == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return 32;
	if (PEFile_type == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 64;
}