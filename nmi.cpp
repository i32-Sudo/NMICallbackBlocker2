
BOOL
CheckMask(
	PCHAR Base,
	PCHAR Pattern,
	PCHAR Mask
) {
	for (; *Mask; ++Base, ++Pattern, ++Mask) {
		if (*Mask == 'x' && *Base != *Pattern) {
			return FALSE;
		}
	}

	return TRUE;
}

PVOID
FindPattern2(
	PCHAR Base,
	DWORD Length,
	PCHAR Pattern,
	PCHAR Mask
) {
	Length -= (DWORD)strlen(Mask);
	for (DWORD i = 0; i <= Length; ++i) {
		PVOID Addr = &Base[i];
		if (CheckMask((PCHAR)Addr, Pattern, Mask)) {
			return Addr;
		}
	}

	return 0;
}

PVOID FindPatternImage(
	PCHAR Base,
	PCHAR Pattern,
	PCHAR Mask
) {
	PVOID Match = 0;

	PIMAGE_NT_HEADERS Headers = (PIMAGE_NT_HEADERS)(Base + ((PIMAGE_DOS_HEADER)Base)->e_lfanew);
	PIMAGE_SECTION_HEADER Sections = IMAGE_FIRST_SECTION(Headers);
	for (DWORD i = 0; i < Headers->FileHeader.NumberOfSections; ++i) {
		PIMAGE_SECTION_HEADER Section = &Sections[i];
		if (*(PINT)Section->Name == 'EGAP' || memcmp(Section->Name, _(".text"), 5) == 0) {
			Match = FindPattern2(Base + Section->VirtualAddress, Section->Misc.VirtualSize, Pattern, Mask);
			if (Match) {
				break;
			}
		}
	}

	return Match;
}

typedef struct _KNMI_HANDLER_CALLBACK
{
	struct _KNMI_HANDLER_CALLBACK* Next;
	void(*Callback)();
	void* Context;
	void* Handle;
} KNMI_HANDLER_CALLBACK, * PKNMI_HANDLER_CALLBACK;

typedef struct _KAFFINITY_EX
{
	USHORT Count;                                                           //0x0
	USHORT Size;                                                            //0x2
	ULONG Reserved;                                                         //0x4
	ULONGLONG Bitmap[20];                                                   //0x8
} KAFFINITY_EX, * PKAFFINITY_EX;

typedef ULONG KEPROCESSORINDEX;
extern "C" NTSYSAPI BOOLEAN  NTAPI KeInterlockedSetProcessorAffinityEx(PKAFFINITY_EX pAffinity, KEPROCESSORINDEX idxProcessor);


QWORD PswResolveRelativeAddress(
	QWORD Instruction,
	DWORD OffsetOffset,
	DWORD InstructionSize
)
{

	QWORD Instr = (QWORD)Instruction;
	INT32 RipOffset = *(INT32*)(Instr + OffsetOffset);
	QWORD ResolvedAddr = (QWORD)(Instr + InstructionSize + RipOffset);
	return ResolvedAddr;
}

void PreventNMIExecution() {
	void* ntoskrnl_base = reinterpret_cast<void*>((uintptr_t)get_ntos_base_address());
	if (ntoskrnl_base == NULL) {
		DbgPrint("[NMI] Failed to get ntoskrnl_base");
	}

	// Perform the pattern scanning to locate nmi_in_progress
	char* pattern = _("\xE8\x00\x00\x00\x00\x83\xCB\xFF\x48\x8B\xD6");
	char* mask = _("x????xxxxxx");

	char* NtoskrnlStr = _("ntoskrnl.exe");

	void* ModuleSig = static_cast<void*>(FindPatternImage((PCHAR)GetKernelModuleBase(NtoskrnlStr), pattern, mask));
	QWORD pattern_idt = reinterpret_cast<QWORD>(ModuleSig);
	// DbgPrint("[NMI] ModuleSig = %p\n", ModuleSig);
	// DbgPrint("[NMI] patternIDT = %p\n", pattern_idt);

	if (pattern_idt != NULL)
	{
		pattern_idt = PswResolveRelativeAddress(pattern_idt, 1, 5);
		pattern_idt = pattern_idt + 0x1a;
		pattern_idt = PswResolveRelativeAddress(pattern_idt, 3, 7);

		*(QWORD*)(pattern_idt + 0x38) = *(QWORD*)(pattern_idt + 0x1A0);
		*(QWORD*)(pattern_idt + 0x40) = *(QWORD*)(pattern_idt + 0x1A8);
		// DbgPrint(_("[NMI] IDT Patched / NMIs Blocked"));
	}
}
