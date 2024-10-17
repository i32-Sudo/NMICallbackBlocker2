# NMICallbackBlocker2
This is a POC Test project for INTEL CPUs on blocking NMI Entries through the IDT Handler.

```cpp
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
```
