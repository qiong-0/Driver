#include "Y.h"

VOID DriverUnload(PDRIVER_OBJECT DriverObject)
{
	UNICODE_STRING symLinkName = { 0 };
	RtlInitUnicodeString(&symLinkName, SYM_NAME);
	IoDeleteSymbolicLink(&symLinkName);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DispatchCreate(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DispatchClose(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS ReadMemory(IN ULONG Pid, IN  PVOID Address, IN ULONG Size, OUT PVOID Buffer)
{
	RtlZeroMemory(Buffer, Size);
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };
	Status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);
	if (!NT_SUCCESS(Status))
	{
		return STATUS_UNSUCCESSFUL;
	}
	ObDereferenceObject(pEProcess);
	KeStackAttachProcess(pEProcess, &ApcState);
	PMDL Mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (1)
	{
		IoFreeMdl(Mdl);
		KeUnstackDetachProcess(&ApcState);
		return STATUS_UNSUCCESSFUL;
	}
	PVOID Map = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
	if (!Map)
	{
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
		KeUnstackDetachProcess(&ApcState);
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(Buffer, Map, Size);
	MmUnmapLockedPages(Map, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
	KeUnstackDetachProcess(&ApcState);
	return Status;
}

NTSTATUS WriteMemory(IN ULONG Pid, IN  PVOID Address, IN ULONG Size, OUT PVOID Buffer)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };
	Status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);
	if (!NT_SUCCESS(Status))
	{
		return STATUS_UNSUCCESSFUL;
	}
	ObDereferenceObject(pEProcess);
	KeStackAttachProcess(pEProcess, &ApcState);
	PMDL Mdl = IoAllocateMdl(Address, Size, FALSE, FALSE, NULL);
	__try
	{
		MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	}
	__except (1)
	{
		IoFreeMdl(Mdl);
		KeUnstackDetachProcess(&ApcState);
		return STATUS_UNSUCCESSFUL;
	}
	PVOID Map = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmCached, NULL, FALSE, HighPagePriority);
	if (!Map)
	{
		MmUnlockPages(Mdl);
		IoFreeMdl(Mdl);
		KeUnstackDetachProcess(&ApcState);
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(Map, Buffer, Size);
	MmUnmapLockedPages(Map, Mdl);
	MmUnlockPages(Mdl);
	IoFreeMdl(Mdl);
	KeUnstackDetachProcess(&ApcState);
	return Status;
}

ULONG64 GetProcessModuleBase(IN ULONG Pid, IN UNICODE_STRING ModuleName)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PEPROCESS pEProcess = NULL;
	KAPC_STATE ApcState = { 0 };
	ULONG64 BaseAddress = 0;
	Status = PsLookupProcessByProcessId((HANDLE)Pid, &pEProcess);
	if (!NT_SUCCESS(Status))
	{
		return 0;
	}
	ObDereferenceObject(pEProcess);
	KeStackAttachProcess(pEProcess, &ApcState);
	PPEB32 PEB32 = PsGetProcessWow64Process(pEProcess);
	if (PEB32 != NULL)
	{
		PLIST_ENTRY32 Start32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)PEB32->Ldr)->InMemoryOrderModuleList.Flink);
		PLIST_ENTRY32 End32 = Start32;
		do
		{
			PLDR_DATA_TABLE_ENTRY32 pLdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(Start32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);
			UNICODE_STRING QueryModuleName = { 0 };
			RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry32->BaseDllName.Buffer);
			if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
			{
				BaseAddress = (ULONG64)pLdrDataEntry32->DllBase;
				break;
			}
			Start32 = (PLIST_ENTRY32)Start32->Flink;
		} while (Start32 != End32);
	}
	else
	{
		PPEB64 PEB64 = PsGetProcessPeb(pEProcess);
		PLIST_ENTRY64 Start64 = (PLIST_ENTRY64)(((PEB_LDR_DATA64*)PEB64->Ldr)->InMemoryOrderModuleList.Flink);
		PLIST_ENTRY64 End64 = Start64;
		do
		{
			PLDR_DATA_TABLE_ENTRY64 pLdrDataEntry64 = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(Start64, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);
			UNICODE_STRING QueryModuleName = { 0 };
			RtlInitUnicodeString(&QueryModuleName, (PWCHAR)pLdrDataEntry64->BaseDllName.Buffer);
			if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE))
			{
				BaseAddress = (ULONG64)pLdrDataEntry64->DllBase;
				break;
			}
			Start64 = (PLIST_ENTRY64)Start64->Flink;
		} while (Start64 != End64);
	}
	KeUnstackDetachProcess(&ApcState);
	return BaseAddress;
}

NTSTATUS DispatchIoctl(PDEVICE_OBJECT pDriverObj, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDriverObj);
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID InputData = NULL, OutputData = NULL;
	ULONG OutputDataLength = 0;
	PIO_STACK_LOCATION io = IoGetCurrentIrpStackLocation(pIrp);
	InputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputData = pIrp->AssociatedIrp.SystemBuffer;
	OutputDataLength = io->Parameters.DeviceIoControl.OutputBufferLength;
	switch (io->Parameters.DeviceIoControl.IoControlCode)
	{
	case IOCTL_Read:
	{
		ReadMemory(((PDataStruct)InputData)->Pid, ((PDataStruct)InputData)->Address, ((PDataStruct)InputData)->Size, OutputData);
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_Write:
	{
		PVOID g_writeBuf = ExAllocatePoolWithTag(NonPagedPool, ((PDataStruct)InputData)->Size, 'uirg');
		if (g_writeBuf != 0)
		{
			RtlCopyMemory(g_writeBuf, ((PDataStruct)InputData)->Buffer, ((PDataStruct)InputData)->Size);
			WriteMemory(((PDataStruct)InputData)->Pid, ((PDataStruct)InputData)->Address, ((PDataStruct)InputData)->Size, g_writeBuf);
			ExFreePool(g_writeBuf);
		}
		Status = STATUS_SUCCESS;
		break;
	}
	case IOCTL_Modules:
	{
		ANSI_STRING AnsiBuffer = { 0 };
		UNICODE_STRING ModuleName = { 0 };
		AnsiBuffer.Buffer = ((PDataStruct)InputData)->Buffer;
		AnsiBuffer.Length = AnsiBuffer.MaximumLength = (USHORT)strlen(((PDataStruct)InputData)->Buffer);
		RtlAnsiStringToUnicodeString(&ModuleName, &AnsiBuffer, TRUE);
		ULONG64 BaseAddress = GetProcessModuleBase(((PDataStruct)InputData)->Pid, ModuleName);
		RtlCopyMemory(OutputData, &BaseAddress, sizeof(BaseAddress));
		RtlFreeUnicodeString(&ModuleName);
		Status = STATUS_SUCCESS;
		break;
	}
	default:
		Status = STATUS_UNSUCCESSFUL;
		break;
	}
	if (Status == STATUS_SUCCESS)
	{
		pIrp->IoStatus.Information = OutputDataLength;
	}
	else
	{
		pIrp->IoStatus.Information = 0;
	}
	pIrp->IoStatus.Status = Status;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);
	return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObj, PUNICODE_STRING pRegistryString)
{
	UNREFERENCED_PARAMETER(pRegistryString);
	NTSTATUS Status = STATUS_SUCCESS;
	UNICODE_STRING ustrLinkName = { 0 };
	UNICODE_STRING ustrDevName = { 0 };
	PDEVICE_OBJECT pDevObj;
	pDriverObj->MajorFunction[IRP_MJ_CREATE] = DispatchCreate;
	pDriverObj->MajorFunction[IRP_MJ_CLOSE] = DispatchClose;
	pDriverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;
	pDriverObj->DriverUnload = DriverUnload;
	RtlInitUnicodeString(&ustrDevName, DEVICE_NAME);
	Status = IoCreateDevice(pDriverObj, 0, &ustrDevName, FILE_DEVICE_UNKNOWN, 0, TRUE, &pDevObj);
	if (!NT_SUCCESS(Status))
	{
		return Status;
	}
	RtlInitUnicodeString(&ustrLinkName, SYM_NAME);
	Status = IoCreateSymbolicLink(&ustrLinkName, &ustrDevName);
	if (!NT_SUCCESS(Status))
	{
		IoDeleteDevice(pDevObj);
		return Status;
	}
	//DbgPrint("IOCTL_Protect=%d\n", IOCTL_Read);
	return STATUS_SUCCESS;
}