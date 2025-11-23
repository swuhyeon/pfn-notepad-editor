#include <ntddk.h>
#include <string.h>
#include "sioctl.h"

#define NT_DEVICE_NAME      L"\\Device\\SIOCTL"
#define DOS_DEVICE_NAME     L"\\DosDevices\\IoctlTest"

#if DBG
#define SIOCTL_KDPRINT(_x_) \
                DbgPrint("SIOCTL.SYS: ");\
                DbgPrint _x_;

#else
#define SIOCTL_KDPRINT(_x_)
#endif

DRIVER_INITIALIZE DriverEntry;

_Dispatch_type_(IRP_MJ_CREATE)
_Dispatch_type_(IRP_MJ_CLOSE)
DRIVER_DISPATCH SioctlCreateClose;

_Dispatch_type_(IRP_MJ_DEVICE_CONTROL)
DRIVER_DISPATCH SioctlDeviceControl;

DRIVER_UNLOAD SioctlUnloadDriver;

VOID
PrintIrpInfo(
    PIRP Irp
);
VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
);

#ifdef ALLOC_PRAGMA
#pragma alloc_text( INIT, DriverEntry )
#pragma alloc_text( PAGE, SioctlCreateClose)
#pragma alloc_text( PAGE, SioctlDeviceControl)
#pragma alloc_text( PAGE, SioctlUnloadDriver)
#pragma alloc_text( PAGE, PrintIrpInfo)
#pragma alloc_text( PAGE, PrintChars)
#endif

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT   DriverObject,
    _In_ PUNICODE_STRING      RegistryPath
)
{
    NTSTATUS        ntStatus;
    UNICODE_STRING  ntUnicodeString;
    UNICODE_STRING  ntWin32NameString;
    PDEVICE_OBJECT  deviceObject = NULL;

    UNREFERENCED_PARAMETER(RegistryPath);

    RtlInitUnicodeString(&ntUnicodeString, NT_DEVICE_NAME);

    ntStatus = IoCreateDevice(
        DriverObject,
        0,
        &ntUnicodeString,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &deviceObject);

    if (!NT_SUCCESS(ntStatus))
    {
        SIOCTL_KDPRINT(("Couldn't create the device object\n"));
        return ntStatus;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = SioctlCreateClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = SioctlDeviceControl;
    DriverObject->DriverUnload = SioctlUnloadDriver;

    RtlInitUnicodeString(&ntWin32NameString, DOS_DEVICE_NAME);

    ntStatus = IoCreateSymbolicLink(
        &ntWin32NameString, &ntUnicodeString);

    if (!NT_SUCCESS(ntStatus))
    {
        SIOCTL_KDPRINT(("Couldn't create symbolic link\n"));
        IoDeleteDevice(deviceObject);
    }

    return ntStatus;
}

NTSTATUS
SioctlCreateClose(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)

{
    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return STATUS_SUCCESS;
}

VOID
SioctlUnloadDriver(
    _In_ PDRIVER_OBJECT DriverObject
)

{
    PDEVICE_OBJECT deviceObject = DriverObject->DeviceObject;
    UNICODE_STRING uniWin32NameString;

    PAGED_CODE();

    RtlInitUnicodeString(&uniWin32NameString, DOS_DEVICE_NAME);

    IoDeleteSymbolicLink(&uniWin32NameString);

    if (deviceObject != NULL)
    {
        IoDeleteDevice(deviceObject);
    }
}

typedef unsigned int DWORD;
typedef unsigned __int64 QWORD, * PQWORD;

#define PID_OFFSET 0x440
#define PS_ACTIVE_OFFSET 0x448
QWORD FindProcessEPROC(
    _In_ int nPID
)
{
    QWORD eproc = 0x00000000;
    int currentPID = 0;
    int startPID = 0;
    int iCount = 0;
    PLIST_ENTRY plistActiveProcs;

    eproc = (QWORD)PsGetCurrentProcess();
    startPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
    currentPID = startPID;
    for (;;)
    {
        if (nPID == currentPID)
        {
            return eproc;
        }
        else if ((iCount >= 1) && (startPID == currentPID))
        {
            break;
        }
        else {
            plistActiveProcs = (LIST_ENTRY*)(eproc + PS_ACTIVE_OFFSET);
            eproc = (QWORD)plistActiveProcs->Flink - PS_ACTIVE_OFFSET;
            currentPID = (INT) * ((QWORD*)(eproc + (QWORD)PID_OFFSET));
            iCount++;
        }
    }

    return 0;
}

#define DTB_OFFSET 0x028
QWORD GetProcessDirBase(QWORD eproc)
{
    QWORD	directoryTableBase;

    if (eproc == 0x0) {
        return 0x0;
    }

    directoryTableBase = *(QWORD*)(eproc + DTB_OFFSET);
    directoryTableBase = directoryTableBase & 0xfffffffff000;

    return directoryTableBase;
}

#define PFN_MASK(pe)        ((QWORD)((pe) & 0x0000FFFFFFFFF000UL))
#define PFN_SETZERO(pe)    ((QWORD)((pe) & 0xFFFF000000000FFFUL))

NTSTATUS MmReadPhysical(PVOID targetAddress, ULONG64 sourceAddress, size_t size, size_t* bytesRead)
{
    PHYSICAL_ADDRESS address = { 0 };
    MM_COPY_ADDRESS copyInfo = { 0 };
    address.QuadPart = (LONGLONG)sourceAddress;
    copyInfo.PhysicalAddress = address;
    return MmCopyMemory(targetAddress, copyInfo, size, MM_COPY_MEMORY_PHYSICAL, bytesRead);
}

typedef union _virt_addr_t
{
    QWORD value;
    struct
    {
        QWORD offset_4kb : 12;
        QWORD pt_index : 9;
        QWORD pd_index : 9;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }a;

    struct
    {
        QWORD offset_2mb : 21;
        QWORD pd_index : 9;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }b;

    struct
    {
        QWORD offset_1gb : 30;
        QWORD pdpt_index : 9;
        QWORD pml4_index : 9;
        QWORD reserved : 16;
    }c;

} virt_addr_t, * pvirt_addr_t;


QWORD GetPfn(ULONG64 cr3, QWORD virtual_addr)
{
    size_t dummy;
    QWORD* ppml4 = NULL;
    QWORD   pdpt = 0;
    QWORD* ppdpt = NULL;
    QWORD   pd = 0;
    QWORD* ppd = NULL;
    QWORD   pt = 0;
    QWORD* ppt = NULL;
    QWORD   pfn = 0;

    virt_addr_t a;

    a.value = virtual_addr;

    size_t copySize = PAGE_SIZE;
    PVOID buffer = ExAllocatePool(NonPagedPool, copySize);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "cr3 : %p\n", cr3);
    MmReadPhysical(buffer, cr3, copySize, &dummy);
    ppml4 = (PQWORD)buffer;
    pdpt = ppml4[a.a.pml4_index];
    pdpt = PFN_MASK(pdpt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppml4[%d]:%p\r\n", a.a.pml4_index, pdpt);

    MmReadPhysical(buffer, pdpt, copySize, &dummy);
    ppdpt = (PQWORD)buffer;
    pd = ppdpt[a.a.pdpt_index];
    pd = PFN_MASK(pd);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppdpt[%d]:%p\r\n", a.a.pdpt_index, pd);

    MmReadPhysical(buffer, pd, copySize, &dummy);
    ppd = (PQWORD)buffer;
    pt = ppd[a.a.pd_index];
    pt = PFN_MASK(pt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppd[%d]:%p\r\n", a.a.pd_index, pt);

    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    pfn = ppt[a.a.pt_index];
    pfn = PFN_MASK(pfn);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].pfn:%p\r\n", a.a.pt_index, pfn);

    QWORD physicalAddress = pfn + a.a.offset_4kb;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Final PFN(physical): %p\n", physicalAddress);

    ExFreePool(buffer);

    return pfn;
}

DWORD g_dwPid = 0;
QWORD g_qwVa = 0;
static HANDLE hPhysicalhandle = NULL;

NTSTATUS GetPhysicalHandle()
{
    NTSTATUS status;
    UNICODE_STRING PhysicalMemoryString;
    OBJECT_ATTRIBUTES attributes;

    WCHAR PhysicalMemoryName[] = L"\\Device\\PhysicalMemory";
    RtlInitUnicodeString(&PhysicalMemoryString, PhysicalMemoryName);
    InitializeObjectAttributes(&attributes, &PhysicalMemoryString, 0, NULL, NULL);
    status = ZwOpenSection(&hPhysicalhandle, SECTION_MAP_READ | SECTION_MAP_WRITE, &attributes);

    return status;
}

NTSTATUS WritePhysicalMemory2(DWORD64 PhysicalAddress, DWORD32 WriteData)
{
    NTSTATUS status;
    PVOID BaseAddress = NULL;
    DWORD32 offset;
    LARGE_INTEGER SectionOffset;
    SIZE_T size = 0x2000;

    status = GetPhysicalHandle();
    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    offset = PhysicalAddress & 0xFFF;

    SectionOffset.QuadPart = (ULONGLONG)(PhysicalAddress);

    status = ZwMapViewOfSection(
        hPhysicalhandle,
        NtCurrentProcess(),
        (PVOID*)&BaseAddress,
        0,
        size,
        &SectionOffset,
        &size,
        ViewShare,
        MEM_TOP_DOWN,
        PAGE_READWRITE);

    if (status < 0)
    {
        status = FALSE;
        goto Leave;
    }

    memmove_s((PVOID)((DWORD64)BaseAddress + offset), sizeof(DWORD32), &WriteData, sizeof(DWORD32));

    status = ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

    if (status < 0)
    {
        status = FALSE;
    }

Leave:
    if (hPhysicalhandle != NULL)
    {
        ZwClose(hPhysicalhandle);
    }

    return status;
}

QWORD SetPfn(QWORD cr3, QWORD virtual_addr, QWORD new_pfn)
{
    size_t dummy;
    QWORD* ppml4 = NULL;
    QWORD   pdpt = 0;
    QWORD* ppdpt = NULL;
    QWORD   pd = 0;
    QWORD* ppd = NULL;
    QWORD   pt = 0;
    QWORD* ppt = NULL;
    QWORD  old_pfn = 0;
    QWORD  tmp_pfn = 0;
    QWORD  pt_entry = 0;

    virt_addr_t a;
    a.value = virtual_addr;
    size_t copySize = PAGE_SIZE;
    PVOID buffer = ExAllocatePool(NonPagedPool, copySize);

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "cr3 : %p\n", cr3);
    MmReadPhysical(buffer, cr3, copySize, &dummy);
    ppml4 = (PQWORD)buffer;
    pdpt = ppml4[a.a.pml4_index];
    pdpt = PFN_MASK(pdpt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppml4[%d]:%p\r\n", a.a.pml4_index, pdpt);
    MmReadPhysical(buffer, pdpt, copySize, &dummy);
    ppdpt = (PQWORD)buffer;
    pd = ppdpt[a.a.pdpt_index];
    pd = PFN_MASK(pd);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppdpt[%d]:%p\r\n", a.a.pdpt_index, pd);
    MmReadPhysical(buffer, pd, copySize, &dummy);
    ppd = (PQWORD)buffer;
    pt = ppd[a.a.pd_index];
    pt = PFN_MASK(pt);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppd[%d]:%p\r\n", a.a.pd_index, pt);

    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    tmp_pfn = ppt[a.a.pt_index];
    old_pfn = PFN_MASK(tmp_pfn);
    tmp_pfn = PFN_SETZERO(tmp_pfn);
    new_pfn = new_pfn << 12;
    tmp_pfn = tmp_pfn | new_pfn;
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].old_pfn:%p tmp_pfn\r\n", a.a.pt_index, old_pfn, tmp_pfn);

    pt_entry = pt + 8 * a.a.pt_index;

    PHYSICAL_ADDRESS val2 = { 0, };
    val2.QuadPart = tmp_pfn;

    WritePhysicalMemory2(pt_entry, val2.LowPart);
    WritePhysicalMemory2(pt_entry + 4, val2.HighPart);

    MmReadPhysical(buffer, pt, copySize, &dummy);
    ppt = (PQWORD)buffer;
    tmp_pfn = ppt[a.a.pt_index];
    tmp_pfn = PFN_MASK(tmp_pfn);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ppt[%d].new_pfn:%p\r\n", a.a.pt_index, tmp_pfn);

    ExFreePool(buffer);

    return old_pfn;
}

NTSTATUS
SioctlDeviceControl(
    PDEVICE_OBJECT DeviceObject,
    PIRP Irp
)

{
    PIO_STACK_LOCATION  irpSp;
    NTSTATUS            ntStatus = STATUS_SUCCESS;
    ULONG               inBufLength;
    ULONG               outBufLength;
    PCHAR               outBuf;

    UNREFERENCED_PARAMETER(DeviceObject);

    PAGED_CODE();

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    inBufLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outBufLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    if (!inBufLength || !outBufLength)
    {
        ntStatus = STATUS_INVALID_PARAMETER;
        goto End;
    }

    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {

    case IOCTL_SET_PID:
    {
        unsigned int* pdwPid = NULL;
        pdwPid = Irp->AssociatedIrp.SystemBuffer;
        SIOCTL_KDPRINT(("\tData from User :"));
        DbgPrintEx(0, 0, "PID : %u", *pdwPid);
        g_dwPid = *pdwPid;
        Irp->IoStatus.Information = 0;
    }
    break;

    case IOCTL_SET_VA:
    {
        unsigned __int64* pun64Va = NULL;
        pun64Va = Irp->AssociatedIrp.SystemBuffer;
        DbgPrintEx(0, 0, "VA : %llx", pun64Va);
        g_qwVa = *pun64Va;
        DbgPrintEx(0, 0, "g_qwVa : %lld\n", g_qwVa);

        QWORD eproc = 0;
        eproc = FindProcessEPROC(g_dwPid);
        QWORD qwCr3 = 0;
        qwCr3 = GetProcessDirBase(eproc);
        QWORD qwPfn = 0;
        qwPfn = GetPfn(qwCr3, g_qwVa);
        outBuf = Irp->AssociatedIrp.SystemBuffer;
        RtlCopyBytes(outBuf, &qwPfn, sizeof(qwPfn));
        Irp->IoStatus.Information = sizeof(qwPfn);

    }
    break;

    case IOCTL_SET_PFN:
    {
        unsigned __int64* pun64NewPfn = NULL;
        pun64NewPfn = Irp->AssociatedIrp.SystemBuffer;
        DbgPrintEx(0, 0, "New Pfn : %llx, g_dwPid: %u, g_qwVa: %llx", *pun64NewPfn, g_dwPid, g_qwVa);

        QWORD eproc = 0;
        eproc = FindProcessEPROC(g_dwPid);
        QWORD qwCr3 = 0;
        qwCr3 = GetProcessDirBase(eproc);

        SetPfn(qwCr3, g_qwVa, *pun64NewPfn);

        Irp->IoStatus.Information = 0;

    }
    break;

    default:
        ntStatus = STATUS_INVALID_DEVICE_REQUEST;
        SIOCTL_KDPRINT(("ERROR: unrecognized IOCTL %x\n",
            irpSp->Parameters.DeviceIoControl.IoControlCode));
        break;
    }

End:
    Irp->IoStatus.Status = ntStatus;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return ntStatus;
}

VOID
PrintIrpInfo(
    PIRP Irp)
{
    PIO_STACK_LOCATION  irpSp;
    irpSp = IoGetCurrentIrpStackLocation(Irp);

    PAGED_CODE();

    SIOCTL_KDPRINT(("\tIrp->AssociatedIrp.SystemBuffer = 0x%p\n",
        Irp->AssociatedIrp.SystemBuffer));
    SIOCTL_KDPRINT(("\tIrp->UserBuffer = 0x%p\n", Irp->UserBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.Type3InputBuffer = 0x%p\n",
        irpSp->Parameters.DeviceIoControl.Type3InputBuffer));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.InputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.InputBufferLength));
    SIOCTL_KDPRINT(("\tirpSp->Parameters.DeviceIoControl.OutputBufferLength = %d\n",
        irpSp->Parameters.DeviceIoControl.OutputBufferLength));
    return;
}

VOID
PrintChars(
    _In_reads_(CountChars) PCHAR BufferAddress,
    _In_ size_t CountChars
)
{
    PAGED_CODE();

    if (CountChars) {

        while (CountChars--) {

            if (*BufferAddress > 31
                && *BufferAddress != 127) {

                KdPrint(("%c", *BufferAddress));

            }
            else {

                KdPrint(("."));

            }
            BufferAddress++;
        }
        KdPrint(("\n"));
    }
    return;
}