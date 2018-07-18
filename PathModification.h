#ifndef _PATH_MODIFICATION_H_
#define _PATH_MODIFICATION_H_ 1
//NTSTATUS PsGetTarProcessInfo(HANDLE pid);
//
//BOOLEAN PathPebLdr(PEPROCESS Process, WCHAR* szFullName, WCHAR* szBaseName);
//
//BOOLEAN PathPebProcessParameters(PEPROCESS Process, WCHAR* szFullName);
//
//BOOLEAN PathSeAuditProcessCreationInfo(PEPROCESS Process, WCHAR* ProcessName);
//
//BOOLEAN PathImageFileName(PEPROCESS Process, char* cName);
//
//BOOLEAN PathSeFileObject(PEPROCESS Process, WCHAR* szFullName);

BOOLEAN PathModification(HANDLE pid);
#endif