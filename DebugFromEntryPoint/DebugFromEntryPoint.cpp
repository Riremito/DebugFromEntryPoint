#include<Windows.h>
#include<string>

#define TOOL_NAME L"DebugFromEntryPoint"

#pragma pack(push, 1)
typedef struct {
#ifdef _WIN64
	BYTE push[7];
	WORD push_sub[8];
	DWORD sub_rsp;
	BYTE loadlib_arg_1[7];
	BYTE loadlib_call_qword_ptr[6];
	BYTE msgbox_arg_4[3];
	BYTE msgbox_arg_3[7];
	BYTE msgbox_arg_2[7];
	BYTE msgbox_arg_1[3];
	BYTE msgbox_call_qword_ptr[6];
	DWORD add_rsp;
	WORD pop_sub[8];
	BYTE pop[7];
	BYTE jmp_qword_ptr[6];
#else
	BYTE push[2];
	BYTE loadlibrary_arg_1[5];
	BYTE loadlib_call_dword_ptr[6];
	BYTE msgbox_arg_4[2];
	BYTE msgbox_arg_3[5];
	BYTE msgbox_arg_2[5];
	BYTE msgbox_arg_1[2];
	BYTE msgbox_call_dword_ptr[6];
	BYTE pop[2];
	BYTE jmp_dword_ptr[6];
#endif
	ULONG_PTR address_LoadLibraryW;
	ULONG_PTR address_MessageBoxW;
	ULONG_PTR address_EntryPoint;
	WCHAR loadlib_path[128];
	WCHAR msgbox_title[128];
	WCHAR msgbox_msg[128];
} DebugEntryPoint;
#pragma pack(pop)


class DebugFromEntryPointInjector {
private:
	PROCESS_INFORMATION target_pi;
	std::wstring target_path;
	HANDLE process_handle;
	HANDLE main_thread_handle;
	bool is_successed;

public:
	DebugFromEntryPointInjector(std::wstring wTargetPath);
	~DebugFromEntryPointInjector();
	bool Run(std::wstring wCmdLine = L"");
};

DebugFromEntryPointInjector::DebugFromEntryPointInjector(std::wstring wTargetPath) {
	target_path = wTargetPath;
	process_handle = NULL;
	main_thread_handle = NULL;
	is_successed = false;
	memset(&target_pi, 0, sizeof(target_pi));
};

DebugFromEntryPointInjector::~DebugFromEntryPointInjector() {
	if (main_thread_handle) {
		if (is_successed) {
			ResumeThread(main_thread_handle);
		}
		CloseHandle(main_thread_handle);
	}
	if (process_handle) {
		if (!is_successed) {
			TerminateProcess(process_handle, 0xDEAD);
		}
		CloseHandle(process_handle);
	}
}

bool DebugFromEntryPointInjector::Run(std::wstring wCmdLine) {
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si, 0, sizeof(si));
	memset(&pi, 0, sizeof(pi));
	si.cb = sizeof(si);

	std::wstring wDir = target_path;
	size_t pos_last_backslash = wDir.rfind(L'\\');
	if (pos_last_backslash != std::wstring::npos) {
		wDir.erase(wDir.begin() + pos_last_backslash + 1, wDir.end());
		if (wCmdLine.length()) {
			if (!CreateProcessW(target_path.c_str(), (LPWSTR)wCmdLine.c_str(), 0, 0, FALSE, CREATE_SUSPENDED, 0, wDir.c_str(), &si, &pi)) {
				return false;
			}
		}
		else {
			if (!CreateProcessW(target_path.c_str(), 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, wDir.c_str(), &si, &pi)) {
				return false;
			}
		}
	}
	else {
		if (wCmdLine.length()) {
			if (!CreateProcessW(target_path.c_str(), (LPWSTR)wCmdLine.c_str(), 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
				return false;
			}
		}
		else {
			if (!CreateProcessW(target_path.c_str(), 0, 0, 0, FALSE, CREATE_SUSPENDED, 0, 0, &si, &pi)) {
				return false;
			}
		}
	}

	process_handle = pi.hProcess;
	main_thread_handle = pi.hThread;

	// Process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	if (!hProcess) {
		return false;
	}

	CloseHandle(process_handle);
	process_handle = hProcess;

	// Thread
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, pi.dwThreadId);
	if (!hThread) {
		return false;
	}

	CloseHandle(main_thread_handle);
	main_thread_handle = hThread;

	CONTEXT ct;
	memset(&ct, 0, sizeof(ct));
	ct.ContextFlags = CONTEXT_ALL;
	if (!GetThreadContext(main_thread_handle, &ct)) {
		return false;
	}

	void *vCode = VirtualAllocEx(process_handle, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!vCode) {
		return false;
	}

	DebugEntryPoint v = { 0 };

	wcscpy_s(v.loadlib_path, L"user32.dll");
	wcscpy_s(v.msgbox_title, TOOL_NAME);
	wcscpy_s(v.msgbox_msg, L"Please set BP at ret code of MessageBoxW API");

	v.address_LoadLibraryW = (ULONG_PTR)LoadLibraryW;
	v.address_MessageBoxW = (ULONG_PTR)MessageBoxW;
#ifdef _WIN64
	v.address_EntryPoint = (ULONG_PTR)ct.Rip;
	ct.Rip = (ULONG_PTR)vCode;
	// push reg
	v.push[0] = 0x50;
	v.push[1] = 0x53;
	v.push[2] = 0x51;
	v.push[3] = 0x52;
	v.push[4] = 0x56;
	v.push[5] = 0x57;
	v.push[6] = 0x55;
	v.push_sub[0] = 0x5041;
	v.push_sub[1] = 0x5141;
	v.push_sub[2] = 0x5241;
	v.push_sub[3] = 0x5341;
	v.push_sub[4] = 0x5441;
	v.push_sub[5] = 0x5541;
	v.push_sub[6] = 0x5641;
	v.push_sub[7] = 0x5741;
	// sub rsp,0x30
	v.sub_rsp = 0x30EC8348;
	// LoadLibraryW(L"user32.dll");
	v.loadlib_arg_1[0] = 0x48;
	v.loadlib_arg_1[1] = 0x8D;
	v.loadlib_arg_1[2] = 0x0D;
	*(signed long int *)&v.loadlib_arg_1[3] = (signed long int)((ULONG_PTR)&v.loadlib_path - (ULONG_PTR)&v.loadlib_arg_1[0] - 0x07);
	v.loadlib_call_qword_ptr[0] = 0xFF;
	v.loadlib_call_qword_ptr[1] = 0x15;
	*(signed long int *)&v.loadlib_call_qword_ptr[2] = (signed long int)((ULONG_PTR)&v.address_LoadLibraryW - (ULONG_PTR)&v.loadlib_call_qword_ptr[0] - 0x06);
	// MessageBoxW(NULL, L"DebugFromEntryPoint", L"Please set BP at ret code of MessageBoxW API", MB_OK);
	v.msgbox_arg_4[0] = 0x4D;
	v.msgbox_arg_4[1] = 0x31;
	v.msgbox_arg_4[2] = 0xC9;
	v.msgbox_arg_3[0] = 0x4C;
	v.msgbox_arg_3[1] = 0x8D;
	v.msgbox_arg_3[2] = 0x05;
	*(signed long int *)&v.msgbox_arg_3[3] = (signed long int)((ULONG_PTR)&v.msgbox_title - (ULONG_PTR)&v.msgbox_arg_3[0] - 0x07);
	v.msgbox_arg_2[0] = 0x48;
	v.msgbox_arg_2[1] = 0x8D;
	v.msgbox_arg_2[2] = 0x15;
	*(signed long int *)&v.msgbox_arg_2[3] = (signed long int)((ULONG_PTR)&v.msgbox_msg - (ULONG_PTR)&v.msgbox_arg_2[0] - 0x07);
	v.msgbox_arg_1[0] = 0x48;
	v.msgbox_arg_1[1] = 0x31;
	v.msgbox_arg_1[2] = 0xC9;
	v.msgbox_call_qword_ptr[0] = 0xFF;
	v.msgbox_call_qword_ptr[1] = 0x15;
	*(signed long int *)&v.msgbox_call_qword_ptr[2] = (signed long int)((ULONG_PTR)&v.address_MessageBoxW - (ULONG_PTR)&v.msgbox_call_qword_ptr[0] - 0x06);
	// add rsp,0x30
	v.add_rsp = 0x30C48348;
	// pop reg
	v.pop_sub[0] = 0x5F41;
	v.pop_sub[1] = 0x5E41;
	v.pop_sub[2] = 0x5D41;
	v.pop_sub[3] = 0x5C41;
	v.pop_sub[4] = 0x5B41;
	v.pop_sub[5] = 0x5A41;
	v.pop_sub[6] = 0x5941;
	v.pop_sub[7] = 0x5841;
	v.pop[0x00] = 0x5D;
	v.pop[0x01] = 0x5F;
	v.pop[0x02] = 0x5E;
	v.pop[0x03] = 0x5A;
	v.pop[0x04] = 0x59;
	v.pop[0x05] = 0x5B;
	v.pop[0x06] = 0x58;
	// jmp EntryPoint
	v.jmp_qword_ptr[0] = 0xFF;
	v.jmp_qword_ptr[1] = 0x25;
	*(signed long int *)&v.jmp_qword_ptr[2] = (signed long int)((ULONG_PTR)&v.address_EntryPoint - (ULONG_PTR)&v.jmp_qword_ptr[0] - 0x06);
#else
	// x86plz
	v.address_EntryPoint = (ULONG_PTR)ct.Eip;
	ct.Eip = (ULONG_PTR)vCode;
	// push reg
	v.push[0] = 0x50;
	v.push[1] = 0x53;
	// LoadLibraryW(L"user32.dll");
	v.loadlibrary_arg_1[0] = 0x68;
	*(ULONG_PTR *)&v.loadlibrary_arg_1[1] = (ULONG_PTR)&v.loadlib_path - (ULONG_PTR)&v + (ULONG_PTR)vCode;
	v.loadlib_call_dword_ptr[0] = 0xFF;
	v.loadlib_call_dword_ptr[1] = 0x15;
	*(ULONG_PTR *)&v.loadlib_call_dword_ptr[2] = (ULONG_PTR)&v.address_LoadLibraryW - (ULONG_PTR)&v +(ULONG_PTR)vCode;
	// MessageBoxW(NULL, L"DebugFromEntryPoint", L"Please set BP at ret code of MessageBoxW API", MB_OK);
	v.msgbox_arg_4[0] = 0x6A;
	v.msgbox_arg_4[1] = 0x00;
	v.msgbox_arg_3[0] = 0x68;
	*(ULONG_PTR *)&v.msgbox_arg_3[1] = (ULONG_PTR)&v.msgbox_title - (ULONG_PTR)&v + (ULONG_PTR)vCode;
	v.msgbox_arg_2[0] = 0x68;
	*(ULONG_PTR *)&v.msgbox_arg_2[1] = (ULONG_PTR)&v.msgbox_msg - (ULONG_PTR)&v + (ULONG_PTR)vCode;
	v.msgbox_arg_1[0] = 0x6A;
	v.msgbox_arg_1[1] = 0x00;
	v.msgbox_call_dword_ptr[0] = 0xFF;
	v.msgbox_call_dword_ptr[1] = 0x15;
	*(ULONG_PTR *)&v.msgbox_call_dword_ptr[2] = (ULONG_PTR)&v.address_MessageBoxW - (ULONG_PTR)&v + (ULONG_PTR)vCode;
	// pop reg
	v.pop[0] = 0x5B;
	v.pop[1] = 0x58;
	// jmp EntryPoint
	v.jmp_dword_ptr[0] = 0xFF;
	v.jmp_dword_ptr[1] = 0x25;
	*(ULONG_PTR *)&v.jmp_dword_ptr[2] = (ULONG_PTR)&v.address_EntryPoint - (ULONG_PTR)&v + (ULONG_PTR)vCode;
#endif

	SIZE_T bw;
	if (!WriteProcessMemory(process_handle, vCode, (void *)&v, sizeof(v), &bw)) {
		return false;
	}

	if (!SetThreadContext(main_thread_handle, &ct)) {
		return false;
	}

	is_successed = true;
	return true;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow) {

	if (__argc < 2) {
		MessageBoxW(NULL, L"Please check target exe file path", TOOL_NAME, MB_OK);
	}
	else {
		DebugFromEntryPointInjector injector(__wargv[1]);
		injector.Run();
	}

	return 0;
}