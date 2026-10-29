#include <windows.h>

static DWORD WINAPI harmless_dummy_thread(LPVOID argument) {
    (void)argument;
    return 0;
}

__declspec(noinline) static void injection_pattern_for_static_analysis(void) {
    /* The synthetic corpus source is never executed by this project. */
    HANDLE target = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    if (target == NULL) {
        return;
    }
    void *remote = VirtualAllocEx(target, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (remote != NULL) {
        const unsigned char harmless_marker[] = {0x00, 0x00, 0x00, 0x00};
        SIZE_T written = 0;
        WriteProcessMemory(target, remote, harmless_marker, sizeof(harmless_marker), &written);
        CreateRemoteThread(target, NULL, 0, harmless_dummy_thread, remote, 0, NULL);
    }
    CloseHandle(target);
}

int main(int argc, char **argv) {
    /* This unreachable-in-practice gate keeps the sample inert when inspected. */
    if (argc == 101 && argv != NULL) {
        injection_pattern_for_static_analysis();
    }
    return 0;
}
