#include <windows.h>

int main(void) {
    HKEY key = NULL;
    const char *run_key = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    const char *value_name = "SyntheticExample";
    const char *value_data = "C:\\Synthetic\\example.exe";
    if (RegCreateKeyExA(HKEY_CURRENT_USER, run_key, 0, NULL, 0, KEY_SET_VALUE,
                        NULL, &key, NULL) == ERROR_SUCCESS) {
        RegSetValueExA(key, value_name, 0, REG_SZ, (const BYTE *)value_data,
                       (DWORD)(lstrlenA(value_data) + 1));
        RegCloseKey(key);
    }
    return 0;
}
