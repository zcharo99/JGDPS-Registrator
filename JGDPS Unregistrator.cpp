#include <windows.h>
#include <iostream>
#include <chrono>
#include <thread>

bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }

    return isAdmin;
}

void RelaunchAsAdmin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath))) {
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteExW(&sei)) {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED) {
                std::wcout << L"Please run this application as an administrator." << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(2));
                exit(1);
            }
        } else {
            exit(0);
        }
    }
}

bool CheckUrlSchemeRegistration() {
    HKEY hKey;
    const wchar_t* urlScheme = L"jgdps";

    LONG result = RegOpenKeyExW(HKEY_CLASSES_ROOT, urlScheme, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    } else {
        return false;
    }
}

bool DeleteUrlSchemeRegistration() {
    const wchar_t* urlScheme = L"jgdps";

    LONG result = RegDeleteTreeW(HKEY_CLASSES_ROOT, urlScheme);
    if (result == ERROR_SUCCESS) {
        return true;
    } else {
        return false;
    }
}

int main() {
    if (!IsRunningAsAdmin()) {
        RelaunchAsAdmin();
    }

    if (CheckUrlSchemeRegistration()) {
        if (DeleteUrlSchemeRegistration()) {
            std::cout << "Unregistered successfully." << std::endl;
        } else {
            std::cout << "Failed to unregister." << std::endl;
        }
    } else {
        std::cout << "Registration not found." << std::endl;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));
    return 0;
}

