#include <windows.h>
#include <shlwapi.h>
#include <iostream>
#include <string>
#include <chrono>
#include <string_view>
#include <algorithm>
#include <thread>

#pragma comment(lib, "Shlwapi.lib")

bool IsRunningAsAdmin() {
    BOOL fIsRunAsAdmin = FALSE;
    PSID pAdministratorsGroup = NULL;

    // Allocate and initialize a SID of the administrators group.
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (!AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0,
        &pAdministratorsGroup)) {
        return false;
    }

    // Determine whether the SID of administrators group is enabled in the primary access token.
    if (!CheckTokenMembership(NULL, pAdministratorsGroup, &fIsRunAsAdmin)) {
        fIsRunAsAdmin = FALSE;
    }

    // Free the SID.
    if (pAdministratorsGroup) {
        FreeSid(pAdministratorsGroup);
    }

    return fIsRunAsAdmin;
}

void RelaunchAsAdmin() {
    wchar_t szPath[MAX_PATH];
    if (GetModuleFileNameW(NULL, szPath, ARRAYSIZE(szPath))) {
        // Launch itself as an admin.
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.lpVerb = L"runas";
        sei.lpFile = szPath;
        sei.hwnd = NULL;
        sei.nShow = SW_NORMAL;

        if (!ShellExecuteExW(&sei)) {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED) {
                std::wcout << L"Please run this application as an administrator." << std::endl;
            }
            else {
                std::wcout << L"Failed to relaunch as an administrator. Error: " << dwError << std::endl;
            }
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
}


bool RegisterCustomUrlScheme(const std::string& appPath) {
    HKEY hKey;
    LPCWSTR urlScheme = L"jgdps"; // Use wide-character string

    // Convert narrow-character string to wide-character string
    int size = MultiByteToWideChar(CP_UTF8, 0, appPath.c_str(), -1, NULL, 0);
    std::wstring wAppPath(size, 0);
    MultiByteToWideChar(CP_UTF8, 0, appPath.c_str(), -1, &wAppPath[0], size);

    // Create the registry key for the custom URL scheme
    LONG result = RegCreateKeyExW(HKEY_CLASSES_ROOT, urlScheme, 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL);
    if (result != ERROR_SUCCESS) {
        return false;
    }
    RegSetValueExW(hKey, NULL, 0, REG_SZ, (const BYTE*)L"URL:JGDPS Protocol", sizeof(L"URL:JGDPS Protocol"));
    RegSetValueExW(hKey, L"URL Protocol", 0, REG_SZ, (const BYTE*)L"", sizeof(L""));

    HKEY hSubKey;
    result = RegCreateKeyExW(hKey, L"shell\\open\\command", 0, NULL, 0, KEY_WRITE, NULL, &hSubKey, NULL);
    if (result != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return false;
    }
    RegSetValueExW(hSubKey, NULL, 0, REG_SZ, (const BYTE*)wAppPath.c_str(), (wAppPath.size() + 1) * sizeof(wchar_t));

    RegCloseKey(hSubKey);
    RegCloseKey(hKey);
    return true;
}


bool ValidateAppPath(std::string_view appPath) {
    std::string path = std::string(appPath);

    // Convert forward slashes to backslashes
    std::replace(path.begin(), path.end(), '/', '\\');

    // Check if the file has a valid extension (.exe or .scr)
    if (PathFindExtensionA(path.c_str()) != ".exe" && PathFindExtensionA(path.c_str()) != ".scr") {
        std::cout << "Invalid file extension. File must have .exe or .scr extension." << std::endl;
        return false;
    }

    // Check if the file exists
    if (!PathFileExistsA(path.c_str())) {
        std::cout << "File does not exist." << std::endl;
        return false;
    }

    return true;
}

int main() {
    std::string appPath;
    std::cout << "Enter the application path (e.g., \"C:/Path/To/YourApp.exe\" \"%1\"): ";
    std::getline(std::cin, appPath);

    if (!ValidateAppPath(appPath)) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return 1;
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));

    if (IsRunningAsAdmin()) {
        std::cout << "Running with administrator privileges." << std::endl;
        if (RegisterCustomUrlScheme(appPath)) {
            std::cout << "Success!" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
        else {
            std::cout << "Failed to register URL scheme." << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds(2));
        }
    }
    else {
        std::cout << "Not running as an administrator, attempting to relaunch..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        RelaunchAsAdmin();
    }

    return 0;
}