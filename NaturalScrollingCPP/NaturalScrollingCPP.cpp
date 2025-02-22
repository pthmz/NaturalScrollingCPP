#include <iostream>
#include <windows.h>
#include <vector>
#include <string>
#include <Wbemidl.h>
#include <comdef.h>
#include <locale>
#include <codecvt>
#include <SetupAPI.h>
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Setupapi.lib")

// Convert wchar_t* to std::string
std::string wstring_to_string(const std::wstring& wstr) {
    try {
        std::wstring_convert<std::codecvt_utf8<wchar_t>> converter;
        return converter.to_bytes(wstr);
    }
    catch (const std::range_error&) {
        return "";
    }
}

// Declare the ModifyFlipFlopWheel function
void ModifyFlipFlopWheel(HKEY deviceParametersKey);

// Recursively traverse the registry
void RecursiveTraversal(HKEY key, const std::string& path) {
    TCHAR subKeyName[MAX_PATH];
    DWORD subKeyNameSize = MAX_PATH;
    HKEY subKey;
    DWORD index = 0;
    LONG result;

    // Get all subkey names
    while ((result = RegEnumKeyEx(key, index, subKeyName, &subKeyNameSize, NULL, NULL, NULL, NULL)) == ERROR_SUCCESS) {
        std::wstring subKeyNameW(subKeyName);
        std::string subKeyNameS = wstring_to_string(subKeyNameW);
        std::string fullPath = path + "\\" + subKeyNameS;
        std::cout << "Traverse the registry path: " << fullPath.substr(1) << std::endl;

        // Open the subkey
        if (RegOpenKeyEx(key, subKeyName, 0, KEY_ALL_ACCESS, &subKey) == ERROR_SUCCESS) {
            if (subKeyNameS == "Device Parameters") {
                ModifyFlipFlopWheel(subKey);
            }
            else {
                RecursiveTraversal(subKey, fullPath);
            }
            RegCloseKey(subKey);
        }

        subKeyNameSize = MAX_PATH;
        index++;
    }

    if (result != ERROR_NO_MORE_ITEMS) {
        std::cerr << "Error enumerating subkeys at path " << path << ": " << result << std::endl;
    }
}

// Modify the FlipFlopWheel value
void ModifyFlipFlopWheel(HKEY deviceParametersKey) {
    DWORD value = 1;
    LONG result = RegSetValueEx(deviceParametersKey, L"FlipFlopWheel", 0, REG_DWORD, (const BYTE*)&value, sizeof(value));
    if (result == ERROR_SUCCESS) {
        std::cout << "Successfully set FlipFlopWheel to 1." << std::endl;
    }
    else {
        std::cerr << "Unable to set FlipFlopWheel: " << result << std::endl;
    }
}

// Traverse and modify the registry
void TraverseAndModifyRegistry() {
    HKEY rootKey;
    LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Enum\\HID", 0, KEY_ALL_ACCESS, &rootKey);
    if (result == ERROR_SUCCESS) {
        RecursiveTraversal(rootKey, "");
        RegCloseKey(rootKey);
    }
    else {
        std::cerr << "The specified registry path does not exist or could not be opened." << std::endl;
    }
    std::cout << "Traversal completed." << std::endl;
}

// Restart the device
void RestartDevice(const std::wstring& pnpDeviceId) {
    // Try to simplify the PNPDeviceID
    std::wstring simplifiedId = pnpDeviceId;
    size_t pos = simplifiedId.find_last_of(L'\\');
    if (pos != std::wstring::npos) {
        simplifiedId = simplifiedId.substr(0, pos);
    }

    HDEVINFO deviceInfoSet = SetupDiGetClassDevs(NULL, simplifiedId.c_str(), NULL, DIGCF_ALLCLASSES | DIGCF_PRESENT);
    if (deviceInfoSet == INVALID_HANDLE_VALUE) {
        DWORD errorCode = GetLastError();
        std::cerr << "Failed to get device information set. Error code = " << errorCode << std::endl;
        switch (errorCode) {
        case ERROR_INVALID_DATA:
            std::cerr << "Error: Invalid data passed to SetupDiGetClassDevs." << std::endl;
            break;
        case ERROR_NO_MORE_ITEMS:
            std::cerr << "Error: No more matching devices found." << std::endl;
            break;
        default:
            std::cerr << "Unknown error occurred." << std::endl;
            break;
        }
        return;
    }

    SP_DEVINFO_DATA deviceInfoData;
    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
    if (SetupDiEnumDeviceInfo(deviceInfoSet, 0, &deviceInfoData)) {
        // Disable the device
        SP_PROPCHANGE_PARAMS propChangeParams;
        propChangeParams.ClassInstallHeader.cbSize = sizeof(SP_CLASSINSTALL_HEADER);
        propChangeParams.ClassInstallHeader.InstallFunction = DIF_PROPERTYCHANGE;
        propChangeParams.Scope = DICS_FLAG_GLOBAL;
        propChangeParams.StateChange = DICS_DISABLE;
        if (!SetupDiSetClassInstallParams(deviceInfoSet, &deviceInfoData, &propChangeParams.ClassInstallHeader, sizeof(propChangeParams))) {
            std::cerr << "Failed to disable device. Error code = " << GetLastError() << std::endl;
        }
        else {
            if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, deviceInfoSet, &deviceInfoData)) {
                std::cerr << "Failed to call class installer to disable device. Error code = " << GetLastError() << std::endl;
            }
            else {
                // Enable the device
                propChangeParams.StateChange = DICS_ENABLE;
                if (!SetupDiSetClassInstallParams(deviceInfoSet, &deviceInfoData, &propChangeParams.ClassInstallHeader, sizeof(propChangeParams))) {
                    std::cerr << "Failed to enable device. Error code = " << GetLastError() << std::endl;
                }
                else {
                    if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, deviceInfoSet, &deviceInfoData)) {
                        std::cerr << "Failed to call class installer to enable device. Error code = " << GetLastError() << std::endl;
                    }
                    else {
                        std::cout << "Successfully restarted device." << std::endl;
                    }
                }
            }
        }
    }
    else {
        std::cerr << "Failed to enumerate device information. Error code = " << GetLastError() << std::endl;
    }

    SetupDiDestroyDeviceInfoList(deviceInfoSet);
}

// Restart mouse devices
void RestartMouseDevices() {
    HRESULT hres;

    // Initialize COM
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize COM library. Error code = 0x" << std::hex << hres << std::endl;
        return;
    }

    // Initialize security
    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    if (FAILED(hres)) {
        std::cerr << "Failed to initialize security. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return;
    }

    // Get the WMI service
    IWbemLocator* pLoc = NULL;
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&pLoc
    );
    if (FAILED(hres)) {
        std::cerr << "Failed to create IWbemLocator object. Error code = 0x" << std::hex << hres << std::endl;
        CoUninitialize();
        return;
    }

    IWbemServices* pSvc = NULL;
    hres = pLoc->ConnectServer(
        _bstr_t(L"ROOT\\CIMV2"),
        NULL,
        NULL,
        0,
        NULL,
        0,
        0,
        &pSvc
    );
    if (FAILED(hres)) {
        std::cerr << "Could not connect. Error code = 0x" << std::hex << hres << std::endl;
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Set the proxy
    hres = CoSetProxyBlanket(
        pSvc,
        RPC_C_AUTHN_WINNT,
        RPC_C_AUTHZ_NONE,
        NULL,
        RPC_C_AUTHN_LEVEL_CALL,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE
    );
    if (FAILED(hres)) {
        std::cerr << "Could not set proxy blanket. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    // Execute the query
    IEnumWbemClassObject* pEnumerator = NULL;
    hres = pSvc->ExecQuery(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM Win32_PnPEntity WHERE ClassGuid='{4D36E96F-E325-11CE-BFC1-08002BE10318}'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );
    if (FAILED(hres)) {
        std::cerr << "Query for operating system name failed. Error code = 0x" << std::hex << hres << std::endl;
        pSvc->Release();
        pLoc->Release();
        CoUninitialize();
        return;
    }

    IWbemClassObject* pclsObj = NULL;
    ULONG uReturn = 0;
    bool foundDevices = false;
    while (pEnumerator) {
        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
        if (0 == uReturn) {
            break;
        }

        foundDevices = true;
        std::cout << "=== Device Information ===" << std::endl;

        VARIANT vtProp;
        // Get device information
        hr = pclsObj->Get(L"Caption", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::cout << "  Caption: " << std::string(_bstr_t(vtProp.bstrVal)) << std::endl;
            VariantClear(&vtProp);
        }
        else {
            std::cout << "  Caption: N/A" << std::endl;
        }

        hr = pclsObj->Get(L"Description", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::cout << "  Description: " << std::string(_bstr_t(vtProp.bstrVal)) << std::endl;
            VariantClear(&vtProp);
        }
        else {
            std::cout << "  Description: N/A" << std::endl;
        }

        hr = pclsObj->Get(L"Manufacturer", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::cout << "  Manufacturer: " << std::string(_bstr_t(vtProp.bstrVal)) << std::endl;
            VariantClear(&vtProp);
        }
        else {
            std::cout << "  Manufacturer: N/A" << std::endl;
        }

        hr = pclsObj->Get(L"DeviceID", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::cout << "  DeviceID: " << std::string(_bstr_t(vtProp.bstrVal)) << std::endl;
            VariantClear(&vtProp);
        }
        else {
            std::cout << "  DeviceID: N/A" << std::endl;
        }

        hr = pclsObj->Get(L"PNPDeviceID", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::wstring pnpDeviceId = static_cast<const wchar_t*>(_bstr_t(vtProp.bstrVal));
            std::cout << "  PNPDeviceID: " << std::string(_bstr_t(vtProp.bstrVal)) << std::endl;
            VariantClear(&vtProp);

            // Restart the device
            RestartDevice(pnpDeviceId);
        }
        else {
            std::cout << "  PNPDeviceID: N/A" << std::endl;
        }

        hr = pclsObj->Get(L"Status", 0, &vtProp, 0, 0);
        if (SUCCEEDED(hr)) {
            std::cout << "  Status: " << std::string(_bstr_t(vtProp.bstrVal)) << std::endl;
            VariantClear(&vtProp);
        }
        else {
            std::cout << "  Status: N/A" << std::endl;
        }

        std::cout << std::endl;

        pclsObj->Release();
    }

    if (!foundDevices) {
        std::cout << "No pointer devices were found." << std::endl;
    }

    pEnumerator->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
}

int main() {
    // Traverse the registry and modify specific key values
    TraverseAndModifyRegistry();

    // Restart mouse devices
    RestartMouseDevices();

    return 0;
}