#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include "kthook/kthook.hpp"
#include <string>
#include <sstream>
#include <Psapi.h>

using dMainLoop = void(__stdcall*)();
using dSaveSurface = void(__stdcall*)(const char* pDestFile, int destFormat, void* pSrcSurface, void* pSrcPalette, void* pSrcRect);
kthook::kthook_simple<dMainLoop> mainLoopHook;
kthook::kthook_simple<dSaveSurface> saveSurfaceHook;

inline uintptr_t GetSAMP()
{
    static auto address = reinterpret_cast<uintptr_t>(GetModuleHandleA("samp.dll"));
    return address;
}

void ScreenshotSaveSurface(const decltype(saveSurfaceHook)& hook, const char* pDestFile, int destFormat, void* pSrcSurface, void* pSrcPalette, void* pSrcRect)
{
    std::array<std::byte, 16> srcRect;
    std::memcpy(srcRect.data(), pSrcRect, srcRect.size());

    std::thread thread([&hook, destFile = std::string(pDestFile ? pDestFile : ""), destFormat, pSrcPalette, pSrcSurface, srcRect]() mutable
    {
        hook.get_trampoline()(destFile.c_str(), destFormat, pSrcSurface, pSrcPalette, &srcRect);
    });
    thread.detach();
}

uintptr_t FindPattern(const char* pattern, const char* mask, uintptr_t begin, uintptr_t end) {
    size_t patternLength = strlen(mask);
    for (uintptr_t i = begin; i < end - patternLength; ++i) {
        bool found = true;
        for (size_t j = 0; j < patternLength; ++j) {
            if (mask[j] != '?' && pattern[j] != *(char*)(i + j)) {
                found = false;
                break;
            }
        }
        if (found) {
            return i;
        }
    }
    return 0;
}

void ParseSignature(const std::string& signature, std::string& pattern, std::string& mask) {
    std::stringstream ss(signature);
    std::string byte;

    while (ss >> byte) {
        if (byte == "??") {
            pattern += '\0';
            mask += '?';
        }
        else {
            pattern += (char)std::stoi(byte, nullptr, 16);
            mask += 'x';
        }
    }
}

uintptr_t ScanPatternInModule(const std::string& moduleName, const std::string& signature) {
    HMODULE module = GetModuleHandleA(moduleName.c_str());
    if (!module) return 0;

    MODULEINFO moduleInfo;
    GetModuleInformation(GetCurrentProcess(), module, &moduleInfo, sizeof(MODULEINFO));

    std::string pattern;
    std::string mask;
    ParseSignature(signature, pattern, mask);

    uintptr_t baseAddress = reinterpret_cast<uintptr_t>(moduleInfo.lpBaseOfDll);
    uintptr_t moduleSize = static_cast<uintptr_t>(moduleInfo.SizeOfImage);

    return FindPattern(pattern.c_str(), mask.c_str(), baseAddress, baseAddress + moduleSize);
}

void MainLoop(const decltype(mainLoopHook)& hook)
{
    static bool init = false;
    if (!init)
    {
        init = true;

        // Find target address by signature
        uintptr_t address = ScanPatternInModule("samp.dll", "68 ?? ?? ?? ?? 50 E8 ?? ?? ?? ?? 83 C4 0C EB ?? 8B");

        // Delete screen message
        uintptr_t screenMsgAddr = address + 0x6; // call CChat__AddInfoFormatted
        DWORD oldProtect;
        VirtualProtect(reinterpret_cast<LPVOID>(screenMsgAddr), 0x5, PAGE_EXECUTE_READWRITE, &oldProtect);
        memset(reinterpret_cast<void*>(screenMsgAddr), 0x90, 0x5);
        VirtualProtect(reinterpret_cast<LPVOID>(screenMsgAddr), 0x5, oldProtect, &oldProtect);

        // Screen fix
        saveSurfaceHook.set_dest(address - 0xB); // call D3DXSaveSurfaceToFileA
        saveSurfaceHook.set_cb(ScreenshotSaveSurface);
        saveSurfaceHook.install();
    }
    hook.get_trampoline()();
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
	    {
			DisableThreadLibraryCalls(hModule);

            mainLoopHook.set_dest(0x53E968);
            mainLoopHook.set_cb(MainLoop);
            mainLoopHook.install();
	    }
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
