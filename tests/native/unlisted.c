/* A plain unsigned DLL that is on no list: loading it into the guarded JVM must close the
   client with "untrusted_module" (exit code 210). Test fixture only; not part of any build
   that is shipped or signed. */
#include <windows.h>

__declspec(dllexport) int mebet_test_unlisted(void) { return 42; }

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance; (void)reason; (void)reserved;
    return TRUE;
}
