
# LOLSpoof

LOLSpoof is a an interactive shell program that automatically spoof the command line arguments of the spawned process.
Just call your incriminate-looking command line LOLBin (e.g. `powershell -w hidden -enc ZwBlAHQALQBwAHIAbwBjAGUA....`) and LOLSpoof will ensure that the process creation telemetry appears legitimate and clear.

![](/Example.png)

> Use only for 64-bit LOLBins

## Why
Process command line is a very monitored telemetry, being thoroughly inspected by AV/EDRs, SOC analysts or threat hunters.

## How
1. Prepares the spoofed command line out of the real one: `lolbin.exe " " * sizeof(real arguments)`
2. Spawns that suspended LOLBin with the spoofed command line
3. Gets the remote PEB address
4. Gets the address of RTL_USER_PROCESS_PARAMETERS struct
5. Gets the address of the command line unicode buffer
6. Overrides the fake command line with the real one
7. Resumes the main thread

## Opsec considerations
Although this simple technique helps to bypass command line detection, it may introduce other suspicious telemetry:
1. Creation of suspended process
2. The new process has trailing spaces (but it's really easy to make it a repeated character or even random data instead)
3. Write to the spawned process with WriteProcessMemory

