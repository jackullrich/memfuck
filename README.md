# memfuck
A PoC designed to bypass all usermode hooks in a WoW64 environment.

MemFuck will unmap everything. Then you are free to execute code in an environment free of user-mode hooks.

Just don't rely on Rtl* functions or anything other than Nt* functions :)

To look up syscall numbers for your system, please visit: https://j00ru.vexillium.org/syscalls/nt/64/

Tested on Windows 10 x64 Build 19041.508

To learn more about the project visit:
https://winternl.com/memfuck/
