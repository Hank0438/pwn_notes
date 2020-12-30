# HEVD writeups 

## HEVD exploits
| Done | Vulnerability | x86 Exploit | x64 Exploit | 
| ---- | ------------- | -------- | -------- |
|  | Pool Overflow |  |  |
|  | Use After Free |  |  |
|  | Stack Overflow |  |  |
|  | Type Confusion |  |  |
|  | Integer Overflow |  |  |
|  | Stack Overflow GS |  |  |
|  | Uninitialized Variable |  |  |
|  | Null Pointer Dereference |  |  |
|  | Arbitary Memory Overwrite |  |  |
|  | HackSys Extreme Vulnerable |  |  |

* x64 exploit should bypass SMEP (Supervisor Mode Execution Prevention)

### Exploit Reference



## Windows Kernel Debugging
* The host and guset both are Windows 10 VM.
* The network interface is Virtual Box Host-Only Ethernet Adapter
* Debuggee: 192.168.56.101
* Debugger: 192.168.56.102
* Nice picture from www.nakivo.com
![](https://www.nakivo.com/blog/wp-content/uploads/2019/07/VirtualBox-network-settings-%E2%80%93-VMs-use-the-host-only-network.png)

### Debuggee
In order to install unsigned driver, set Windows OS to test-mode 
```
PS> bcdedit /set testsigning on
PS> bcdedit /debug on
```
Setup debugger information and retrieve the key
```
PS> bcdedit /dbgsettings NET HOSTIP:192.168.56.102 PORT:50000
```
Setup debug through which network interface
Copy `VerifiedNICList.xml` and  `kdnet.exe` from host `C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\` to guest 
```
PS> kdnet.exe
PS> bcdedit /set "{dbgsettings}" busparams b.d.f # choose the Virtual Box Host-Only Adapter
```
Show up the debug setting
```
PS> bcdedit /dbgsettings
```
![](https://i.imgur.com/c0LPQNn.png)

### Debugger

* WinDBG Preview is available on Microsoft Store 
WinDBG Preview -> File -> Attach To Kernel -> Net
![](https://i.imgur.com/sfsPmP9.png)

* Configure kernel symbols
Settings -> Debugging settings
```
srv*c:\symbols*https://msdl.microsoft.com/download/symbols
```
![](https://i.imgur.com/knOb3WI.png)


### Debug Reference
https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-a-network-debugging-connection-automatically




