# Early Bird APC Injection

<a href="https://git.io/typing-svg"><img src="https://readme-typing-svg.demolab.com?font=Fira+Code&pause=1000&width=435&lines=Early+Bird+APC+Injection;Windows+Shellcode+Injector+v1.0;" alt="Typing SVG" /></a>

**Early Bird APC Injection** is a Windows tool that demonstrates the use of Advanced Process Control (APC) injection techniques. This technique allows you to queue a function (or payload) to be executed by a target process thread in an alertable state. The tool scans for a specific process and injects shellcode into it, making use of `QueueUserAPC`. 

This tool is built for educational purposes, malware analysis, and pentesting in controlled environments, offering insight into how APC injection works within Windows. **It should never be used for malicious purposes.**

---

## How it Works

**Early Bird APC Injection** uses the following approach:

1. **Process Creation**: A new process (or existing one) is targeted using `CreateProcessA`.
2. **Memory Allocation**: The tool allocates memory in the remote process using `VirtualAllocEx`.
3. **Shellcode Injection**: The shellcode is written into the allocated memory space using `WriteProcessMemory`.
4. **APC Queueing**: The `QueueUserAPC` function is used to inject and execute the shellcode in the context of the target process's thread.
5. **Process Control**: Uses debugging techniques to control and continue the execution of the target process after injection.

---

## Features

- **APC Injection**: Demonstrates how to queue APCs for a remote process thread.
- **Shellcode Execution**: Injects and executes arbitrary shellcode.
- **Process Debugging**: Leverages process debugging (`DEBUG_PROCESS`) for better control over process flow.
- **Memory Management**: Securely allocates and writes to memory in the target process.

---

## Code Highlights

- **Memory Allocation**: Uses `VirtualAllocEx` to allocate memory in the remote process.
- **Shellcode Writing**: Injects shellcode with `WriteProcessMemory`.
- **Protection Change**: Changes memory protection to `PAGE_EXECUTE_READWRITE` using `VirtualProtectEx`.
- **APC Queueing**: Uses `QueueUserAPC` to queue the injected payload for execution by the target thread.
  
---

## Prerequisites

- **Windows**: The tool is built specifically for Windows environments.
- **C Compiler**: Requires a C compiler like MSVC to compile the source code.
- **Admin Privileges**: Must be run with administrative privileges to interact with remote processes.

---

## Usage

1. Clone the repository:
    ```bash
    git clone https://github.com/yourusername/earlybirdapc-injection.git
    ```

2. Compile the code:
    ```bash
    cl /EHsc earlybirdapc_injection.c
    ```

3. Run the compiled binary, targeting a process (e.g., `RuntimeBroker.exe`):
    ```bash
    earlybirdapc_injection.exe
    ```
Or directly use Visual Studio and run it <3
---

## Disclaimer

This project is strictly for educational purposes and should only be used in a lawful manner within controlled environments. Misuse of this tool can lead to serious legal consequences. The author does not take any responsibility for any damages caused by the use of this tool.

---

## License

This project is licensed under the MIT License.

