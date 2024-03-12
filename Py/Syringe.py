
import subprocess
import sys
from ctypes import (byref, c_int, c_long, c_ulong,
                    create_string_buffer, windll)

class Inject:

    PROC_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)
    MEM_CREATE = 0x00001000 | 0x00002000
    MEM_RELEASE = 0x8000
    PAGE_EXECUTE_READWRITE = 0x40


    def __init__(self):

        # Define our Kernel32 Function Call (Kernel Mode Actions)
        self.kernel32 = windll.kernel32

        # Define our User32 Function Call (User Mode Actions)
        self.user32 = windll.user32

        # Variable to hold PID
        self.pid = c_ulong()

        # Dynamic Variable to Handle (HANDLE)
        self.handle = None



    # Create Process from path to the exe and returns the pid to the user
    def create_process(self, path):
        return subprocess.Popen([path]).pid



    # Get the Handle from the PID
    def load_from_pid(self, pid):
        try:
            # Release memory
            self.unload()

            # Set our pid object to a ulong
            self.pid = c_ulong(pid)

            # Open our process handle
            self.handle = self.kernel32.OpenProcess(self.PROC_ALL_ACCESS, 0, pid)

            if not self.handle:
                print("self.handle: Not True")

            #if not self.handle:
            #    raise WinError()
        except Exception as e:
            print(f"load_from_pid() Error: {e}")



    # Unload th
    def unload(self):
        try:
            if self.handle:
                self.kernel32.CloseHandle(self.handle)
                if not self.handle:
                    print("self.handle: Handle isn't true")
            self.handle = None
        except Exception as e:
            print(f"unload() Error: {e}")



    # Allocates remote memory
    def alloc_remote(self, buffer, size):
        try:
            # Allocate remote memory
            alloc = self.kernel32.VirtualAllocEx(self.handle, None, c_int(size),
                                                self.MEM_CREATE, self.PAGE_EXECUTE_READWRITE)
            
            # If allocation is false return an error
            if not alloc:
                print("Allocation has failed")

            # Write empty buffer which will hold the space for our DLL Path
            self.write_memory(alloc, buffer)

            # Return Allocation Address
            return alloc
        except Exception as e:
            print(f"alloc_remote() Error: {e}")

    

    # Free up remote memory
    def free_remote(self, addr, size):
        try:
            # Attempt to Free up remote memory
            if not self.kernel32.VirtualFreeEx(self.handle, addr, c_int(0), self.MEM_RELEASE):
                # If fails prints error
                print("Freeing Remote Memory Failed")
        except Exception as e:
            print(f"free_remote() Error: {e}")



    def get_address_from_module(self, module, function):
        try:
            module_addr = self.kernel32.GetModuleHandleA(module.encode("ascii"))
            if not module_addr:
                print("False Module Address")
            function_addr = self.kernel32.GetProcAddress(module_addr, function.encode("ascii"))
            if not module_addr:
                print("False Module Address")
            return function_addr
        except Exception as e:
            print(f"get_address_from_module Error: {e}")

    

    def create_remote_thread(self, function_addr, args):
        try:
            # Dll Addy in mem
            dll_addr = c_long(0)

            # Use the Remote Allocation Module to allocate memory for our arguments
            args_addr = self.alloc_remote(args, len(args))

            # Attempt to create our thread and store its handle
            thread = self.kernel32.CreateRemoteThread(self.handle, None, None, c_long(function_addr),
                                                    c_long(args_addr), None, None)
            # If thread's handle is false it means it failed to create
            if not thread:
                print("Thread Creation Failed - Step 1 (Thread didn't Create)")

            # Check if our thread handle has timed out
            if self.kernel32.WaitForSingleObject(thread, 0xFFFFFFFF) == 0xFFFFFFFF:
                print("Thread Creation Failed - Step 2 (Thread Timedout)")

            # Check if there is no Termination Status to our thread handle
            if not self.kernel32.GetExitCodeThread(thread, byref(dll_addr)):
                print("Thread Creation Failed - Step 3 (Thread was terminated)")

            # Free our arg's memory
            self.free_remote(args_addr, len(args))

            # Return the the value of the dll addr
            return dll_addr.value
        
        except Exception as e:
            print(f"create_remote_thread Error: {e}")



    def read_memory(self, addr, size):
        try:
            # Create a buffer to store the memory we will read
            buffer = create_string_buffer(size)

            # Attempt to read process memory to our handle process handle
            if not self.kernel32.ReadProcessMemory(self.handle, c_long(addr), buffer, size, None):

                # If we failed return an error message
                print("Failed to read process memory")

            # If all is okay return the memory
            return buffer
        
        except Exception as e:
            print(f"read_memory Error: {e}")



    # Write memory to the process
    def write_memory(self, addr, string):
        try:
            # Get the size of the data we will write into memory
            size = len(string)

            # Write the memory (Attempt)
            if not self.kernel32.WriteProcessMemory(self.handle, addr, string, size, None):

                # If we fail return an error message
                print('Failed to write process memory')

        except Exception as e:
            print(f"write_memory Error: {e}")    



    # LLA Function
    def load_library(self, buffer):
        # Hook
        function_addr = self.get_address_from_module("kernel32.dll", "LoadLibraryA")

        # Create a thread for the function addredd
        dll_addr = self.create_remote_thread(function_addr, buffer)

        # Return its dll_address
        return dll_addr



    # Inject the DLL Utilising our LLA Function
    def inject_dll(self, path):
        return self.load_library(path.encode("ascii"))



    # Call functions from the target process
    def call_from_injected(self, path, dll_addr, function, args):
        function_offset = self.get_offset_of_exported_function(path.encode("ascii"), function)
        self.create_remote_thread(dll_addr + function_offset, args)



    def get_offset_of_exported_function(self, module, function):
        try:
            base_addr = self.kernel32.LoadLibraryA(module)
            if not base_addr:
                print("False Base address")
            function_addr = self.kernel32.GetProcAddress(base_addr, function.encode("ascii"))
            if not function_addr:
                print("False Function Address")
            if not self.kernel32.FreeLibrary(base_addr):
                print("Failed to free lib")
            return function_addr - base_addr
        except Exception as e:
            print(f"get_offset_of_exported_function Error: {e}")
