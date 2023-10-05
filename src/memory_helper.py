
import ctypes
import ctypes.wintypes
import struct
import re
import psutil
import globals
from Helper import logger

MAX_PATH = 260
MAX_MODULE_NAME32 = 255
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020

class MODULEENTRY32(ctypes.Structure):
    """
    Windows C-type ModuleEntry32 object used to interact with our game process
    """
    _fields_ = [('dwSize', ctypes.c_ulong),
                ('th32ModuleID', ctypes.c_ulong),
                ('th32ProcessID', ctypes.c_ulong),
                ('GlblcntUsage', ctypes.c_ulong),
                ('ProccntUsage', ctypes.c_ulong),
                ('modBaseAddr', ctypes.c_size_t),
                ('modBaseSize', ctypes.c_ulong),
                ('hModule', ctypes.c_void_p),
                ('szModule', ctypes.c_char * (MAX_MODULE_NAME32+1)),
                ('szExePath', ctypes.c_char * MAX_PATH)]

kernel32 = ctypes.WinDLL('Kernel32', use_last_error=True)
CreateToolhelp32Snapshot = kernel32.CreateToolhelp32Snapshot
CreateToolhelp32Snapshot.reltype = ctypes.c_long
CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]

Module32First = kernel32.Module32First
Module32First.argtypes = [ctypes.c_void_p, ctypes.POINTER(MODULEENTRY32)]
Module32First.rettype = ctypes.c_int

Module32Next = ctypes. windll.kernel32.Module32Next
Module32Next.argtypes = [ctypes. c_void_p, ctypes.POINTER(MODULEENTRY32)]
Module32Next.rettype = ctypes.c_int

CloseHandle = kernel32.CloseHandle
CloseHandle.argtypes = [ctypes.c_void_p]
CloseHandle.rettype = ctypes.c_int

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPCVOID,
                              ctypes.wintypes.LPVOID, ctypes.c_size_t,
                              ctypes.POINTER(ctypes.c_size_t)]
ReadProcessMemory.restype = ctypes.wintypes.BOOL

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.LPVOID,
                               ctypes.c_void_p, ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_size_t)]
WriteProcessMemory.restype = ctypes.wintypes.BOOL

UWORLDPATTERN = "48 8B 05 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 74 06 48 8B 49 70"
GOBJECTPATTERN = "89 0D ? ? ? ? 48 8B DF 48 89 5C 24"
GNAMEPATTERN = "48 8B 1D ? ? ? ? 48 85 DB 75 ? B9 08 04 00 00"

def convert_pattern_to_regex(pattern: str) -> bytes:
    """
    Taking in our standard "pattern" format, convert that format to one that
    can be used in a regex search for those bytes
    :param pattern: the raw string-formatted pattern we want to convert
    :return: Regex-compatible bytes pattern search
    """
    split_bytes = pattern.split(' ')
    re_pat = bytearray()
    for byte in split_bytes:
        if '?' in byte:
            re_pat.extend(b'.')
        else:
            re_pat.extend(re.escape(bytes.fromhex(byte)))
    return bytes(re_pat)

def search_data_for_pattern(data: bytes, raw_pattern: str):
    """
    Convert out raw pattern into an address where that pattern exists in
    memory
    :param data: A large dump of the early process memory
    :param raw_pattern: string-formatted pattern we want to identify the
    location of in memory
    :return: Return the first location of our pattern in the large data scan we
    conducted at memory reader init time.
    """
    return re.search(
        convert_pattern_to_regex(raw_pattern),
        data,
        re.MULTILINE | re.DOTALL
    ).start()

class ReadMemory:
    """
    Class responsible for aiding in memory reading
    """
    def __init__(self, exe_name: str):
        """
        Gets the process ID for the executable, then a handle for that process,
        then we get the base memory address for our process using the handle.

        With the base memory address known, we can then perform our standard
        memory calls (read_int, etc) to get data from memory.

        :param exe_name: The executable name of the program we want to read
        memory from
        """
        self.exe = exe_name
        try:
            self.pid = self._get_process_id()
            self.handle = self._get_process_handle()
            self.base_address = self._get_base_address()
            self.memsize = self._get_process_memory_usage()
            self.reminmemaddress = self.base_address
            self.remaxmemaddress = self.reminmemaddress + self.memsize
            self.minmemaddress = 0
            self.maxmemaddress = self.memsize

            self.build_bases()
            g_name_offset = self.read_ulong(self.base_address + self.g_name_base + 3)
            g_name_ptr = self.base_address + self.g_name_base + g_name_offset + 7
            self.g_name_start_address = self.read_ptr(g_name_ptr)
        except Exception as e:
            logger.error(f"initializing memory reader: {e}")

    def build_bases(self):
        bulk_scan = self.read_bytes(self.base_address, self.memsize)
        self.u_world_base = search_data_for_pattern(bulk_scan, UWORLDPATTERN)
        globals.has_gotten_gworld = True
        self.g_name_base = search_data_for_pattern(bulk_scan, GNAMEPATTERN)
        globals.has_gotten_gnames = True
        del bulk_scan

    def _get_process_id(self):
        """
        Determines the process ID for the given executable name
        """
        for proc in psutil.process_iter():
            if self.exe in proc.name():
                return proc.pid
        raise Exception(f"Cannot find executable with name: {self.exe}")
    
    def is_proc_active(self) -> bool:
        """
        Checks if the process is currently running
        """
        for proc in psutil.process_iter():
            if self.exe in proc.name():
                return True
        return False
    
    def _get_process_memory_usage(self):
        try:
            process = psutil.Process(self.pid)
            memory_info = process.memory_info()
            return memory_info.rss
        except psutil.NoSuchProcess:
            logger.error(f"Process with ID {self.pid} not found.")
        except psutil.AccessDenied:
            logger.error(f"Access denied to process with ID {self.pid}.")

    def _get_process_handle(self):
        """
        Attempts to open a handle (using read and query permissions only) for
        the class process ID
        :return: an open process handle for our process ID (which matches the
        executable), used to make memory calls
        """
        try:
            return kernel32.OpenProcess(PROCESS_QUERY_INFORMATION
                                                      | PROCESS_VM_WRITE
                                                      | PROCESS_VM_READ,
                                                      False, self.pid)
        except Exception as e:
            raise Exception(f"Cannot create handle for pid {self.pid}: "
                            f"Error: {str(e)}")
        
    def _get_base_address(self):
        """
        Using the global ctype constructors, determine the base address
        of the process ID we are working with. In something like cheat engine,
        this is the equivalent of the "SoTGame.exe" portions in
        "SoTGame.exe"+0x15298A. Creates a snapshot of the process, then begins
        to iterate over the modules (.exe/.dlls) until we match the provided
        exe_name
        :return: the base memory address for the process
        """
        module_entry = MODULEENTRY32()
        module_entry.dwSize = ctypes.sizeof(MODULEENTRY32)
        h_module_snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)

        module = Module32First(h_module_snap, ctypes.byref(module_entry))

        if not module:
            CloseHandle(h_module_snap)
            raise Exception(f"Error getting {self.exe} base address: {ctypes.GetLastError()}")
        while module:
            if module_entry.szModule.decode() == self.exe:
                CloseHandle(h_module_snap)
                return module_entry.modBaseAddr
            module_entry = Module32Next(h_module_snap, ctypes.pointer(module_entry))

    def check_process_is_active(self, _):
        """
        Check if the game is still running and if not, exit
        """
        if not self._process_is_active():
            logger.info(f"Appears {self.exe} has been closed. Exiting program.")
            exit(0)

    def _process_is_active(self) -> bool:
        """
        Check if the PID of the game exists
        :return: value indicating the game process is alive or not
        """
        return psutil.pid_exists(self.pid)

    def read_bytes(self, address: int, byte: int) -> bytes:
        """
        Read a number of bytes at a specific address
        :param address: address at which to read a number of bytes
        :param byte: count of bytes to read
        """
        #if not isinstance(address, int):
        #    raise TypeError(f'Address must be int: {address}')
        buff = ctypes.create_string_buffer(byte)
        bytes_read = ctypes.c_size_t()
        ReadProcessMemory(self.handle, ctypes.c_void_p(address),
                          ctypes.byref(buff), byte, ctypes.byref(bytes_read))
        return buff.raw
    
    def read_gname(self, actor_id: int) -> str:
        """
        Looks up an actors name in the g_name DB based on the actor ID provided
        :param int actor_id: The ID for the actor we want to find the name of
        :rtype: str
        :return: The name for the actor
        """
        name_ptr = self.read_ptr(self.g_name_start_address + int(actor_id / 0x4000) * 0x8)
        name = self.read_ptr(name_ptr + 0x8 * int(actor_id % 0x4000))
        return self.read_string(name + 0x10, 64)
    
    def read_fstring(self, stringptr: int):
        stringAddress = self.read_ptr(stringptr)
        charcount = self.read_int(stringptr + 8)
        if charcount > 0 and charcount < 500:
            text = self.read_string(stringAddress, charcount)
            return text
        else:
            return "NoStringFound"

    def read_fname(self, address: int):
        comparisonIndex = self.read_int(address)
        name = self.read_gname(comparisonIndex)
        return name
    
    def read_ftext(self, address: int):
        FTextPtr = self.read_ptr(address)
        f_string = self.read_fstring(FTextPtr)
        return f_string
    
    def write_ftext(self, address: int, string: str):
        FTextPtr = self.read_ptr(address)
        self.write_fstring(FTextPtr, string)
        
    def write_fstring(self, address: int, string: str):
        stringAddress = self.read_ptr(address)
        new_buffer = string.encode('utf-16-le') + b'\x00\x00'

        if not self.write_bytes(stringAddress, new_buffer):
            logger.error("Failed writing bytes")
            return
        if not self.write_int32(address + 8, int(len(new_buffer) / 2)):
            logger.error("Failed writing int32 length")
            return

    def read_string(self, address: int, byteCount: int = 256) -> str:
        """
        Read a number of bytes and convert that to a string up until the first
        occurrence of no data. Useful in getting raw names
        :param address: address at which to read a number of bytes
        :param byte: count of bytes to read, optional as we assume a 50
        byte name
        """
        buffer = self.read_bytes(address, byteCount)
        nullByteIndex = buffer.find(b'\x00')

        if nullByteIndex == 1:
            longer_check = self.read_name_string(address, byteCount)
            if re.match('[A-Za-z0-9_/"]*', longer_check):
                result = longer_check
        elif nullByteIndex < 0:
            return "NoStringFound"
        else:
            result = str("".join(map(chr, buffer[:nullByteIndex])))
        return result

    def read_name_string(self, address: int, byte: int = 32) -> str:
        """
        Used to convert bytes that represent a players name to a string. Player
        names always are separated by at least 3 null characters
        :param address: address at which to read a number of bytes
        :param byte: count of bytes to read, optional as we assume a 32
        byte name
        """
        buff = self.read_bytes(address, byte*2)
        i = buff.find(b"\x00\x00\x00")
        shorter = buff[:i] + b'\x00'
        try:
            joined = shorter.decode('utf-16').rstrip('\x00').rstrip()
        except:
            joined = str("".join(map(chr, shorter)))
        return joined.replace('’', "'")
    
    def read_vector2_obj(self, address: int):
        bytes = self.read_bytes(address, 8)
        unpacked = struct.unpack("<ff", bytes)
        return {"x": unpacked[0]/100, "y": unpacked[1]/100}
    
    def read_vector3_obj(self, address: int):
        bytes = self.read_bytes(address, 12)
        unpacked = struct.unpack("<fff", bytes)
        return {"x": unpacked[0]/100, "y": unpacked[1]/100, 
                           "z": unpacked[2]/100}
    
    def read_vector3(self, address: int) -> str:
        bytes = self.read_bytes(address, 12)
        unpacked = struct.unpack("<fff", bytes)
        return f"({unpacked[0]}, {unpacked[1]}, {unpacked[2]})"
    
    def read_vector2(self, address: int) -> str:
        bytes = self.read_bytes(address, 8)
        unpacked = struct.unpack("<ff", bytes)
        return f"({unpacked[0]}, {unpacked[1]})"
    
    def read_int64(self, address: int):
        read_bytes = self.read_bytes(address, struct.calcsize('q'))
        read_bytes = struct.unpack('<q', read_bytes)[0]
        return read_bytes

    def read_int16(self, address: int):
        read_bytes = self.read_bytes(address, struct.calcsize('h'))
        read_bytes = struct.unpack('<h', read_bytes)[0]
        return read_bytes

    def read_int8(self, address: int):
        read_bytes = self.read_bytes(address, struct.calcsize('b'))
        read_bytes = struct.unpack('<b', read_bytes)[0]
        return read_bytes
    
    def read_int(self, address: int):
        """
        :param address: address at which to read a number of bytes
        """
        read_bytes = self.read_bytes(address, struct.calcsize('i'))
        read_bytes = struct.unpack('<i', read_bytes)[0]
        return read_bytes
    
    def read_ints(self, address: int):
        """
        :param address: address at which to read a number of bytes
        """
        ints = []
        ints.append(self.read_int(address))
        ints.append(self.read_uint32(address))
        ints.append(self.read_int64(address))
        ints.append(self.read_uint64(address))
        ints.append(self.read_int16(address))
        ints.append(self.read_int8(address))
        ints.append(self.read_uint16(address))
        ints.append(self.read_uint8(address))
    
    def read_bool(self, address: int):
        """
        Read a boolean value from the given address.

        :param address: Address at which to read a boolean value.
        :return: The boolean value read from the address.
        """
        read_byte = self.read_bytes(address, 1)
        read_bool = bool(read_byte[0])
        return read_bool
    
    def read_bit_bool(self, address: int, bit: int):
        """
        Read a bit size boolean value from the given address together with a bit index.

        :param address: Address at which to read a bitsize boolean value.
        :return: The bitsize boolean value read from the address.
        """
        by = self.read_bytes(address, 1)[0]
        bo = self.get_bit(by, bit)
        return bo
    
    def get_bit(self, byte: int, bitNum: int = 0):
        return (byte & (1 << bitNum)) != 0
    
    def read_char(self, address: int):
        """
        Read a character value from the given address.

        :param address: Address at which to read a character value.
        :return: The character value read from the address.
        """
        read_bytes = self.read_bytes(address, struct.calcsize('c'))
        read_char = struct.unpack('c', read_bytes)[0]
        return read_char
    
    def read_uint64(self, address: int) -> int:
        """
        Read the UInt64 (8 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 8 bytes of data (UInt64) that live at the provided address
        """
        read_bytes = self.read_bytes(address, struct.calcsize('Q'))
        read_bytes = struct.unpack('<Q', read_bytes)[0]
        return read_bytes
    
    def read_uint32(self, address: int) -> int:
        """
        Read the UInt32 (4 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 4 bytes of data (UInt32) that live at the provided address
        """
        read_bytes = self.read_bytes(address, struct.calcsize('I'))
        read_bytes = struct.unpack('<I', read_bytes)[0]
        return read_bytes
    
    def read_uint16(self, address: int) -> int:
        """
        Read the UInt16 (2 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 2 bytes of data (UInt16) that live at the provided address
        """
        read_bytes = self.read_bytes(address, struct.calcsize('H'))
        read_bytes = struct.unpack('<H', read_bytes)[0]
        return read_bytes
    
    def read_uint8(self, address: int) -> int:
        """
        Read the UInt8 (1 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 1 bytes of data (UInt8) that live at the provided address
        """
        read_bytes = self.read_bytes(address, struct.calcsize('B'))
        read_bytes = struct.unpack('<B', read_bytes)[0]
        return read_bytes

    def convert_to_uintptr(self, address):
        """
        Converts a memory address to a ulonglong pointer in Python using ctypes.
        :param world_address: Memory address to convert
        :return: ulonglong pointer to the memory address
        """
        ptr_type = ctypes.POINTER(ctypes.c_uint)
        return ctypes.cast(address, ptr_type)

    def read_float(self, address: int) -> float:
        """
        Read the float (4 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        """
        read_bytes = self.read_bytes(address, struct.calcsize('f'))
        read_bytes = struct.unpack('<f', read_bytes)[0]
        return read_bytes
    
    def read_double(self, address: int) -> float:
        """
        Read a double-precision floating-point number (8 bytes) at a given address
        and return that data as a float.
        
        :param address: The memory address to read the double from.
        :return: The double-precision floating-point number at the provided address.
        """
        read_bytes = self.read_bytes(address, struct.calcsize('d'))
        read_double = struct.unpack('<d', read_bytes)[0]
        return read_double

    def read_ulong(self, address: int):
        """
        Read the 32 bit uLong (4 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 4-bytes of data (ulong) that live at the provided
        address
        """
        read_bytes = self.read_bytes(address, struct.calcsize('L'))
        read_bytes = struct.unpack('<L', read_bytes)[0]
        return read_bytes
    
    def get_ptr_addr(self, base, offsets: list, *, is_64_bit = True):
        """
        Gets an address from a pointer
        :param base: base address of game + pointer address
        :param offsets: a list of offsets to add to the pointer address to get the final value address
        :param is_64_bit: (Optional) reads as LongLong if True, and as Int if false. Defaults to true
        :return: the address that has been found
        """
        if is_64_bit:
            read_method = self.read_ptr
        else:
            read_method = self.read_int
        addr = read_method(base)
        for offset in offsets[:-1]:
            addr = read_method(addr + offset)
        return addr + offsets[-1]
    
    def read_longlong(self, address: int) -> int:
        """
        Read the LongLong (8 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 8-bytes of data (longlong) that live at the provided
        address
        """
        read_bytes = self.read_bytes(address, struct.calcsize('LL'))
        read_bytes = struct.unpack('<LL', read_bytes)[0]
        return read_bytes

    def read_ptr(self, address: int) -> int:
        """
        Read the uLongLong (8 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 8-bytes of data (ulonglong) that live at the provided
        address
        """
        return struct.unpack('<Q', self.read_bytes(address, struct.calcsize('Q')))[0]
    
    def read_guid(self, address: int) -> tuple [int, int, int, int]:
        """
        Read the guid (4 ints) (16 bytes) at a given address and return that data
        :param address: address at which to read a number of bytes
        :return: the 16-bytes of data (guid) that live at the provided
        address
        """
        guidRaw = self.read_bytes(address, 16)
        guid = struct.unpack("<iiii", guidRaw)
        return guid
    
    def hex_dump(self, data, address=0):
        """
        Helper function to create a hex dump of the given data.
        """
        result = []
        for i in range(0, len(data), 16):
            row = [f'{address+i:08x}:']
            chars = data[i:i+16]
            hex_codes = ' '.join([f'{c:02x}' for c in chars])
            hex_codes += '   ' * (16 - len(chars))
            row.append(hex_codes)
            row.append(''.join([chr(c) if 32 <= c < 127 else '.' for c in chars]))
            result.append(' '.join(row))
        return '\n'.join(result)
    
    simples = ["char", "bool", "float", "int32_t", "int64_t", "uint16_t", "uint32_t", "uint64_t", "FText", "FName", "FString", "bit bool", "double"]
    
    def read_type(self, address: int, data_type: str):
        type_format_mapping = {
            "int32_t": 'i',
            "uint32_t": 'I',
            "int64_t": 'q',
            "uint64_t": 'Q',
            "int16_t": 'h',
            "uint16_t": 'H',
            "int8_t": 'b',
            "uint8_t": 'B',
            "float": 'f',
            "double": 'd'
        }

        if data_type in type_format_mapping:
            format_string = type_format_mapping[data_type]
            read_bytes = self.read_bytes(address, struct.calcsize(format_string))
            value = struct.unpack('<' + format_string, read_bytes)[0]
            return value
        else:
            raise ValueError(f"Unsupported data type: {data_type}")

    def write_bool(self, address: int, value: bool) -> bool:
        """
        Write a BOOL value at a specific address
        :param address: address at which to write the BOOL value
        :param value: BOOL value to write
        """
        if not isinstance(address, int):
            raise TypeError(f'Address must be int: {address}')
        value_ptr = ctypes.pointer(ctypes.c_bool(value))
        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(self.handle, ctypes.c_void_p(address),
                           value_ptr, ctypes.sizeof(ctypes.c_bool),
                           ctypes.byref(bytes_written))
        if bytes_written.value != ctypes.sizeof(ctypes.c_bool):
            print("Failed Writing bool:", bytes_written.value)
            return False
        return True
    
    def write_float(self, address: int, value: float) -> bool:
        if not isinstance(address, int):
            raise TypeError(f'Address must be int: {address}')
        value_ptr = ctypes.pointer(ctypes.c_float(value))
        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(self.handle, ctypes.c_void_p(address),
                           value_ptr, ctypes.sizeof(ctypes.c_float),
                           ctypes.byref(bytes_written))
        if bytes_written.value != ctypes.sizeof(ctypes.c_float):
            print("Failed Writing float:", bytes_written.value)
            return False
        return True
    
    def write_int32(self, address: int, value: int) -> bool:
        if not isinstance(address, int):
            raise TypeError(f'Address must be int: {address}')
        if not isinstance(value, int):
            raise TypeError(f'Value must be int32: {value}')
        value_ptr = ctypes.pointer(ctypes.c_int32(value))
        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(self.handle, ctypes.c_void_p(address),
                           value_ptr, ctypes.sizeof(ctypes.c_int32),
                           ctypes.byref(bytes_written))
        if bytes_written.value != ctypes.sizeof(ctypes.c_int32):
            print("Failed Writing int32:", bytes_written.value)
            return False
        return True
    
    def write_bytes(self, address: int, data: bytes) -> bool:
        if not isinstance(address, int):
            raise TypeError(f'Address must be int: {address}')
        if not isinstance(data, bytes):
            raise TypeError(f'Data must be bytes: {data}')
        
        bytes_written = ctypes.c_size_t()
        buffer = ctypes.create_string_buffer(data)
        
        WriteProcessMemory(
            self.handle,
            ctypes.c_void_p(address),
            buffer,
            len(data),
            ctypes.byref(bytes_written)
        )
        
        if bytes_written.value != len(data):
            print("Failed Writing bytes:", bytes_written.value)
            return False
        
        return True
    
    def write_bit_bool(self, address: int, value: bool, bit_offset: int) -> bool:
        """
        Write a bit-sized BOOL value at a specific address with the given bit offset.

        :param address: Address at which to write the bit-sized BOOL value.
        :param value: BOOL value to write.
        :param bit_offset: Bit offset at which to write the BOOL value (0-7).
        :return: True if the write is successful, False otherwise.
        """
        if not isinstance(address, int):
            raise TypeError(f'Address must be int: {address}')

        if not isinstance(value, bool):
            raise TypeError(f'Value must be bool: {value}')

        if not 0 <= bit_offset <= 7:
            raise ValueError(f'Bit offset must be between 0 and 7: {bit_offset}')

        current_byte = self.read_bytes(address, 1)[0]
        current_byte &= ~(1 << bit_offset)
        if value:
            current_byte |= (1 << bit_offset)
        updated_byte = ctypes.c_byte(current_byte)

        bytes_written = ctypes.c_size_t()
        WriteProcessMemory(self.handle, ctypes.c_void_p(address),
                        ctypes.byref(updated_byte), ctypes.sizeof(ctypes.c_byte),
                        ctypes.byref(bytes_written))

        if bytes_written.value != ctypes.sizeof(ctypes.c_byte):
            print("Failed:", bytes_written.value)
            return False

        return True