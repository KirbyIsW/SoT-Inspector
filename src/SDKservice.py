import Helper, time, os, glob, json
from SDKClasses import SDKClass, SDKProperty, SDKFunction, SDKParameter
from memory_helper import ReadMemory
from tkinter import messagebox
from typing import Union
import subprocess

simples = ["char", "bool", "float", "int32_t", "int64_t", "uint16_t", "uint32_t", "uint64_t", "FText", "FName", "FString", "bit bool", "double"]

class DumperService:
    def __init__(self, dump_path: str, type: str = "default") -> None:
        """
        :param dump_path: The path of the dump file
        :param type: The type of dump we are using, our and UEDumper dumps are currently supported
        """
        self.path = dump_path
        self.type = type

    def run_dumper(self, argvs: list = []):
        try:
            path = os.path.join(os.path.abspath(self.path), "Dumper.exe")
            args = [path] + argvs
            Helper.logger.info(f"Running dumper at path {path} with argvs {argvs}")
            returncode = subprocess.run(args, check=True)
            returncode = returncode.returncode
            
        except subprocess.CalledProcessError as e:
            Helper.logger.error(f"SubProcess.run() error: {e}")

        Helper.logger.info(f"Dumper ran and exited with exit code {returncode}")

    def is_dumped(self) -> bool:
        path = os.path.join(os.path.abspath(self.path), "dump.dmp")
        return os.path.exists(path)
    
    def should_update_dump(self, gobjects_len: int, min_diff: int = 5000) -> int:
        """
        Returns: 
        >>> 0: "Dont dump at all"
        >>> 1: "Completely new dump"
        >>> Possible 3: "Dump from inside python"
        """
        with open(os.path.join(os.path.abspath(self.path), "dump.dmp"), "r") as fs:
            line = fs.readline()
            fs.close()
        num = int(line.split(" ")[1])

        if gobjects_len == num: # No more objects found
            return 0

        elif gobjects_len < num:
            return 1
        elif abs(gobjects_len - num) > min_diff:
            return 2
        return 0
    
    def get_gobjects_diff(self, gobjects_len: int):
        with open(os.path.join(os.path.abspath(self.path), "dump.dmp"), "r") as fs:
            line = fs.readline()
            fs.close()
            
        num = int(line.split(" ")[1])
        return abs(gobjects_len - num)
    
    def load_dump(self):
        if self.type == "default":
            self.load_inspector_dump()
        elif self.type == "dumper7":
            pass
        elif self.type == "UEDumper":
            self.load_UEDumper_dump()
        else:
            messagebox.showerror("Invalid dump type", "Invalid dump type")
            exit()

    def load_UEDumper_dump(self):
        class_counter = 0

        Helper.logger.info(f"Scanning SDK in folder {self.path}")

        sdk_files = glob.glob(os.path.join(self.path, "*.h"))
        if (len(sdk_files) == 0):
            messagebox.showerror("No files", f"There are no files in {self.path}, please double check")
            Helper.logger.info("No SDK files found")
            exit()
        file_count = len(sdk_files)
        Helper.logger.info(f"Files to scan: {file_count}")

        filter_names = ["BP_CliffGenerator_classes.h"]
        priority_names = ["Athena_classes.h", "Athena_struct.h", "Engine_classes.h", "Engine_struct.h"]
        main_files = [f for f in sdk_files if os.path.basename(f) in priority_names]
        sdk_files = [f for f in sdk_files if os.path.basename(f) not in priority_names + filter_names]
        sdk_files[:0] = main_files

        full_sdk = {}

        Helper.logger.info("Loading SDK files...")
        for f in sdk_files:
            with open(f) as file:
                lines = file.readlines()
                filtered_lines = [line.strip() for line in lines if line.strip()]
                full_sdk[f.split("\\")[-1]] = filtered_lines
        Helper.logger.info("Files Loaded!")

        for file_name, lines in full_sdk.items():
            i = 0
            while i < len(lines):
                class_length = self.get_class_length(lines[i:])
                enum_line: str = lines[i+1]

                if ("enum" in enum_line):
                    sdk_enum = SDKClass()
                    sdk_enum.name = enum_line.split(" ")[2]
                    for x, line in enumerate(lines[i+2:i+class_length-1]):
                        sdk_enum.elements[x] = line.replace(",", "")
                    sdk_enum.is_enum = True
                    Helper.enum_names.append(sdk_enum.name)
                    i += class_length
                    Helper.name_class_map[sdk_enum.name] = sdk_enum
                    continue
                name_line: str = lines[i+2]
                class_name = name_line.split(' ')[1]

                if class_length == -1:
                    Helper.logger.error(f"reading SDK file {file_name} Class {class_name}")
                    break
                class_text = lines[i:i+class_length]
                sdk_class = SDKClass()
                sdk_class.name = class_name
                sdk_class.code_text = class_text
                sdk_class.size = self.get_class_size_UE(class_text)
                Helper.class_size_map[class_name] = sdk_class.size
                Helper.name_class_map[class_name] = sdk_class
                i += class_length
                class_counter += 1
            
        Helper.logger.info(f"Total Classes Read: {class_counter}")

        for classObj in list(Helper.name_class_map.values()):
            lines = classObj.code_text

            class_info = SDKClass()
            property_count = 0
            bit = 0
            bit_offset = 0

            for i, line in enumerate(lines):

                if "};" in line:
                    break
                if len(line) < 3:
                    continue
                if line.startswith("// Size"):
                    offset_hex = line[9:line.index(" (")]
                    class_info.size = int(offset_hex, 16)
                    if "Inherited" in line:
                        inherited_hex = line.split("Inherited: ")[1].replace(")", "").strip()
                        class_info.inherited_size = int(inherited_hex, 16)
                elif line.startswith("//"):
                    name_line: str = lines[i+2]
                    class_info.name = name_line.split(' ')[1]
                elif line.endswith("{"):
                    if ":" in line:
                        class_info.super_class_name = line.split(":")[1].replace("{", "").strip()
                    else:
                        continue
                elif line.endswith(")"):
                    property: SDKProperty = SDKProperty()
                    offset_hex = line.split("; // ")[1].split("(")[0].strip()
                    offset = int(offset_hex, 16)

                    property.offset = offset
                    property_size_hex = line.split("(")[1].replace(")", "").strip()
                    property_size = int(property_size_hex, 16)
                    property.size = property_size

                    saved_line = line

                    
                    line = line.replace("*", "")
                    property_type = line.split(" ")[0]

                    if property.size == 1 and "char" in line and "UnknownData" not in line:
                        enum_name = line.split(" ")[1].replace(";", "").strip()
                        if enum_name == "ServerState":
                            property.type_name = "enum"
                            property.is_enum = True
                            property.name = "EFishingRodServerState"
                            class_info.properties.append(property)
                            continue
                        if enum_name == "BattlingState":
                            property.type_name = "enum"
                            property.is_enum = True
                            property.name = "EFishingRodBattlingState"
                            class_info.properties.append(property)
                            continue
                        elif "E" + enum_name in Helper.enum_names:
                            property.type_name = "enum"
                            property.is_enum = True
                            property.name = "E" + enum_name
                            class_info.properties.append(property)
                            continue

                    if property_type == "struct":
                        property.is_struct = True
                        property.name = line.split(';')[0].split(" ")[-1]
                        _line = line.split(" ")[1]
                        
                        test_line = line.split(" ")[2].replace(";", "").replace(",", "")
                        if ">" in test_line:
                            test_type = test_line.split(">")[0]
                        else:
                            test_type = test_line
                            
                        if (_line == "UClass"):
                            if "Class" in property.name:
                                property.type_name = property.name.replace("Class", "")
                                test: SDKClass = Helper.find_actor_class(property.type_name)
                                if test is not None:
                                    property.type_name = test.name
                                    property.is_pointer = True
                                else:
                                    property.type_name = "UClass"
                                    property.is_pointer = True
                            else:
                                property.type_name = "UClass"
                                property.is_pointer = True
                            property.is_simple_type = False
                        elif "TArray" in _line:
                            temp_array_info = saved_line.split("<")[1].split(">")[0]
                            array_info = line.split("<")[1].split(">")[0]
                            property.is_array = True
                            if (temp_array_info.find("*") != -1):
                                property.is_array_of_ptr = True
                            if ("struct" in array_info):
                                property.type_name = array_info.split(" ")[1]
                                property.is_simple_type = False

                                if property.type_name not in Helper.class_size_map.keys():
                                    property_class = None
                                    if property.type_name in Helper.name_class_map.keys():
                                        property_class = Helper.name_class_map[property.type_name]
                                    if property_class is not None:
                                        property_size = property_class.size
                                    else:
                                        property_size = 0
                                    Helper.class_size_map[property.type_name] = property_size
                                else:
                                    property_size = Helper.class_size_map[property.type_name]

                                property.size = property_size
                            else:
                                property.type_name = array_info
                                property.is_simple_type = True
                        elif "TMap" in _line:
                            property.is_simple_type = False
                            property.is_map = True
                            temp_map_info = saved_line.split("<")[1].split(">")[0]
                            map_info = line.split("<")[1].split(">")[0]

                            property.type_name == "TMap"
                            map_key_type: str = temp_map_info.split(",")[0].strip().replace("struct ", "")
                            map_value_type: str = temp_map_info.split(",")[1].strip().replace("struct ", "")
                            if "*" in map_key_type:
                                property.map_key_is_pointer = True
                                map_key_type = map_key_type.split("*")[0]
                            if "*" in map_value_type:
                                property.map_value_is_pointer = True
                                map_value_type = map_value_type.split("*")[0]
                                
                            property.map_key_type = map_key_type
                            property.map_value_type = map_value_type
                        elif "FName" == test_type or "FString" == test_type or "FText" == test_type:
                            property.type_name = test_type
                            property.is_simple_type = True
                        else:
                            if "*" in saved_line:
                                property.is_pointer = True
                            property.type_name = _line
                            property.is_simple_type = False
                    else:
                        property.type_name = property_type
                        name = line.split(" ")[1].split(";")[0]
                        if (":" in line):
                            property.name = line.split(" ")[1].split(" : ")[0]
                            property.is_bit_size = True
                            if (bit_offset == property.offset):
                                property.bit_number = bit
                                bit += int(line.split(" : ")[1].split(";")[0])
                            else:
                                property.bit_number = 0
                                bit = int(line.split(" : ")[1].split(";")[0])
                            bit_offset = property.offset
                            name = name.split(":")[0].strip()
                        property.is_simple_type = True
                        property.name = name

                    if "UnknownData" in property.name:
                        property.is_unknown_data = True

                    class_info.properties.append(property)

                elif "// Function" in line:
                    function: SDKFunction = SDKFunction()

                    if line.split(" ")[0] == "struct":
                        _line = line[7:]
                        function.return_type_is_struct = True
                        if "TArray" in _line.split(" ")[0]:
                            if ">>" in _line.split("(")[0]:
                                TArray_Type = _line[_line.find("<"):_line.split("(")[0].rfind(">")]
                            else:
                                TArray_Type = _line.split("<")[1].split(">")[0]
                            if "struct" in TArray_Type:
                                function.return_type = _line.split(" ")[0] + " " + _line.split(" ")[1].split("(")[0]
                                function.name = _line.split(" ")[2].split("(")[0]
                            else:
                                function.return_type = _line.split(" ")[0].strip()
                                function.name = line[1:].split(" ")[2].split("(")[0]
                        else:
                            function.return_type = _line.split(" ")[0]
                            function.name = _line[1:].split(" ")[1].split("(")[0]
                    else:
                        function.return_type = line.split(" ")[0]
                        function.name = line[1:].split(" ")[1].split("(")[0]

                    params: list[SDKParameter] = []
                    raw_params = line[line.find('(') + 1 : line.find(')')].split(",")

                    for _param in raw_params: 
                        if (_param == ""):
                            break
                        _param = _param.strip()
                        param = SDKParameter()
                        if _param.find("struct") == 0:
                            if _param.find("TArray") != -1:
                                param.object_type = "struct " + _param.split(" ")[1] + " " +  _param.split(" ")[-2]
                                param.name = _param.split(" ")[-1]
                            else:
                                param.object_type = "struct " + _param.split(" ")[1]
                                param.name = _param.split(" ")[-1]       
                        else:
                            param.object_type = _param.split(" ")[-2]
                            param.name = _param.split(" ")[-1]

                        params.append(param)

                    function.parameters = params
                    class_info.functions.append(function)

            classObj.name = class_info.name
            classObj.size = class_info.size
            classObj.inherited_size = class_info.inherited_size
            classObj.super_class_name = class_info.super_class_name
            classObj.properties = class_info.properties
            classObj.functions = class_info.functions
            classObj.is_enum = class_info.is_enum
            classObj.elements = class_info.elements

    def get_class_size_UE(self, code_text: list[str]) -> int:
        if any(l.startswith("// Size") for l in code_text):
            line = next(l for l in code_text if l.startswith("// Size"))
            offset_hex = line[9:line.index(" (")]
            size = int(offset_hex, 16)
            return size
        return 0

    def load_inspector_dump(self):
        lines: list[str] = []
        with open(os.path.join(os.path.abspath(self.path), "dump.dmp"), "r") as fs:
            lines = fs.readlines()
            lines.pop(0)
            fs.close()

        for line in lines:
            if line[:12] == "New gObjects:":
                continue

            object = eval(line)
            if object["Object Type"] == "enum":
                sdkenum = SDKClass()
                sdkenum.name = object["Name"].replace(" ", "_")
                sdkenum.is_enum = True
                for i in range(len(object["Elements"])):
                    element = object["Elements"][i]
                    sdkenum.elements[i] = element
            else:
                sdkclass = SDKClass()
                sdkclass.name = object["Name"].replace(" ", "_")
                sdkclass.super_class_name = object["Super"]
                sdkclass.size = object["Size"]
                sdkclass.size = object["Size"]
                sdkclass.inherited_size = object["Inherited"]

                bit_idx = 0
                for prop in object["Properties"]:
                    sdkprop = SDKProperty()
                    proptype: str = prop["Type"]

                    name: str = prop["Name"]
                    if " : " in name and (proptype == "char" or proptype == "unknown"):
                        sdkprop.is_bit_size = True
                        split = name.split(" : ")
                        sdkprop.bit_number = bit_idx
                        bit_idx += 1
                        bit_idx = bit_idx % 8
                        name = split[0]
                    elif proptype == "unknown":
                        sdkprop.is_unknown_data = True

                    sdkprop.name = name
                    if proptype.startswith("struct"):
                        sdkprop.is_struct = True
                        proptype = proptype[7:]

                    if proptype.startswith("TArray<"):
                        sdkprop.is_array = True
                        try:
                            inner = proptype.split("<")[1].split(">")[-2]
                        except:
                            inner = proptype.split("<")[1].split(">")[-1]
                        if inner.endswith("*"):
                            sdkprop.is_array_of_ptr = True
                            proptype = inner.replace("*", " ")
                        proptype = proptype.replace("TArray<", "").replace("struct ", "")[:-1]
                    elif proptype.startswith("TMap<"):
                        sdkprop.is_map = True
                        try:
                            inner = proptype.split("<")[1].split(">")[-2]
                        except:
                            inner = proptype.split("<")[1].split(">")[-1]
                        
                        split = inner.replace("struct ", "").split(", ")
                        key = split[0]
                        value = split[1]

                        if "*" in key:
                            sdkprop.map_key_is_pointer = True
                            key = key.replace("*", "")
                        sdkprop.map_key_type = key

                        if "*" in value:
                            sdkprop.map_value_is_pointer = True
                            value = value.replace("*", "")
                        sdkprop.map_value_type = value

                    else:
                        if "*" in proptype:
                            sdkprop.is_pointer = True
                            proptype = proptype.replace("*", "")

                    if proptype in simples:
                        sdkprop.is_simple_type = True

                    sdkprop.type_name = proptype
                    sdkprop.offset = prop["Offset"]
                    sdkprop.size = prop["Size"]

                    sdkclass.properties.append(sdkprop)

                for func in object["Functions"]:
                    sdkfunc = SDKFunction()
                    sdkfunc.name = func["Name"].replace(" ", "_")
                    sdkfunc.return_type = func["ReturnType"].replace("struct ", "")

                    for parm in func["Parameters"]:
                        sdkparm = SDKParameter()
                        sdkparm.name = parm["Name"].replace(" ", "_")
                        sdkparm.object_type = parm["Type"].replace("struct ", "")

                        sdkfunc.parameters.append(sdkparm)

                    sdkfunc.func = func["Func"]

                    sdkclass.functions.append(sdkfunc)

                # Helper.logger.info(f"class {sdkclass.name}{f'({sdkclass.super_class_name})' if sdkclass.super_class_name != 'None' else ''}:")
                # for prop in sdkclass.properties:
                #     Helper.logger.info(f"\t{prop.type_name}{'*' if prop.is_pointer else ''} {prop.name} {hex(prop.offset)}({hex(prop.size)})")
                # Helper.logger.info("")
                # for func in sdkclass.functions:
                #     params = ""
                #     for param in func.parameters:
                #         params += f"{param.object_type} {param.name}, "
                #     if len(func.parameters) > 0:
                #         params = params[:-2]
                #     Helper.logger.info(f"\t{func.return_type} {func.name}({params});")
                # Helper.logger.info("")
                # Helper.logger.info("")

                Helper.name_class_map[sdkclass.name] = sdkclass 
                Helper.class_size_map[sdkclass.name] = sdkclass.size
    
    def get_classes_that_fit(self, size: int) -> dict:
        return {name: value for name, value in Helper.class_size_map.items() if value <= size}

    def get_class_length(self, sdk_lines: list[str]) -> int:
        for i, line in enumerate(sdk_lines):
            if ("}" in line):
                return i + 1
        return -1
    
    def get_property_class(self, class_name, property_name) -> SDKClass:
        """
        Figures out what class a property is and returns the respective SDKClass object
        """
        c = self.get_class_from_name(class_name)

        if c is not None:
            p = [prop for prop in c.properties if prop.name == property_name]
            if p:
                property = p[0]
                property_class = self.get_class_from_name(property.type_name)
                property.type_class = property_class
                return property_class
        return None
    
    def get_class_from_name(self, class_name) -> SDKClass:
        """
        Gets the SDK_Class object binded to any class name
        """
        if class_name is None or class_name == "" or class_name == "FMulticastDelegate" or class_name == "int16_t":
            return None
        
        if class_name in Helper.name_class_map.keys():
            return Helper.name_class_map[class_name]
        #else:
        #    Helper.logger.error(f'getting Class "{class_name}" from name')

        return None
    
    def is_valid_class(self, class_name: str):
        return class_name in Helper.class_size_map
    
    def get_class_size_from_name(self, class_name: str) -> int:
        try:
            return Helper.class_size_map[class_name]
        except:
            return 0
    
    def find_sdk_offset(self, class_var: str) -> int:
        offset = -1
        split = class_var.split(".")
        class_name = split[0]
        variable = split[1]
        if class_var not in Helper.class_var_offsets.keys():
            class_obj: SDKClass = Helper.name_class_map[class_name]
            for prop in class_obj.properties:
                if prop.name == variable:
                    offset = prop.offset
            
            if offset:
                Helper.class_var_offsets[class_var] = offset
        else:
            offset = Helper.class_var_offsets[class_var]
        
        return offset