import Helper

class SDKProperty:
    def __init__(self, name: str = "", offset: int = 0, size: int = 0, type_name: str = "", is_simple_type: bool = False):
        self.name: str = name
        self.type_name: str = type_name
        self.type_class: 'SDKClass' = None
        self.size: int = size
        self.offset: int = offset
        self.is_struct: bool = False
        self.is_pointer: bool = False
        self.is_enum: bool = False
        self.is_unknown_data: bool = False
        self.is_simple_type: bool = is_simple_type
        self.is_array: bool = False
        self.is_array_of_ptr: bool = False
        self.tArray_data: int = 0
        self.tArray_length: int = 0
        self.tArray_max: int = 0
        self.is_map: bool = False
        self.map_key_type: str = ""
        self.map_key_is_pointer: bool = False
        self.map_value_type: str = ""
        self.map_value_is_pointer: bool = False
        self.is_bit_size: bool = False
        self.bit_number: int = 0
        self.temp_parent_chain = ""
        self.temp_chain_depth: int = 0

    def to_data(self):
        data = {
            "Name": self.name,
            "TypeName": self.type_name,
            "Size": self.size,
            "Offset": self.offset,
            "IsPointer": self.is_pointer,
            "IsEnum": self.is_enum,
            "IsUnknownData": self.is_unknown_data,
            "IsSimpleType": self.is_simple_type,
            "IsArray": self.is_array,
            "IsArrayOfPtr": self.is_array_of_ptr,
            "TArrayData": self.tArray_data,
            "TArrayLength": self.tArray_length,
            "TArrayMax": self.tArray_max,
            "IsMap": self.is_map,
            "MapKeyType": self.map_key_type,
            "MapKeyIsPointer": self.map_key_is_pointer,
            "MapValueType": self.map_value_type,
            "MapValueIsPointer": self.map_value_is_pointer,
            "IsBitSize": self.is_bit_size,
            "BitNumber": self.bit_number,
            "IsStruct": self.is_struct
        }
        return data
    
    def load_data(self, data: dict):
        self.name = data["Name"]
        self.type_name = data["TypeName"]
        self.size = data["Size"]
        self.offset = data["Offset"]
        self.is_pointer = data["IsPointer"]
        self.is_enum = data["IsEnum"]
        self.is_unknown_data = data["IsUnknownData"]
        self.is_simple_type = data["IsSimpleType"]
        self.is_array = data["IsArray"]
        self.is_array_of_ptr = data["IsArrayOfPtr"]
        self.tArray_data = data["TArrayData"]
        self.tArray_length = data["TArrayLength"]
        self.tArray_max = data["TArrayMax"]
        self.is_map = data["IsMap"]
        self.map_key_type = data["MapKeyType"]
        self.map_key_is_pointer = data["MapKeyIsPointer"]
        self.map_value_type = data["MapValueType"]
        self.map_value_is_pointer = data["MapValueIsPointer"]
        self.is_bit_size = data["IsBitSize"]
        self.bit_number = data["BitNumber"]
        self.is_struct = data["IsStruct"]
        
    def get_property_text(self):
        text = f"{self.type_name}"
        if self.is_pointer:
            text += "*"
        if self.is_array:
            if self.is_array_of_ptr:
                text += "*"
            text += "[]"
        text += f" {self.name}"
        if self.is_bit_size:
            text += f" : {self.bit_number}"
        text += f"; {self.offset}({self.size})"
        return text

class SDKClass:
    def __init__(self):
        self.name: str = ""
        self.size: int = 0
        self.inherited_size: int = 0
        self.code_text: list[str] = []
        self.parent: 'SDKClass' = None
        self.owner: 'SDKClass' = None
        self.parent_class_name: str = ""
        self.properties: dict[int, 'SDKProperty'] = {}
        self.functions: list['SDKFunction'] = []
        self.is_updated: bool = False
        self.temp_parent_chain: str = ""
        self.temp_chain_depth: int = 0

        self.is_enum = False
        self.elements: dict[int, str] = {}

    def to_string(self):
        output = []
        if self.is_enum:
            output.append(f"// enum Class {self.name}")
            for element, value in self.elements.items():
                output.append(f"{element}::{value}")
            return output

        output.append(f"// Class {self.name}")
        output.append(f"// Size: {hex(self.size).upper()} (Inherited: {hex(self.inherited_size).upper()})")
        for line in self.code_text:
            output.append(line)
        return output
    
    def get_parent_class(self) -> 'SDKClass':
        if self.is_enum:
            return None

        if self.parent_class_name in Helper.name_class_map.keys():
            self.parent = Helper.name_class_map[self.parent_class_name]
            return self.parent
        else:
            if not self.parent_class_name == "":
                Helper.logger.error(f'getting parent class "{self.parent_class_name}" for class {self.name}')
        return None
        
    def read_class(self, lines: list[str]) -> 'SDKClass':
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
                    class_info.parent_class_name = line.split(":")[1].replace("{", "").strip()
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
                        class_info.properties[property_count] = property
                        property_count += 1
                        continue
                    if enum_name == "BattlingState":
                        property.type_name = "enum"
                        property.is_enum = True
                        property.name = "EFishingRodBattlingState"
                        class_info.properties[property_count] = property
                        property_count += 1
                        continue
                    elif "E" + enum_name in Helper.enum_names:
                        property.type_name = "enum"
                        property.is_enum = True
                        property.name = "E" + enum_name
                        class_info.properties[property_count] = property
                        property_count += 1
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

                class_info.properties[property_count] = property
                property_count += 1

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

        return class_info

    def update(self) -> None:
        if not self.is_updated:
            try:
                if self.is_enum:
                    self.Update(self)
                else:
                    new_class = self.read_class(self.code_text)
                    self.Update(new_class)
                
                Helper.name_class_map[self.name] = self
            except Exception as e:
                Helper.logger.error(f"updating class {self.name}: {e}\n")

    def Update(self, new_class: 'SDKClass') -> None:
        self.name = new_class.name
        self.size = new_class.size
        self.inherited_size = new_class.inherited_size
        self.parent = new_class.parent
        self.parent_class_name = new_class.parent_class_name
        self.properties = new_class.properties
        self.functions = new_class.functions
        self.is_enum = new_class.is_enum
        self.elements = new_class.elements
        self.is_updated = True

class SDKParameter:
    def __init__(self):
        self.name = ""
        self.object_type = ""

    def ToString(self):
        return f"{self.object_type} {self.name}"
        
class SDKFunction:
    def __init__(self):
        self.name = ""
        self.return_type = ""
        self.return_type_is_struct = False
        self.return_type_is_t = False
        self.parameters: list[SDKParameter] = []

    def ToString(self) -> str:
        output = ""
        if self.return_type_is_struct:
            output += "struct "
        output += self.return_type + " " + self.name + "("
        for i, param in enumerate(self.parameters):
            output += param.ToString()
            if i < len(self.parameters) - 1:
                output += ", "
        output += ")"
        return output

        