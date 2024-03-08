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
        self.super_class_name: str = ""
        self.properties: list['SDKProperty'] = []
        self.functions: list['SDKFunction'] = []
        self.is_updated: bool = False
        self.temp_parent_chain: str = ""
        self.temp_chain_depth: int = 0

        self.is_enum = False
        self.elements: dict[int, str] = {}

        # UEDumper data
        self.code_text: list[str] = []

    def __str__(self) -> str:
        return self.name
    
    def __repr__(self):
        return self.name

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
        self.func: int = 0

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

        