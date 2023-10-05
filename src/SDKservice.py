import os
import glob
import Helper
from SDKClasses import SDKClass
from tkinter import messagebox

class SDKService:
    def __init__(self, folder_location: str) -> None:
        self.folder_location = folder_location
        self.has_scanned = False
        self.file_count = 0

    def scan_sdk(self) -> bool:
        """
        Scans through the directory given for any header files, 
        and then parses them all and saves for later use
        """
        if self.has_scanned:
            messagebox.showinfo("Already Scanned", "The sdk is already scanned")
            Helper.logger.warn("SDK already scanned!")
            return False
        
        class_counter = 0

        Helper.logger.info(f"Scanning SDK in folder {self.folder_location}")

        sdk_files = glob.glob(os.path.join(self.folder_location, "*.h"))
        if (len(sdk_files) == 0):
            messagebox.showerror("No files", f"There are no files in {self.folder_location}, please double check")
            Helper.logger.info("No SDK files found")
            exit()
        self.file_count = len(sdk_files)
        Helper.logger.info(f"Files to scan: {self.file_count}")

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
                sdk_class.size = self.get_class_size(class_text)
                Helper.class_size_map[class_name] = sdk_class.size
                Helper.name_class_map[class_name] = sdk_class
                i += class_length
                class_counter += 1
            
        Helper.logger.info(f"Total Classes Read: {class_counter}")

        for classObj in list(Helper.name_class_map.values()):
            classObj.update()

        self.has_scanned = True
        return True
    
    def get_class_size(self, code_text) -> int:
        if any(l.startswith("// Size") for l in code_text):
            line = next(l for l in code_text if l.startswith("// Size"))
            offset_hex = line[9:line.index(" (")]
            size = int(offset_hex, 16)
            return size
        return 0
    
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

        if c.properties is None:
            c.update()
        if c is not None:
            p = [prop for prop in c.properties.values() if prop.name == property_name]
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
        else:
            Helper.logger.error(f'getting Class "{class_name}" from name')

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
            for propId, prop in class_obj.properties.items():
                if prop.name == variable:
                    offset = prop.offset
            
            if offset:
                Helper.class_var_offsets[class_var] = offset
        else:
            offset = Helper.class_var_offsets[class_var]
        
        return offset