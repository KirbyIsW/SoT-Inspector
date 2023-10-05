import tkinter as tk
from tkinter import \
    ttk, Tk, Button, Label, Entry, \
    Menu, Toplevel, Listbox, \
    messagebox, simpledialog
from memory_handler import SoTMemoryHandler

import Render, pyglet
from Render import window_handle

from typing import Union

import time, os, json, threading, win32gui, win32api

from classes import *
from SDKservice import *
from SDKClasses import *
import Helper, globals

actor_filters: list[str] = ["Ship"]
simples = ["char", "bool", "float", "int32_t", "int64_t", "uint16_t", "uint32_t", "uint64_t", "FText", "FName", "FString", "bit bool", "double"]
filters = simples + ["FMulticastDelegate"]
fast_update_items_list: list[str] = []
attached_actors: dict[int, str] = {}
scanning_actors: dict[str, bool] = {}
is_tracked_open = False
is_unknowndata_open = False
last_search = ""
exiting = False

name_map: dict[int, str] = {}
comment_map: dict[int, str] = {}

bit64 = ["Hex64", "Int64", "UInt64", "Float" ]
bit32 = ["Hex32", "Int32", "UInt32", "Float" ]
bit16 = ["Hex16", "Int16", "UInt16"          ]
bit8  = ["Hex8" , "Int8" , "UInt8"           ]

tbit64 = ["Hex64", "Int64", "UInt64", "Pointer" ]
tbit32 = ["Hex32", "Int32", "UInt32", "Float"   ]
tbit16 = ["Hex16", "Int16", "UInt16"            ]
tbit8  = ["Hex8" , "Int8" , "UInt8" , "char"    ]

default_types = ["Hex64", "Hex32", "Hex16", "Hex8", "Sep", "Int64", "Int32", "Int16", "Int8", "Sep", "UInt64", "UInt32", "UInt16", "UInt8", "Sep","char", "Float", "Sep", "FVector", "FVector2D", "TArray", "Sep", "Pointer", "Void Pointer", "Class Instance"]
generic_types = ["Int", "Float", "Pointer", "char"]
special_types = ["FVector", "FVector2D", "TArray"]

sdk_path_filters = ["", "path\\to\\your\\sdk"]

handles = []

class RenderObj:
    def __init__(self, address = 0, name = "Tracked Vector", id = ""):
        self.address = address
        self.location = Vector3
        self.name = name
        self.id = id

# Vector testing
tracked_vectors: list[RenderObj] = []

def detect_type(item: str, default_to_actor: bool = True) -> str:
    """
    Tries to detect actor name `item` as a class name

    Parameters:
        item (str): The name of the actor to try
    
    Returns:
        list: If the name was findable
        None: If it was not
    """
    classname: SDKClass = Helper.find_actor_class(item)
    if classname is not None:
        return classname.name
    if default_to_actor:
        return "AActor"
    return None

def detect_type_get(item: str, default_to_actor: bool = True) -> SDKClass:
    sdkclass: SDKClass = Helper.find_actor_class(item)
    if sdkclass is not None:
        return sdkclass
    if default_to_actor:
        return Helper.name_class_map["AActor"]
    return None

def copy_item(label: str) -> None:
    """
    Fixes a label and copies it to 
    the users clipboard
    """
    root.clipboard_clear()

    split = label.split(" ")
    if "valid" in label.lower() or (" : 0x" in label and "->" not in label):
        text = split[0]
    elif "super:" in label.lower():
        text = split[1]
    elif label.startswith("bit bool"):
        text = "char " + split[2]
    else:
        text = split[0] + " " + split[1]

    root.clipboard_append(text.strip())

def remove_item(item: str) -> None:
    """
    Removes an attached actor from
    the inspector tree
    """
    text = inspector_tree.item(item)["text"].split(" ")[-1]
    address = text.strip()
    del attached_actors[int(address, 16)]
    reload_actor_tree()
    search_val(last_search)
    inspector_tree.delete(item)

def copy_item_address(label: str) -> None:
    """
    Gets the address of an item and copies it
    """
    actoraddress = label.split(" ")[0]
    root.clipboard_clear()
    root.clipboard_append(actoraddress)

def attach(item: str) -> str:
    """
    Attaches an item from the `actor_tree`
    to the `inspector_tree`

    Also returns the id of the new inspector tree node
    """
    rawlabel: str = actor_tree.item(item)["text"]
    data = actor_tree.item(item)["values"]
    address = rawlabel.split(" : ")[0]
    actorname = rawlabel.split(" : ")[1].split(" ")[0]
    actor_tree.item(item, tags=("monospaced", "attached"))
    attached_actors[int(address, 16)] = item
    data.append(int(address, 16))
    data.append(actorname)
    inspector_tree_item = inspector_tree.insert("", "end", text=f"{actorname} : {address}", tags=("monospaced",), values=data)
    inspector_tree.insert(inspector_tree_item, "end", text="", tags=("dummy",))
    return inspector_tree_item

def show_actor_context_menu(event):
    """
    Handles showing and loading of
    the `actor_tree`'s context menu
    """
    global actor_context_menu
    del actor_context_menu
    actor_context_menu = Menu(actor_tree, tearoff=False)

    x, y = event.x, event.y
    item = actor_tree.identify("item", x, y)
    if item == "":
        return
    
    raw_label: str = actor_tree.item(item)["text"]
    
    actor_context_menu.add_command(label="Copy", command=lambda: copy_item(raw_label))
    actor_context_menu.add_command(label="Copy Address", command=lambda: copy_item_address(raw_label))

    type_menu = Menu(actor_context_menu, tearoff=False)
    type_menu.add_command(label="Search this class", command= lambda: open_search_all_actors_for_address("OnePath", item))
    type_menu.add_command(label="Search All Actors One Path", command= lambda: open_search_all_actors_for_address("AllActorsOnePath"))
    type_menu.add_command(label="Search All Actors All Paths", command= lambda: open_search_all_actors_for_address("AllActorsAllPaths"))
    actor_context_menu.add_cascade(label="Search For Address", menu=type_menu)

    if int(raw_label.split(" ")[0], 16) not in attached_actors.keys():
        actor_context_menu.add_command(label="Attach", command=lambda: attach(item))
    

    actor_context_menu.post(event.x_root, event.y_root)

def add_to_update_fast(item: str):
    """
    Appends an `item` to the `fast_update_items_list` list
    """
    global fast_update_items_list
    fast_update_items_list.append(item)

def remove_from_update_fast(item: str):
    """
    Removes an `item` from the `fast_update_items_list` list
    """
    global fast_update_items_list
    fast_update_items_list.remove(item)

def remove_list_box_item():
    """
    Removes an item from the vector tracker list box
    """
    global tracked_vectors
    selected_index = tracked_vectors_list_box.curselection()
    if selected_index:
        index = selected_index[0]
        tracked_vectors_list_box.delete(index)
        del tracked_vectors[index]

def change_list_box_item_label():
    global tracked_vectors
    selected_index = tracked_vectors_list_box.curselection()
    if selected_index:
        index = selected_index[0]
        renderobj: RenderObj = tracked_vectors[index]
        entered_string = simpledialog.askstring("Name", "Enter name:", initialvalue=renderobj.name)
        if entered_string == "":
            pass
        elif entered_string is None:
            return
        renderobj.name = entered_string
        reload_vectors_listbox()
    else:
        messagebox.showerror("Select a vector", "Please select a vector to edit.")

def reload_vectors_listbox():
    tracked_vectors_list_box.delete(0, tk.END)
    for renderobj in tracked_vectors:
        label = f'{hex(renderobj.address)} {renderobj.name} {renderobj.location}'
        tracked_vectors_list_box.insert(tk.END, label)

def open_tracked_vectors_window():
    """
    Opens an unusused `FVector` tracker list box
    """
    if not json_config["rendering"]:
        messagebox.showwarning("Unable to start", "Rendering is disabled, please update config.json and restart")
        return

    global is_tracked_open
    def on_toplevel_close():
        # Update the boolean variable when the toplevel window is closed
        global is_tracked_open
        is_tracked_open = False
        vector_window.destroy()
    if not is_tracked_open:
        is_tracked_open = True
        vector_window = Toplevel()
        vector_window.title("Tracked Vectors")
        vector_window.geometry("1000x800")

        vector_window.protocol("WM_DELETE_WINDOW", on_toplevel_close)

        button_frame = ttk.Frame(vector_window)
        button_frame.pack()

        remove_item = Button(button_frame, text="Remove", command=remove_list_box_item)
        remove_item.pack(side='left')
        change_label_button = Button(button_frame, text="Change Label", command=change_list_box_item_label)
        change_label_button.pack(side='left')

        global tracked_vectors_list_box
        tracked_vectors_list_box = Listbox(vector_window, font=("Courier New", 10))
        tracked_vectors_list_box.pack(side="top", fill="both", expand=True)
        reload_vectors_listbox()
    else:
        messagebox.showinfo("Tracked Vectors Window", "Tracked Vectors window is already open.")

def open_search_all_actors_for_address(search_type: str, item_id: str = None):
    while True:
        user_input = simpledialog.askstring("Enter Address", 'Enter address, only number for integer search and prefix with "0x" for hex search')
        if user_input is None:
            return
        user_input = user_input.strip()
        if user_input == "":
            return
        
        address = 0
        
        if user_input.lower()[:2] == "0x":
            try:
                address = int(user_input, 16)
            except:
                messagebox.showerror("Error", f'Invalid input "{user_input}", please try again')
                continue
            break
        else:
            try:
                address = int(user_input)
            except:
                messagebox.showerror("Error", f'Invalid input "{user_input}", please try again')
                continue
            break

    
    if search_type == "AllActorsOnePath" or search_type == "AllActorsAllPaths":
        if address in mem.address_name_map.keys():
            address_search_goto_val(mem.address_name_map[address], address)
            return

    root.title(f"SoT Inspector | Scanning (0%)")
    
    i = 0

    traveled_pointers: list[int] = [address]
    found_vals = {}

    def search_prop_address(mainProp: Union[SDKProperty, SDKClass], address: int, isClass: bool = False, search_address: int = 0, base_address: int = 0):
        propClass = mainProp
        if not isClass:
            propClass = Service.get_class_from_name(mainProp.type_name)

            if not propClass:
                return
            
        if mainProp.temp_chain_depth > 10:
            return
        
        props_to_scan = {}

        for prop in propClass.properties.values():
            prop.temp_parent_chain = mainProp.temp_parent_chain + "." + prop.name
            prop.temp_chain_depth = mainProp.temp_chain_depth + 1

            if address + prop.offset == search_address:
                found_vals[prop.temp_parent_chain] = base_address

            if prop.is_pointer:
                struct_address = mem.rm.read_ptr(address + prop.offset)
                if struct_address == search_address:
                    found_vals[prop.temp_parent_chain] = base_address
                if (address + prop.offset) not in traveled_pointers:
                    if struct_address not in traveled_pointers:
                        if prop.type_name not in simples and struct_address > 0:
                            traveled_pointers.append(address + prop.offset)
                            traveled_pointers.append(struct_address)
                            props_to_scan[struct_address] = prop
            elif prop.type_name in simples:
                continue
            elif prop.is_enum or prop.is_array or prop.is_unknown_data or prop.is_bit_size:
                continue
            else:
                struct_address = address + prop.offset
                props_to_scan[struct_address] = prop

        for addr, property in props_to_scan.items():
            search_prop_address(property, addr, False, search_address, _address)

        if propClass.parent_class_name:
            parentClass = Service.get_class_from_name(propClass.parent_class_name)
            if parentClass:
                parentClass.temp_parent_chain = mainProp.temp_parent_chain + "." + parentClass.name
                parentClass.temp_chain_depth = mainProp.temp_chain_depth + 1
                search_prop_address(parentClass, address, True, search_address, _address)

    if search_type == "AllActorsOnePath" or search_type == "AllActorsAllPaths":

        for _address, actor in mem.address_name_map.items():
            sdkclass = detect_type_get(actor, True)
            sdkclass.temp_parent_chain = actor
            sdkclass.temp_chain_depth = 0
            search_prop_address(sdkclass, _address, True, address, _address)

            i += 1
            if i % 10 == 0:
                root.title(f"SoT Inspector | Scanning: ({round((i / len(mem.address_name_map)) * 100, 2)}%)")
                root.update_idletasks()

            if len(found_vals) > 0:
                if search_type == "AllActorsOnePath":
                    if len(found_vals) > 1:
                        longest_chain = ""
                        connected_addr = ""
                        for chain, address in found_vals.items():
                            split = chain.split(".")
                            if len(split) > longest_chain.split(".") or longest_chain == "":
                                longest_chain = chain
                                connected_addr = address

                        found_vals = {longest_chain: connected_addr}
                    break

        root.title(f"SoT Inspector | Scanning: (100%)")
    else:
        name_in_actor_tree = actor_tree.item(item_id)['text'].split(' ')[2]
        root.title(f"SoT Inspector | Scanning {name_in_actor_tree}...")
        _address = int(actor_tree.item(item_id)['text'].split(' ')[0], 16)
        sdkclass: SDKClass = Helper.name_class_map[actor_tree.item(item_id)["values"][0]]
        sdkclass.temp_parent_chain = name_in_actor_tree
        sdkclass.temp_chain_depth = 0
        search_prop_address(sdkclass, _address, True, address, _address)
        root.title(f"SoT Inspector | Done Scanning {name_in_actor_tree}")

    if len(found_vals) == 0:
        messagebox.showinfo("Unable to find", f"Couldn't find any value connected to the address {hex(address)}")
    elif len(found_vals) == 1:
        chain = list(found_vals.keys())[0]
        actor_address = found_vals[chain]
        address_search_goto_val(chain, actor_address)
    else:
        messagebox.showinfo("Multiple Paths", f"{len(found_vals)} paths found to {hex(address)}, please choose one")
        choose_between_found_addresses(found_vals)

    root.title(f"SoT Inspector")

def choose_between_found_addresses(found_vals: dict):
    choose_window = Toplevel()
    choose_window.title("Choose a Path")
    choose_window.geometry("600x800")

    button_frame = ttk.Frame(choose_window)
    button_frame.pack()

    choose_item = Button(button_frame, text="Choose", command=address_search_goto_val_from_listbox)
    choose_item.pack(side='left')

    global paths_list_box
    paths_list_box = Listbox(choose_window, font=("Courier New", 10))
    paths_list_box.pack(side="top", fill="both", expand=True)

    for chain, address in found_vals.items():
        paths_list_box.insert(tk.END, f"{chain}: {hex(address)}")

def address_search_goto_val_from_listbox():
    selected_index = paths_list_box.curselection()
    if selected_index:
        item_label = paths_list_box.get(selected_index[0])
        chain = item_label.split(":")[0]
        actor_address = int(item_label.split(" ")[1], 16)
        address_search_goto_val(chain, actor_address)

def address_search_goto_val(chain_str: str, address: str):
    split = chain_str.split(".")
    if len(split) == 1:
        # Check if node already attached
        if is_attached(address):
            see_inspected_actor(address)
        else:
            actorNodeId = get_actor_tree_actor_from_address(address)
            attach(actorNodeId)
            see_inspected_actor(address)
    else: # Is a property
        if is_attached(address):
            node_id = get_insp_tree_id_from_address(address)
            close_child_nodes(inspector_tree, node_id)
            inspector_tree.item(node_id, open=False)
            goto_inspector_tree_node(node_id, chain_str)
        else:
            actorNodeId = get_actor_tree_actor_from_address(address)
            nodeid = attach(actorNodeId)
            goto_inspector_tree_node(nodeid, chain_str)

def get_actor_tree_actor_from_address(address: int) -> str:
    reload_actor_tree()
    nodes = actor_tree.get_children()
    for nodestr in nodes:
        node = actor_tree.item(nodestr)

        if int(node["text"].split(" ")[0], 16) == address:
            return nodestr
        
    return ""

def get_insp_tree_id_from_address(address: int):
    nodes = inspector_tree.get_children()
    for nodestr in nodes:
        if address == int(inspector_tree.item(nodestr)["values"][1]): # [1] is index of actor address
            return nodestr
        
    return ""

def is_attached(address) -> bool:
    nodes = inspector_tree.get_children()
    for nodestr in nodes:
        if address == int(inspector_tree.item(nodestr)["values"][1]): # [1] is index of actor address
            return True
    return False

def see_inspected_actor(address):
    nodes = inspector_tree.get_children()
    for nodestr in nodes:
        node = inspector_tree.item(nodestr)
        if address == int(node["values"][1]): # [1] is index of actor address
            inspector_tree.focus(nodestr)
            inspector_tree.see(nodestr)
            inspector_tree.selection_set(nodestr)

def add_to_render_pos_list(address, name, item):
    obj = RenderObj(address, name, item)
    vector = mem.rm.read_vector3_obj(address)
    obj.location = Vector3(vector["x"], vector["y"], vector["z"])
    tracked_vectors.append(obj)

def get_byte_data(address: int) -> dict:
    """
    Loads a `data` dictionary with data about 
    the values of any given `address`
    """
    data = {}
    data["Float"] = mem.rm.read_float(address)
    data["Int64"] = mem.rm.read_int64(address)
    data["Int32"] = mem.rm.read_int(address)
    data["Int16"] = mem.rm.read_int16(address)
    data["Int8"] = mem.rm.read_int8(address)
    data["UInt64"] = mem.rm.read_uint64(address)
    data["UInt32"] = mem.rm.read_uint32(address)
    data["UInt16"] = mem.rm.read_uint16(address)
    data["UInt8"] = mem.rm.read_uint8(address)
    data["Hex64"] = hex(mem.rm.read_uint64(address))
    data["Hex32"] = hex(mem.rm.read_uint32(address))
    data["Hex16"] = hex(mem.rm.read_uint16(address))
    data["Hex8"] = hex(mem.rm.read_uint8(address))
    return data

def read_bytes(address: int, byte_count: int) -> str:
    """
    Raw byte read for Hex nodes
    """
    raw_bytes = mem.rm.read_bytes(address, byte_count)
    formatted_bytes = " ".join(f"{byte:02X}" for byte in raw_bytes)
    return formatted_bytes

def convert_unknown_data_to_dict(data_str: str, byte_count: int = 0):
    """
    Converts a string representation of a dictionary back into the dictionary
    
    Required because tkinter can only pass data through a `values` variable
    that can only store strings 
    \n
    (One improvement that could be made is some kind
    of safe eval() function that can evaluate a\n
    class string: `"<class '__main__.SomeClass'>"`)
    """
    data = {}
    elements = data_str.replace("}", "").replace("{", "").replace("'", "").replace(":", "").split(", ")
    for element in elements:
        split = element.split(" ")
        key = split[0]
        val = split[1]
        if "Hex" in key:
            if "-" in val:
                val = f'-0x{val[3:].upper()}'
            else:
                val = f'0x{val[2:].upper()}'
        if byte_count == 8 and key in bit64:
            data[key] = val
        elif byte_count == 4 and key in bit32:
            data[key] = val
        elif byte_count == 2 and key in bit16:
            data[key] = val
        elif byte_count == 1 and key in bit8:
            data[key] = val
    
    return data

def type_to_byte_count(type: str) -> int:
    """
    Converts a type to a 
    bit count

    Example:
        >>> type_to_byte_count("Float")
        4
    """
    if type in tbit64:
        return 8
    elif type in tbit32:
        return 4
    elif type in tbit16:
        return 2
    elif type in tbit8:
        return 1
    else:
        return Service.get_class_size_from_name(type)

def generate_node_name(node_offset) -> str:
    """
    Generates a node name from a offset.

    Example:
        >>> generate_node_name(5)
        "N00000005"
    """
    name = f'N{node_offset:08X}'
    return name

def byte_to_char(hex_string):
    byte_value = int(hex_string, 16)
        
    if 32 <= byte_value <= 126:
        return chr(byte_value)
    else:
        return "."

def build_type_label(values) -> str:
    """
    Builds a label given some data

    values = ( data, offset, address, bytes, comment, name, bytecount, type, \
               remaining_size, propertyName, propertySize, forced_lines, datatext )
               
    Note:
        Address is the base address of the UnknownData not the address of the property

    Example:
        >>> values = ({"Float": 100.0}, 10, 5000, "", "Important health info", "Health", "Float", ...)
        >>> build_type_label(values)
        0x000A 0x0000000000001392 Float Health = 100.000 // Important info about health
    """
    try:
        data = eval(values[0])
    except:
        data = values[0]
    address = values[1]
    offset = values[2]
    bytes = values[3]
    comment = values[4]
    name = values[5]
    type = values[7]
    datatext = values[12]
    true_address = address + offset
    label = ""
    if type == "Float":
        label = f'0x{offset:04X}  0x{true_address:016X}  {type} {name} = {"{:.3f}".format(data[type])} // {comment}'
    elif type == "Pointer":
        label = f'0x{offset:04X}  0x{true_address:016X}  Ptr {name} -> 0x{data["Hex64"][2:].upper()} // {comment}'
    elif type == "char":
        label = f'0x{offset:04X}  0x{true_address:016X}  {type} {name} = {byte_to_char(data["Hex8"])} (0x{data["Hex8"][2:].upper()}) // {comment}'
    elif type == "FVector":
        label = f'0x{offset:04X}  0x{true_address:016X}  {type} {name} = {mem.rm.read_vector3(true_address)} // {comment}'
    elif type == "FVector2D":
        label = f'0x{offset:04X}  0x{true_address:016X}  {type} {name} = {mem.rm.read_vector2(true_address)} // {comment}'
    elif type == "TArray":
        label = f'0x{offset:04X}  0x{true_address:016X}  {type}<APlayer*> {name} ({mem.rm.read_int(true_address+8)}/{mem.rm.read_int(true_address+12)}) // {comment}'
    elif "Hex" in type:
        if datatext == "":
            label = f'0x{offset:04X}  0x{true_address:016X}  {bytes} // {comment}'
        else:
            label = f'0x{offset:04X}  0x{true_address:016X}  {bytes} /*{comment}*/ {datatext}'
    elif "Int" in type:
        label = f'0x{offset:04X}  0x{true_address:016X}  {type} {name} = {data[type]} 0x{data[f"Hex{type[3:]}"][2:].upper()} // {comment}'
    return label


def copy_value(value):
    """
    Copies any value
    """
    root.clipboard_clear()
    root.clipboard_append(value)

def create_type_change_function(item, type):
    """
    Required function to save a change_type function\n
    (Weird tkinter bug, idrk why it happens but this was the only fix i could find)
    """
    return lambda: change_type(item, type)

def get_chosen_listbox_item(listbox: Listbox, prop: 'UnknownProperty'):
    selected_indices = listbox.curselection()
    if selected_indices:
        index = selected_indices[0]
        chosen_item: str = listbox.get(index)
        subtype = chosen_item.split(":")[0]
        if prop.type == "Class Instance":
            size = int(chosen_item.split(" ")[1])
            prop.size = size
        prop.subtype = subtype

        reload_unknown_data_node(prop.parent_id)
    class_instance_window.destroy()

def open_type_changing_window(filtered_result: dict, prop: 'UnknownProperty'):
    global is_class_instance_window_open
    global class_instance_window
    def on_class_instance_window_close():
        global is_class_instance_window_open
        is_class_instance_window_open = False
        class_instance_window.destroy()
    class_instance_window = Toplevel()
    class_instance_window.title(f"Class Instance")
    class_instance_window.geometry("800x1000")
    class_instance_window.protocol("WM_DELETE_WINDOW", on_class_instance_window_close)
    class_instance_window.grab_set()

    global top_class_frame
    top_class_frame = ttk.Frame(class_instance_window)
    top_class_frame.pack(fill="x")

    search_label = Label(top_class_frame, text="Search:")
    search_label.pack(side="left")

    global search_entry
    search_entry = Entry(top_class_frame)
    search_entry.pack(side="left", fill="x", expand=True)

    search_button = Button(top_class_frame, text="Search", command=lambda: search_dict(search_entry.get(), filtered_result))
    search_button.pack(side="left")

    main_class_frame = ttk.Frame(class_instance_window)
    main_class_frame.pack(side="bottom", fill="both", expand=True)

    class_frame = ttk.Frame(main_class_frame)
    class_frame.pack(fill="both", expand=True)

    global class_list
    class_list = Listbox(class_frame, font=("Courier New", 10))

    choose_button = Button(top_class_frame, text="Choose", command=lambda: get_chosen_listbox_item(class_list, prop))
    choose_button.pack()

    class_list.pack(side="left", fill="both", expand=True)

    scrollbar_frame = ttk.Frame(class_frame)
    scrollbar_frame.pack(side="right", fill="y")
    scrollbar = ttk.Scrollbar(scrollbar_frame, orient="vertical", command=class_list.yview)
    scrollbar.pack(side="right", fill="y")
    class_list.configure(yscrollcommand=scrollbar.set)

    for name, value in filtered_result.items():
        class_list.insert(tk.END, f"{name}: {value}")

def reload_class_list_box(class_dict: dict):
    class_list.delete(0, tk.END)
    for name, value in class_dict.items():
        class_list.insert(tk.END, f"{name}: {value}")

def handle_focus_out(event, toplevel: Toplevel):
    if not hasattr(handle_focus_out, "messagebox_shown"):
        handle_focus_out.messagebox_shown = True
        messagebox.showwarning("Attention", "Please choose an option or close this window.")
        toplevel.focus_force()
        toplevel.after(500, reset_messagebox_flag)

def reset_messagebox_flag():
    handle_focus_out.messagebox_shown = False

def search_dict(query: str, class_dict: dict):
    if query == "":
        reload_class_list_box(class_dict)
        return
    
    newdict = {}
    if "," in query:
        try:
            val = int(query.split(",")[0].strip())
            search = query.split(",")[1].strip()
        except:
            try:
                val = int(query.split(",")[1].strip())
                search = query.split(",")[0].strip()
            except:
                messagebox.showerror("Wrong format", f'Please use either (size, name_filter) or (name_filter, size)')
                return

    for key, value in class_dict.items():
        if "," in query:
            if search.lower() in key.lower() and val == value:
                newdict[key] = value
        else:
            if query.lower() in key.lower() or query == str(value):
                newdict[key] = value
    reload_class_list_box(newdict)

def toggle_bool(address) -> bool:
    current_state = mem.rm.read_bool(address)
    success_state = mem.rm.write_bool(address, not current_state)
    return success_state

def toggle_bit_bool(address, bit) -> bool:
    current_state = mem.rm.read_bit_bool(address, bit)
    mem.rm.write_bit_bool(address, not current_state, bit)

def get_float_input(current_value: float):
    user_input = simpledialog.askfloat("Float Input", "Enter a float value:", initialvalue=current_value)
    return user_input

def get_and_write_float(address: int):
    cur_val = mem.rm.read_float(address)
    value = get_float_input(cur_val)
    if value is not None and isinstance(value, float):
        mem.rm.write_float(address, value)

def get_and_write_int32(address: int):
    cur_val = mem.rm.read_int(address)
    user_input = simpledialog.askinteger("Int Input", "Enter a int value:", initialvalue=cur_val)
    if user_input is not None and isinstance(user_input, int):
        mem.rm.write_int32(address, user_input)

def get_and_write_ftext(address: int):
    cur_string = mem.rm.read_ftext(address)
    user_input = simpledialog.askstring("FText Input", "Enter a string value:", initialvalue=cur_string)
    if user_input is not None:
        mem.rm.write_ftext(address, user_input)

def get_name_from_id(item_id: str):
    """
    Returns a filtered name from any tkinter `item_id`
    """
    text = inspector_tree.item(item_id)["text"]
    if "Super:" in text:
        text = text.split(" ")[1]
    elif " : 0x" in text:
        text = text.split(" ")[0]
    elif " [0x" in text:
        text = text.split(" ")[1]
    return text.replace("*", "")

def get_property_name_from_id(item_id: str) -> str:
    text = inspector_tree.item(item_id)["text"]
    if "Super:" in text:
        text = text.split(" ")[1]
    elif len(text.strip().split(" ")) == 3:
        text = text.split(" ")[1]
    elif " -> " in text:
        text = text.split(" ")[1]
    elif " = " in text:
        text = text.split(" = ")[0].split(" ")[-1]
    elif "TArray<" in text:
        text = text.split(" ")[1]
    return text.strip()

def get_parent_name_chain(item_id: str):
    """
    Gets a chain looking string by following the chain of parent nodes

    Example:
        AActor.UObject.ActorId
    """
    string: str = inspector_tree.item(item_id)["text"].split(" ")[1]
    parent_id = inspector_tree.parent(item_id)
    while parent_id:
        name = get_name_from_id(parent_id)
        if name:
            string = name + "." + string
        item_id = parent_id
        parent_id = inspector_tree.parent(item_id)
    return string

def scan_sdk():
    """
    Scans the sdk located at `sdk_location`
    """
    full_start_time = time.time()
    if not Service.scan_sdk():
        messagebox.showerror("Could not scan SDK", "There was an error scanning the sdk")
        exit()
    
    full_end_time = time.time()
    full_elapsed_time = full_end_time - full_start_time
    Helper.logger.info(f"SDK Scanned with an elapsed time of {round(full_elapsed_time, 4)}")

def close_child_nodes(tree: ttk.Treeview, item_id):
    """
    Closes all child nodes of any node
    """
    sub_items = tree.get_children(item_id)
    for sub_item in sub_items:
        tree.item(sub_item, open=False)
        close_child_nodes(tree, sub_item)

    tree.delete(*sub_items)

def read_type(address: int, data):
    """
    Reads the type at `address`
    """
    if isinstance(data, dict):
        type = data["TypeName"]
    else:
        type = data
    value = None
    if type == "char":
        value = mem.rm.read_char(address)
    elif type == "bool":
        value = mem.rm.read_bool(address)
    elif type == "float":
        value = mem.rm.read_float(address)
    elif type == "int32_t":
        value = mem.rm.read_int(address)
    elif type == "enum":
        value = mem.rm.read_uint8(address)
    elif type == "uint16_t":
        value = mem.rm.read_uint16(address)
    elif type == "uint32_t":
        value = mem.rm.read_uint32(address)
    elif type == "int64_t":
        value = mem.rm.read_int64(address)
    elif type == "uint64_t":
        value = mem.rm.read_uint64(address)
    elif type == "FName":
        value = mem.rm.read_fname(address)
    elif type == "FText":
        value = mem.rm.read_ftext(address)
    elif type == "FString":
        value = mem.rm.read_fstring(address)
    elif type == "double":
        value = mem.rm.read_double(address)
    
    return value

def get_unknown_data_prop_size(type) -> int:
    if "64" in type:
        return 8
    elif "32" in type:
        return 4
    elif "16" in type:
        return 2
    elif "8" in type:
        return 1
    elif type == "Pointer":
        return 8
    elif type == "Float":
        return 4
    elif type == "TArray":
        return 16
    else:
        return Service.get_class_size_from_name(type)

class UnknownProperty:
    def __init__(self, address = 0, offset = 0, type = "Hex64", name = "", comment = "", id = 0) -> None:
        self.address = address
        self.offset = offset
        self.type = type
        self.name = name
        self.comment = comment
        self.size = 0
        self.values = {}
        self.bytes = ""
        self.expandable = False
        self.subtype = ""
        self.template_prop = False

        self.buffer: int = 0

        self.id = id
        self.node_id = ""
        self.parent_id = ""

    def get_data_text(self) -> str:
        data_text = ""
        if self.size >= 4:
            float_value = self.values["Float"]
            formatted_float_value = "{:.3f}".format(float_value) if -999999.0 < float_value < 999999.0 else "#####"
            data_text += formatted_float_value
            if self.size == 4:
                data_text += f' {self.values["Int32"]} 0x{self.values["Hex32"][2:].upper()}'
            elif self.size == 8:
                data_text += f' {self.values["Int64"]} 0x{self.values["Hex64"][2:].upper()}'
        return data_text

    def build_label(self) -> str:
        pre_text = f'0x{self.offset:04X}  0x{self.address+self.offset:016X}  '
        if "Hex" in self.type:
            data_text = self.get_data_text()
            if data_text == "":
                label = f'{pre_text}{self.bytes} // {self.comment}'
            else:
                label = f'{pre_text}{self.bytes} /*{self.comment}*/ {data_text}'
        elif self.type == "Float":
            label = f'{pre_text}{self.type} {self.name} = {"{:.3f}".format(self.values[self.type])} // {self.comment}'
        elif self.type == "Pointer":
            label = f'{pre_text}Ptr {self.name} <{self.subtype}> -> 0x{self.values["Hex64"][2:].upper()} // {self.comment}'
        elif self.type == "Void Pointer":
            label = f'{pre_text}Ptr {self.name} <void> -> 0x{self.values["Hex64"][2:].upper()} // {self.comment}'
        elif self.type == "char":
            label = f'{pre_text}{self.type} {self.name} = {byte_to_char(self.values["Hex8"])} (0x{self.values["Hex8"][2:].upper()}) // {self.comment}'
        elif self.type == "FVector":
            label = f'{pre_text}{self.type} {self.name} = {mem.rm.read_vector3(self.address+self.offset)} // {self.comment}'
        elif self.type == "FVector2D":
            label = f'{pre_text}{self.type} {self.name} = {mem.rm.read_vector2(self.address+self.offset)} // {self.comment}'
        elif self.type == "Class Instance":
            label = f'{pre_text}Instance {self.name} <{self.subtype}> // {self.comment}'
        elif self.type == "TArray":
            label = f'{pre_text}{self.type}<{self.subtype}> {self.name} ({mem.rm.read_int(self.address+self.offset+8)}/{mem.rm.read_int(self.address+self.offset+12)}) // {self.comment}'
        elif "UInt" in self.type:
            label = f'{pre_text}{self.type} {self.name} = {self.values[self.type]} 0x{self.values[f"Hex{self.type[4:]}"][2:].upper()} // {self.comment}'
        elif "Int" in self.type:
            label = f'{pre_text}{self.type} {self.name} = {self.values[self.type]} 0x{self.values[f"Hex{self.type[3:]}"][2:].upper()} // {self.comment}'
        return label
    
    def check_template(self):
        self.template_prop = False
        if self.type == "TArray": self.template_prop = True
        elif self.type == "Pointer": self.template_prop = True
        elif self.type == "Class Instance": self.template_prop = True
        return self.template_prop
    
    def check_expandable(self):
        self.expandable = False
        if self.type == "TArray" and self.subtype: 
            length = mem.rm.read_int(self.address+self.offset+8)
            if length > 0 and length < 1000:
                self.expandable = True

        elif self.type == "Pointer" and self.subtype: self.expandable = True
        elif self.type == "Void Pointer": self.expandable = True
        elif self.type == "Class Instance" and self.subtype: self.expandable = True
        return self.expandable
    
    def update(self, type: str, offset: int = None, expandable: bool = None, buffer: int = None) -> None:
        if expandable is not None:
            self.expandable = expandable

        if offset is not None:
            self.offset = offset
            
        self.type = type
        if self.type == "Class Instance":
            self.size = Service.get_class_size_from_name(self.subtype)
            if self.size <= 0:
                self.size = 8
        elif self.type == "Void Pointer":
            self.size = 8
            self.buffer = buffer
        else:
            self.size = get_unknown_data_prop_size(type)
            self.bytes = read_bytes(self.address + self.offset, self.size)

        self.check_template()
        self.check_expandable()

        return self
    
unknown_data_props: dict[str, list[UnknownProperty]] = {}
unknown_data_order: dict[str, dict[int, UnknownProperty]] = {}

def prev_prop(property: UnknownProperty) -> UnknownProperty:
    if property.id-1 < 0:
        return None
    try:
        return unknown_data_props[get_parent_name_chain(property.parent_id)][property.id-1]
    except:
        return None

def next_prop(property: UnknownProperty) -> UnknownProperty:
    try:
        return unknown_data_props[get_parent_name_chain(property.parent_id)][property.id+1]
    except:
        return None
    
def get_data_text(values: dict, size: int) -> str:
    data_text = ""
    if size >= 4:
        float_value = values["Float"]
        formatted_float_value = "{:.3f}".format(float_value) if -999999.0 < float_value < 999999.0 else "#####"
        data_text += formatted_float_value
        if size == 4:
            data_text += f' {values["Int32"]} 0x{values["Hex32"][2:].upper()}'
        elif size == 8:
            data_text += f' {values["Int64"]} 0x{values["Hex64"][2:].upper()}'
    return data_text

def change_type(item: str, type: str) -> None:
    """
    Tries to change the a node to a different type
    and handles structuring of the following nodes
    """
    parent_id = inspector_tree.parent(item)
    parent_values = inspector_tree.item(parent_id)["values"]
    chain_str = get_parent_name_chain(parent_id)
    offset = int(inspector_tree.item(item)["text"].split(" ")[0], 16)
    property: UnknownProperty = unknown_data_order[chain_str][offset]
    vals = eval(parent_values[0])
    current_type = property.type
    remaining_bytes = int(vals["Size"]) - property.offset

    if type == "Void Pointer":
        buffer_size = simpledialog.askinteger("Buffer size", "Enter the amount of bytes you want to read", initialvalue=256)
        property.update(type, None, True, buffer_size)
        reload_unknown_data_node(parent_id)
        return

    size = Service.get_class_size_from_name(type)

    if current_type == type:
        return
    
    o = property.offset

    if type == "Class Instance":
        property.subtype = ""
        property.update(type)
        class_items_that_fit = Service.get_classes_that_fit(remaining_bytes)
        sorted_dict = dict(sorted(class_items_that_fit.items(), key=lambda item: item[1], reverse=True))
        open_type_changing_window(sorted_dict, property)
    
    if type in special_types:
        if not remaining_bytes < size:
            property.update(type)
    
    elif type == "Hex64":
        if not remaining_bytes < 8:
            property.update(type)

    # Hex64 ->
    elif current_type in tbit64:
        if type in tbit64:
            property.update(type)
        elif type in tbit32:
            property.update(type)
            next_prop(property).update("Hex32", o+4)
        elif type in tbit16:
            property.update(type)
            property = next_prop(property)
            if property:
                property.update("Hex32", o+2)
            property = next_prop(property)
            if property:
                property.update("Hex16", o+6)
        elif type in tbit8:
            property.update(type)
            property = next_prop(property)
            if property:
                property.update("Hex32", o+1)
            property = next_prop(property)
            if property:
                property.update("Hex16", o+5)
            property = next_prop(property)
            if property:
                property.update("Hex8", o+7)
        else:
            if not remaining_bytes < size:
                property.update(type)

    # Hex32 ->
    elif current_type in tbit32:
        if type in tbit32:
            property.update(type)
        elif type in tbit64:
            if not remaining_bytes < 8:
                property.update(type)
        elif type in tbit16:
            property.update(type)
            next_prop(property).update("Hex16", o+2)
        elif type in tbit8:
            property.update(type)
            property = next_prop(property)
            if property:
                property.update("Hex16", o+1)
            property = next_prop(property)
            if property:
                property.update("Hex8", o+3)
        else:
            if not remaining_bytes < size:
                property.update(type)
    # Hex16 ->
    elif current_type in tbit16:
        if type in tbit16:
            property.update(type)
        elif type in tbit64:
            if not remaining_bytes < 8:
                property.update(type)
        elif type in tbit32:
            if not remaining_bytes < 4:
                property.update(type)
        elif type in tbit8:
            property.update(type)
            next_prop(property).update("Hex8", o+1)
        else:
            if not remaining_bytes < size:
                property.update(type)

    # Hex8 ->
    elif current_type in tbit8:
        if type in tbit8:
            property.update(type)
        elif type in tbit64:
            if not remaining_bytes < 8:
                property.update(type)
        elif type in tbit32:
            if not remaining_bytes < 4:
                property.update(type)
        elif type in tbit16:
            if not remaining_bytes < 2:
                property.update(type)
        else:
            if not remaining_bytes < size:
                property.update(type)

    else:
        if not remaining_bytes < size:
            property.update(type)
    
    if not property.check_template():
        property.subtype = ""
    reload_unknown_data_node(parent_id)

def reload_unknown_data_order_dict(chain_str):
    keys_to_remove = {}

    for offset, prop in unknown_data_order[chain_str].items():
        if not offset == prop.offset:
            keys_to_remove[offset] = prop.offset

    for offset, new_offset in keys_to_remove.items():
        unknown_data_order[chain_str][new_offset] = unknown_data_order[chain_str].pop(offset)

def reload_unknown_data_node(node_id):
    inspector_tree.delete(*inspector_tree.get_children(node_id))
    values = inspector_tree.item(node_id)["values"]
    data = eval(values[0])

    remaining_size = data["Size"]
    address = int(values[1])

    chain_str = get_parent_name_chain(node_id)
    reload_unknown_data_order_dict(chain_str)

    id = 0
    offset = 0
    while remaining_size > 0:
        if offset in unknown_data_order[chain_str].keys():
            prop = unknown_data_order[chain_str][offset]
            prop.offset = offset
            label = prop.build_label()
            prop.bytes = read_bytes(prop.address + prop.offset, prop.size)
            prop.values = get_byte_data(prop.address + prop.offset)
            values = (prop.id,)
            insert = inspector_tree.insert(node_id, "end", text=label, tags=("monospaced",), values=values)
            if prop.check_expandable():
                inspector_tree.insert(insert, "end", text="", tags=("dummy",))
            prop.node_id = insert
            offset += prop.size
            remaining_size -= prop.size
        else:
            chunk_sizes = [8, 4, 2, 1]
            this_address = address + offset
            values = ()
            for chunk_size in chunk_sizes:
                if remaining_size >= chunk_size:
                    bytes = read_bytes(this_address, chunk_size)
                    data = get_byte_data(this_address)
                    if chunk_size == 8:
                        type = "Hex64"
                    elif chunk_size == 4:
                        type = "Hex32"
                    elif chunk_size == 2:
                        type = "Hex16"
                    elif chunk_size == 1:
                        type = "Hex8"
                    comment = ""
                    
                    values = (id,)
                    name = generate_node_name(offset)
                    prop = UnknownProperty(address, offset, type, name, comment, id)
                    prop.values = data
                    prop.size = chunk_size
                    prop.bytes = bytes
                    prop.parent_id = node_id
                    unknown_data_props[chain_str].append(prop)
                    unknown_data_order[chain_str][prop.offset] = prop

                    nodeid = inspector_tree.insert(node_id, "end", text=prop.build_label(), tags=("monospaced",), values=values)
                    prop.node_id = nodeid
                    offset += chunk_size
                    remaining_size -= chunk_size
                    id += 1
                    break
                else:
                    continue

def edit_comment(item_id: str, property: UnknownProperty) -> None:
    """
    Edits the comment on the right clicked node

    See Also:
        - :func:`edit_name`: For editing the name of the node
    """
    previous_comment = property.comment
    entered_string = simpledialog.askstring("Comment", "Enter comment:", initialvalue=previous_comment)
    if entered_string == "":
        pass
    elif entered_string is None:
        return
    property.comment = entered_string
    comment_map[property.offset] = entered_string
    edited_label = property.build_label()
    inspector_tree.item(item_id, text=edited_label)

def edit_name(item_id: str, property: UnknownProperty) -> None:
    """
    Edits the name on the right clicked node

    See Also:
        - :func:`edit_comment`: For editing the comment of the node
    """
    previous_name = property.name
    entered_string = simpledialog.askstring("Edit Name", "Enter name:", initialvalue=previous_name)
    if entered_string == "":
        pass
    elif entered_string is None:
        return
    property.name = entered_string
    label = property.build_label()
    name_map[property.offset] = entered_string
    inspector_tree.item(item_id, text=label)

def fast_update_loop():
    """
    The fast update loop for updating the 
    `inspector_tree` nodes
    """
    global fast_update_items_list
    if len(fast_update_items_list) > 0:
        for item in fast_update_items_list:
            try:
                parent = inspector_tree.parent(item)
                if parent:
                    is_opened = inspector_tree.item(parent, "open")
                    if is_opened:
                        raw_data: str = inspector_tree.item(item)["values"]
                        data: dict = eval(raw_data[0])
                        address = int(raw_data[1])
                        type_name = data["TypeName"] 
                        name = data["Name"]
                        size = data["Size"]
                        value = read_type(address, type_name)
                        if data["IsBitSize"]:
                            bool = mem.rm.read_bit_bool(address, data["BitNumber"])
                            prop_text = f"bit bool {name} = {bool}"
                        elif data["IsEnum"]:
                            enum_obj: SDKClass = Helper.name_class_map[name]
                            value = read_type(address, type_name)
                            try:
                                value_text = enum_obj.elements[value]
                            except:
                                continue
                            prop_text = f"{type_name} {name} = {value_text} ({value})"
                        else:
                            prop_text = f"{type_name} {name} = {value} [{hex(size)}]"
                        inspector_tree.item(item, text=prop_text)
                    else:
                        fast_update_items_list.remove(item)
                else:
                    fast_update_items_list.remove(item)
            except:
                fast_update_items_list.remove(item)
    mem.update_idle_disconnect()
    if globals.idle_disconnect == False:
        text = "Disable Anti AFK"
    else:
        text = "Enable Anti AFK"
    idle_dc_button.configure(text=text)

    # global exiting
    # if not exiting:
    #     if win32api.GetAsyncKeyState(0x23) & 0x8000:
    #         Helper.logger.info("[END] Pressed, exiting")
    #         exiting = True
    #         messagebox.showinfo("[END] Pressed", "End Pressed, exiting")
    #         exit()
    # else:
    #     return

    root.after(50, fast_update_loop)

def update_inspector_tree_nodes():
    """
    Updates the nodes in the 
    `inspector_tree` TreeView
    """
    stack = list(inspector_tree.get_children())

    while stack:
        item = stack.pop()
        parent = inspector_tree.parent(item)
        state = inspector_tree.item(parent, "open")
        sub_items = inspector_tree.get_children(item)
        if state:
            item_data = inspector_tree.item(item)["values"]
            try:
                data: dict = eval(item_data[0])
                
                address = int(item_data[1])
                offset = int(data["Offset"])
                type_name = data["TypeName"]
                name = data["Name"]
                size = data["Size"]
                if data["IsSimpleType"] and "UnknownData" not in name and not data["IsArray"]:
                    value = read_type(address, type_name)
                    if data["IsBitSize"]:
                        bool = mem.rm.read_bit_bool(address, data["BitNumber"])
                        prop_text = f"bit bool {name} = {bool}"
                    else:
                        prop_text = f"{type_name} {name} = {value} [{hex(size)}]"
                    inspector_tree.item(item, text=prop_text)
                elif data["IsEnum"]:
                    enum_obj: SDKClass = Helper.name_class_map[name]
                    value = read_type(address, type_name)
                    value_text = enum_obj.elements[value]
                    prop_text = f"{type_name} {name} = {value_text} ({value}) [{hex(size)}]"
                    inspector_tree.item(item, text=prop_text)
                elif data["IsPointer"]:
                    address = int(item_data[2])
                    address_pointed_to = mem.rm.read_ptr(address)
                    prop_text = f"{type_name}* {name} : {hex(address)} -> {hex(address_pointed_to)}"
                    inspector_tree.item(item, text=prop_text)
            except: pass

        stack.extend(reversed(sub_items))

    root.after(1000, update_inspector_tree_nodes)

def change_sub_type(prop: UnknownProperty):
    parent_values = inspector_tree.item(prop.parent_id)["values"]
    data = eval(parent_values[0])
    size = data["Size"]
    remaining_size = size - prop.offset
    if prop.type == "Class Instance":
        class_items_that_fit = Service.get_classes_that_fit(remaining_size)
    else:
        class_items_that_fit = Helper.class_size_map
    sorted_dict = dict(sorted(class_items_that_fit.items(), key=lambda item: item[1], reverse=True))
    open_type_changing_window(sorted_dict, prop)

def reload_scan_listbox(dictionary: dict):
    value_list.delete(0, tk.END)
    for name, value in dictionary.items():
        value_list.insert(tk.END, f"{name}: {value}")

def scan_actor_for_val(actorName: str, search_val: str, search_type, value_type: str, actor: SDKClass, address: int):
    traveled_pointers: list[int] = [address]
    found_vals = {}
    add_all = False

    def search_prop_address(mainProp: Union[SDKProperty, SDKClass], address: int, isClass: bool = False):
        propClass = mainProp
        if not isClass:
            propClass = Service.get_class_from_name(mainProp.type_name)

            if not propClass:
                return
            
        if mainProp.temp_chain_depth > 10:
            return
        
        props_to_scan = {}

        for prop in propClass.properties.values():
            prop.temp_parent_chain = mainProp.temp_parent_chain + "." + prop.name
            prop.temp_chain_depth = mainProp.temp_chain_depth + 1

            if address + prop.offset == search_val:
                found_vals[prop.temp_parent_chain] = f'{hex(search_val)}'

            if prop.is_pointer:
                struct_address = mem.rm.read_ptr(address + prop.offset)
                if struct_address == search_val:
                    found_vals[prop.temp_parent_chain] = f'->{hex(search_val)}'
                if (address + prop.offset) not in traveled_pointers:
                    if struct_address not in traveled_pointers:
                        if prop.type_name not in simples and struct_address > 0:
                            traveled_pointers.append(address + prop.offset)
                            traveled_pointers.append(struct_address)
                            props_to_scan[struct_address] = prop
            elif prop.type_name in simples:
                continue
            elif prop.is_enum or prop.is_array or prop.is_unknown_data or prop.is_bit_size:
                continue
            else:
                struct_address = address + prop.offset
                props_to_scan[struct_address] = prop

        for addr, property in props_to_scan.items():
            search_prop_address(property, addr)

        if propClass.parent_class_name:
            parentClass = Service.get_class_from_name(propClass.parent_class_name)
            if parentClass:
                parentClass.temp_parent_chain = mainProp.temp_parent_chain + "." + parentClass.name
                parentClass.temp_chain_depth = mainProp.temp_chain_depth + 1
                search_prop_address(parentClass, address, True)

    def search_prop_val(mainProp: Union[SDKProperty, SDKClass], address: int, isClass: bool = False):
        propClass = mainProp
        if not isClass:
            propClass = Service.get_class_from_name(mainProp.type_name)

            if not propClass:
                return
            
        if mainProp.temp_chain_depth > 10:
            return
        
        props_to_scan = {}
        
        for prop in propClass.properties.values():
            prop.temp_parent_chain = mainProp.temp_parent_chain + "." + prop.name
            prop.temp_chain_depth = mainProp.temp_chain_depth + 1
            if prop.is_pointer:
                if (address + prop.offset) not in traveled_pointers:
                    struct_address = mem.rm.read_ptr(address + prop.offset)
                    if struct_address not in traveled_pointers:
                        if prop.type_name not in simples and struct_address > 0:
                            traveled_pointers.append(address + prop.offset)
                            traveled_pointers.append(struct_address)
                            props_to_scan[struct_address] = prop

            elif prop.type_name in simples:
                if prop.type_name.lower() == value_type.lower() or (value_type == "Int" and "int" in prop.type_name.lower()):
                    prop_address = address + prop.offset
                    if value_type == "FString":
                        val = mem.rm.read_fstring(prop_address)
                    elif value_type == "FName":
                        val = mem.rm.read_fname(prop_address)
                    elif value_type == "FText":
                        val = mem.rm.read_ftext(prop_address)
                    else:
                        val = mem.rm.read_type(prop_address, prop.type_name)
                        if prop.type_name == "Float":
                            found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name} = 0.0'

                    if not val:
                        if add_all:
                            found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name} = {val}'
                        continue

                    if add_all:
                        found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name} = {val}'

                    elif value_type == "FString" or value_type == "FName" or value_type == "FText":
                        if search_val.lower() in val.lower():
                            found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name} = {val}'
                    
                    elif value_type == "Float" or value_type == "Double":
                        if round(float(search_val), 3) == round(val, 3):
                            found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name} = {val}'

                    elif value_type == "Int":
                        search_val_int = int(search_val)
                        if val == search_val_int:
                            found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name} = {val}'

                    elif value_type == "Hex":
                        search_val_int = int(search_val, 16)
                        val = mem.rm.read_type(prop_address, prop.type_name)
                        if val == search_val_int:
                            found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name} = {hex(val)}'

                        

            elif prop.is_enum or prop.is_array or prop.is_unknown_data or prop.is_bit_size:
                continue
            else:
                struct_address = address + prop.offset
                props_to_scan[struct_address] = prop

        for addr, property in props_to_scan.items():
            search_prop_val(property, addr)

        if propClass.parent_class_name:
            parentClass = Service.get_class_from_name(propClass.parent_class_name)
            if parentClass:
                parentClass.temp_parent_chain = mainProp.temp_parent_chain + "." + parentClass.name
                parentClass.temp_chain_depth = mainProp.temp_chain_depth + 1
                search_prop_val(parentClass, address, True)

        return

    def search_prop_name(mainProp: Union[SDKProperty, SDKClass], address: int, isClass: bool = False):
        propClass = mainProp
        if not isClass:
            propClass = Service.get_class_from_name(mainProp.type_name)

            if not propClass:
                return
            
        if mainProp.temp_chain_depth > 10:
            return
        
        props_to_scan = {}

        for prop in propClass.properties.values():
            prop.temp_parent_chain = mainProp.temp_parent_chain + "." + prop.name
            prop.temp_chain_depth = mainProp.temp_chain_depth + 1
            if prop.is_pointer:
                if search_val.lower() in prop.name.lower():
                    found_vals[prop.temp_parent_chain] = f'{prop.type_name}* {prop.name}'

                if (address + prop.offset) not in traveled_pointers:
                    struct_address = mem.rm.read_ptr(address + prop.offset)
                    if struct_address not in traveled_pointers:
                        if prop.type_name not in simples and struct_address > 0:
                            traveled_pointers.append(address + prop.offset)
                            traveled_pointers.append(struct_address)
                            props_to_scan[struct_address] = prop

            elif prop.is_enum or prop.is_array or prop.is_unknown_data or prop.is_bit_size or prop.type_name in simples:
                if search_val.lower() in prop.name.lower():
                    found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name}'

            else:
                struct_address = address + prop.offset
                props_to_scan[struct_address] = prop

        for addr, property in props_to_scan.items():
            search_prop_name(property, addr)
        
        if propClass.parent_class_name:
            parentClass = Service.get_class_from_name(propClass.parent_class_name)
            if parentClass:
                parentClass.temp_parent_chain = mainProp.temp_parent_chain + "." + parentClass.name
                parentClass.temp_chain_depth = mainProp.temp_chain_depth + 1
                search_prop_name(parentClass, address, True)

        return

    def search_prop_type(mainProp: Union[SDKProperty, SDKClass], address: int, isClass: bool = False):
        propClass = mainProp
        if not isClass:
            propClass = Service.get_class_from_name(mainProp.type_name)

            if not propClass:
                return
            
        if mainProp.temp_chain_depth > 10:
            return
        
        props_to_scan = {}

        for prop in propClass.properties.values():
            prop.temp_parent_chain = mainProp.temp_parent_chain + "." + prop.name
            prop.temp_chain_depth = mainProp.temp_chain_depth + 1

            if prop.is_pointer:
                if search_val.lower() in prop.type_name.lower():
                    found_vals[prop.temp_parent_chain] = f'{prop.type_name}* {prop.name}'

                if (address + prop.offset) not in traveled_pointers:
                    struct_address = mem.rm.read_ptr(address + prop.offset)
                    if struct_address not in traveled_pointers:
                        if prop.type_name not in simples and struct_address > 0:
                            traveled_pointers.append(address + prop.offset)
                            traveled_pointers.append(struct_address)
                            props_to_scan[struct_address] = prop

            elif prop.is_enum or prop.is_array or prop.is_unknown_data or prop.is_bit_size or prop.type_name in simples:
                if search_val.lower() in prop.type_name.lower():
                    found_vals[prop.temp_parent_chain] = f'{prop.type_name} {prop.name}'
            else:
                struct_address = address + prop.offset
                props_to_scan[struct_address] = prop

        for addr, property in props_to_scan.items():
            search_prop_type(property, addr)

        if propClass.parent_class_name:
            parentClass = Service.get_class_from_name(propClass.parent_class_name)
            if parentClass:
                parentClass.temp_parent_chain = mainProp.temp_parent_chain + "." + parentClass.name
                parentClass.temp_chain_depth = mainProp.temp_chain_depth + 1
                search_prop_type(parentClass, address, True)

        return


    if search_val == "":
        add_all = True

    try:
        actor.temp_parent_chain = actorName
        actor.temp_chain_depth = 0

        if search_type == "Value":
            search_prop_val(actor, address, True)
        elif search_type == "Address":
            if search_val.startswith("0x"):
                search_val = int(search_val, 16)
            else:
                search_val = int("0x" + search_val, 16)
            if address == search_val:
                found_vals[actor.temp_parent_chain] = f'{hex(search_val)}'
            search_prop_address(actor, address, True)
        elif search_type == "Property Name":
            if search_val == "":
                messagebox.showerror("Enter a name", f'Please enter a name or part of a name when searching using "{search_type}"')
                return
            search_prop_name(actor, address, True)
        elif search_type == "Property Type":
            if search_val == "":
                messagebox.showerror("Enter a type", f'Please enter a typename or part of a typename when searching using "{search_type}"')
                return
            search_prop_type(actor, address, True)
    except Exception as e:
        messagebox.showerror("Error", f'Error: {e}')
        return

    reload_scan_listbox(found_vals)

def init_scan(name: str, type, address):
    actorClass = Service.get_class_from_name(type)
    search_value = scan_search_entry.get()
    search_value_type = value_type_clicked.get()
    search_type = search_type_clicked.get()
    scan_actor_for_val(name, search_value, search_type, search_value_type, actorClass, address)

def search_actor_for_val_screen(item: str):
    node = inspector_tree.item(item)
    actor_type = node["values"][0]
    actor_name = node["text"].split(" ")[0]
    actor_address = int(node["values"][1])

    if actor_name in scanning_actors.keys():
        if scanning_actors[actor_name]:
            messagebox.showerror(f"Already scanning {actor_name}", f'{actor_name} is already getting scanned')
            return

    scanning_actors[actor_name] = True

    global scan_window

    def on_scan_window_close():
        scanning_actors[actor_name] = False
        scan_window.destroy()
    scan_window = Toplevel()
    scan_window.title(f"Actor Scanner: {node['text'].split(' ')[0]}")
    scan_window.geometry("1200x1000")
    scan_window.protocol("WM_DELETE_WINDOW", on_scan_window_close)

    main_frame = ttk.Frame(scan_window)
    main_frame.pack(fill="both", expand=True)

    listbox_frame = ttk.Frame(main_frame)
    listbox_frame.pack(side="left", fill="both", expand=True)

    scrollbarY = ttk.Scrollbar(listbox_frame, orient="vertical")
    scrollbarX = ttk.Scrollbar(listbox_frame, orient="horizontal")

    global value_list
    value_list = Listbox(listbox_frame, font=("Courier New", 10))
    listbox_frame.grid_rowconfigure(0, weight=1)
    listbox_frame.grid_columnconfigure(0, weight=1)
    value_list.grid(row=0, column=0, sticky=tk.N+tk.S+tk.E+tk.W)

    value_list.configure(yscrollcommand=scrollbarY.set)
    value_list.configure(xscrollcommand=scrollbarX.set)

    scrollbarY.config(command=value_list.yview)
    scrollbarX.config(command=value_list.xview)

    scrollbarY.grid(row=0, column=1, sticky=tk.N+tk.S)
    scrollbarX.grid(row=1, column=0, sticky=tk.E+tk.W)

    search_button = Button(main_frame, text="Scan", command=lambda: init_scan(actor_name, actor_type, actor_address))
    search_button.pack(anchor='w')

    search_label = Label(main_frame, text="Value:")
    search_label.pack(anchor='w')

    search_entry_frame = ttk.Frame(main_frame)
    search_entry_frame.pack(fill='x')

    global scan_search_entry
    scan_search_entry = Entry(search_entry_frame)
    scan_search_entry.pack(fill="x", padx=10)

    search_type_options = [
        "Value",
        "Value",
        "Address",
        "Property Name",
        "Property Type"
    ]

    global search_type_clicked
    search_type_clicked = tk.StringVar()
    search_type_clicked.set(search_type_options[1])

    search_type_dd = ttk.OptionMenu(search_entry_frame, search_type_clicked, *search_type_options)
    search_type_dd.pack(anchor="w")


    value_type_options = [
        "Float",
        "Float",
        "Int",
        "Double",
        "Hex",
        "FString",
        "FName",
        "FText"
    ]

    global value_type_clicked
    value_type_clicked = tk.StringVar()
    value_type_clicked.set(value_type_options[2])

    value_type_dd = ttk.OptionMenu(search_entry_frame, value_type_clicked, *value_type_options)
    value_type_dd.pack(anchor="w")

    goto_button = Button(main_frame, text="Go to selected", command=lambda: goto_selected_scan_entry(item))
    goto_button.pack(anchor="w")

def goto_selected_scan_entry(item_id: str):
    selected_index = value_list.curselection()
    if selected_index:
        if not goto_inspector_tree_node(item_id, value_list.get(selected_index[0])):
            messagebox.showerror("Failed", f'Failed opening the node')
    else:
        messagebox.showerror("Select Item", f'Please select an item from the listbox')

def goto_inspector_tree_node(item_id: str, chain_str: str, index: int = 1) -> bool:
    try:
        steps = chain_str.split(":")[0].split(".")
        inspector_tree.focus(item_id)
        inspector_tree.see(item_id)
        inspector_tree.selection_set(item_id)

        if index < len(steps):
            on_insp_node_open()
            step = steps[index]
            for node in inspector_tree.get_children(item_id):
                name = get_property_name_from_id(node)
                if name.strip() == step:
                    goto_inspector_tree_node(node, chain_str, index+1)
    except Exception as e:
        Helper.logger.error(f"Error in {goto_inspector_tree_node.__name__} ([{index}]): {e}")
        return False

    return True

def figure_out_class_item(item_id: str, address: int):
    tree_node = inspector_tree.item(item_id)
    old_name = get_name_from_id(item_id)
    raw_name = mem.rm.read_fname(address + 24)

    raw_name = detect_type(raw_name, False)
    if not raw_name:
        raw_name = detect_type(mem.rm.read_fname(mem.rm.read_ptr(address + 0x10) + 24), False)
    if not raw_name:
        messagebox.showerror("Class failed", "Failed to figure out class name")
        return

    if old_name == raw_name:
        messagebox.showinfo("Same class", "Correct class already in place")
        return
    filters = ["None", "Class", None]
    if raw_name not in filters:
        type_name = Helper.find_class_name(raw_name)

        if type_name != "":
        
            inspector_tree.item(item_id, open=False)

            new_label = f'{type_name}*' + tree_node["text"].split("*")[1]

            old_values = tree_node["values"]
            new_values = old_values
            property_data = eval(old_values[0])
            property_data["TypeName"] = type_name
            new_values[0] = property_data
            new_values.append(old_name)

            inspector_tree.item(item_id, text=new_label, values=new_values)
            return
    messagebox.showerror("Class failed", "Failed to figure out class name")

def reset_class_item(item_id: str):
    tree_node = inspector_tree.item(item_id)
    inspector_tree.item(item_id, open=False)

    old_values = tree_node["values"]
    new_values = old_values
    property_data = eval(old_values[0])
    old_name = new_values.pop()
    property_data["TypeName"] = old_name
    new_values[0] = property_data

    new_label = f'{old_name}*' + tree_node["text"].split("*")[1]
    inspector_tree.item(item_id, text=new_label, values=new_values)

def figure_out_actor_class(item_id: str):
    tree_node = inspector_tree.item(item_id)
    inspector_tree.item(item_id, open=False)

    old_values = tree_node["values"]
    old_name = get_name_from_id(item_id)
    address: int = old_values[1]

    raw_name = mem.rm.read_fname(mem.rm.read_ptr(address + 0x10) + 24)

    if old_name == raw_name:
        messagebox.showinfo("Same class", "Correct class already in place")
        return
    
    filters = ["None", "Class", None]
    if raw_name not in filters:
        type_name = Helper.find_class_name(raw_name)

        if old_name == type_name:
            messagebox.showinfo("Same class", "Correct class already in place")
            return

        if type_name != "":
            if type_name not in Helper.name_class_map:
                messagebox.showinfo("Error", f"Unable to find class {type_name} in SDK. Possible outdated SDK dump?")
                return

            inspector_tree.item(item_id, open=False)

            new_label = f'{type_name} : ' + tree_node["text"].split(" : ")[1]

            new_values = old_values
            new_values.append(old_name)

            inspector_tree.item(item_id, text=new_label, values=new_values)
            return

    messagebox.showerror("Error", "Failed to figure out actor class")
    
def reset_actor_class(item_id: str):
    tree_node = inspector_tree.item(item_id)
    inspector_tree.item(item_id, open=False)

    old_values = tree_node["values"]
    old_name = old_values.pop()

    new_label = f'{old_name} : ' + tree_node["text"].split(" : ")[1]

    new_values = old_values

    inspector_tree.item(item_id, text=new_label, values=new_values)

def reset_unknown_data_node(item_id: str):
    chain_str = get_parent_name_chain(item_id)
    unknown_data_order[chain_str].clear()
    inspector_tree.item(item_id, open=False)
    inspector_tree.focus(item_id)
    on_insp_node_open()

def show_insp_context_menu(event: tk.Event):
    """
    Handles showing and loading of
    the `inspector_tree`'s context menu
    """
    global insp_context_menu
    del insp_context_menu
    insp_context_menu = Menu(inspector_tree, tearoff=False)

    x, y = event.x, event.y
    item = inspector_tree.identify("item", x, y)
    if not item:
        return
    inspector_tree.selection_set(item)
    rawlabel: str = inspector_tree.item(item)["text"]
    values = inspector_tree.item(item)["values"]

    if len(values) == 1 and isinstance(values[0], int):
        parent_id = inspector_tree.parent(item)
        chain_str = get_parent_name_chain(parent_id)
        offset = int(rawlabel.split(" ")[0], 16)
        property = unknown_data_order[chain_str][offset]

        type_menu = Menu(insp_context_menu, tearoff=False)
        for type in default_types:
            if type == "Sep":
                type_menu.add_separator()
            else:
                type_menu.add_command(label=type, command=create_type_change_function(item, type))
        insp_context_menu.add_cascade(label="Change Type", menu=type_menu)
        if not property.template_prop:
            state="disabled"
        else: state="active"
        insp_context_menu.add_command(label="Change Subtype", command=lambda: change_sub_type(property), state=state)

        insp_context_menu.add_separator()

        insp_context_menu.add_command(label="Copy", command=lambda: copy_value(property.type + " " + property.name))
        insp_context_menu.add_command(label="Copy Offset", command=lambda: copy_value(hex(property.offset)))
        insp_context_menu.add_command(label="Copy Address", command=lambda: copy_value(hex(property.address+property.offset)))
        insp_context_menu.add_separator()

        if "Hex" in property.type:
            state="disabled"
        else: state="active"
        insp_context_menu.add_command(label="Change Name", command=lambda: edit_name(item, property), state=state)
        insp_context_menu.add_command(label="Comment", command=lambda: edit_comment(item, property))
        
        try:
            data = convert_unknown_data_to_dict(property.values, property.size)
            if data:
               insp_context_menu.add_separator()
            for key, value in data.items():
               text = f'{key}: {value}'
               insp_context_menu.add_command(label=text, state="disabled")
        except: pass

    else:
        insp_context_menu.add_command(label="Copy", command=lambda: copy_item(rawlabel))
        if values:
            address = values[1]
            insp_context_menu.add_command(label="Copy Address", command=lambda: copy_value(hex(address)))
            try:
                try:
                    offset = int(values[2], 16)
                except:
                    offset = int(eval(values[0])["Offset"])
                insp_context_menu.add_command(label="Copy Offset", command=lambda: copy_value(hex(offset)))
            except: pass
            try:
                data = eval(values[0])
                if data["TypeName"] == "bit bool":
                    bit = data["BitNumber"]
                    insp_context_menu.add_command(label="Copy Bit Offset", command=lambda: copy_value(bit))
            except: pass
        if " : 0x" in rawlabel and "->" not in rawlabel:
            if len(values) == 4:
                insp_context_menu.add_command(label=f"Reset to {values[3]}", command=lambda: reset_actor_class(item))
            else:
                insp_context_menu.add_command(label="Figure out class", command=lambda: figure_out_actor_class(item))
            insp_context_menu.add_command(label="Search for value", command=lambda: search_actor_for_val_screen(item))
            insp_context_menu.add_command(label="Remove", command=lambda: remove_item(item))

        try:
            data = eval(values[0])
            if "UnknownData" in data["Name"] and data["TypeName"] != "bit bool":
                insp_context_menu.add_separator()
                insp_context_menu.add_command(label="Reset", command=lambda: reset_unknown_data_node(item))
            if data["TypeName"] == "bool":
                insp_context_menu.add_command(label="Toggle Bool", command=lambda: toggle_bool(address))
            if data["TypeName"] == "bit bool":
                bit = data["BitNumber"]
                insp_context_menu.add_command(label="Toggle Bit Bool", command=lambda: toggle_bit_bool(address, bit))
            if data["TypeName"] == "FText":
                insp_context_menu.add_command(label="Write FText", command=lambda: get_and_write_ftext(address))
            if data["TypeName"] == "float":
                insp_context_menu.add_command(label="Change Value (Risky)", command=lambda: get_and_write_float(address))
            if data["TypeName"] == "int32_t":
                insp_context_menu.add_command(label="Change Value (Risky)", command=lambda: get_and_write_int32(address))
            if data["IsSimpleType"] and "UnknownData" not in data["Name"] or data["IsEnum"]:
                if item not in fast_update_items_list:
                    insp_context_menu.add_command(label="Add to fast update loop", command=lambda: add_to_update_fast(item))
                else:
                    insp_context_menu.add_command(label="Remove from fast update loop", command=lambda: remove_from_update_fast(item))
            if data["TypeName"] == "FVector":
                if json_config["rendering"]:
                    insp_context_menu.add_command(label="Track Vector", command=lambda: add_to_render_pos_list(address, data["Name"], item))
                else:
                    insp_context_menu.add_command(label="Track Vector (Rendering Disabled)", state="disabled", command=lambda: add_to_render_pos_list(address, data["Name"], item))
            if data["IsStruct"] and not data["IsArray"] and data["IsPointer"]:
                if len(values) == 4:
                    insp_context_menu.add_command(label=f"Reset to {values[3]}", command=lambda: reset_class_item(item))
                else:
                    insp_context_menu.add_command(label="Figure out type", command=lambda: figure_out_class_item(item, address))

        except Exception as e:
            pass
    insp_context_menu.post(event.x_root, event.y_root)

def on_insp_node_open_init(event: tk.Event):
    on_insp_node_open()

def on_insp_node_open():
    """
    Main inspector function, handles opening, reading and loading whenever you open a node.\n
    Should definetly refactor
    """
    tree = inspector_tree

    item_id = tree.focus()
    tree.delete(*tree.get_children(item_id))
    tree.item(item_id, open=True)
    
    node_item = tree.item(item_id)
    node_name = node_item["text"].split(" ")[0]
    if node_name == "Super:":
        node_name = node_item["text"].split(" ")[1]

    node_data = node_item["values"]
    try:
        if len(node_data) == 5:
            if node_data[4] == "TPair":
                data = node_data[0]
                key_address = node_data[1]
                value_address = node_data[2]
                pair_index = node_data[3]

                if isinstance(data, str):
                    data: dict = eval(data)

                map_key_type = data["MapKeyType"]
                map_key_is_pointer = data["MapKeyIsPointer"]
                map_value_type = data["MapValueType"]
                map_value_is_pointer = data["MapValueIsPointer"]

                final_key_address = key_address
                final_value_address = value_address

                key_text = f'{map_key_type} : {hex(final_key_address)}'
                value_text = f'{map_value_type} : {hex(final_value_address)}'
                
                if map_key_is_pointer:
                    final_key_address = mem.rm.read_ptr(key_address)
                    key_text = f'{map_key_type}* : {hex(key_address)} -> {hex(final_key_address)}'
                elif map_key_type in simples:
                    simple_value = read_type(final_key_address, map_key_type)
                    key_text = f"{map_key_type} = {simple_value}"

                if map_value_is_pointer:
                    final_value_address = mem.rm.read_ptr(value_address)
                    value_text = f'{map_value_type}* : {hex(value_address)} -> {hex(final_value_address)}'
                elif map_value_type in simples:
                    simple_value = read_type(final_value_address, map_value_type)
                    value_text = f"{map_value_type} = {simple_value}"

                key_prop_data = (map_key_type, final_key_address)
                key_item_insert = tree.insert(item_id, "end", text=key_text, tags=("monospaced",), values=key_prop_data)
                if map_key_type not in simples:
                    tree.insert(key_item_insert, "end", text="", tags=("dummy",))

                value_prop_data = (map_value_type, final_value_address)
                value_item_insert = tree.insert(item_id, "end", text=value_text, tags=("monospaced",), values=value_prop_data)
                if map_value_type not in simples:
                    tree.insert(value_item_insert, "end", text="", tags=("dummy",))
                return
            
        data, address = node_data[0], node_data[1]
        try:
            converted_data: dict = eval(data)
            state = True
        except:
            state = False

        if data == "FVector": 
            state = False

        if state:
            converted_data: dict = eval(data)
            object_is_simple = converted_data["IsSimpleType"]

            type_name: str = converted_data["TypeName"]
            if converted_data["IsArray"]:
                array_data: int = converted_data["TArrayData"]
                array_length: int = converted_data["TArrayLength"]
                is_array_of_ptr: bool = converted_data["IsArrayOfPtr"]
                for i in range(array_length):
                    if is_array_of_ptr:
                        item_address = mem.rm.read_ptr(array_data + (i * 8))
                        text = f"{type_name} : {hex(array_data + (i * 8))} -> {hex(item_address)}"
                    else:
                        typesize = Service.get_class_size_from_name(type_name)
                        item_address = array_data + (i * typesize)
                        if object_is_simple or type_name in simples:
                            simple_value = read_type(item_address, type_name)
                            text = f"{type_name} = {simple_value}"
                        else:
                            text = f"{type_name} : {hex(item_address)}"

                    data = (type_name, item_address)
                    item_insert = tree.insert(item_id, "end", text=text, tags=("monospaced",), values=data)
                    if not object_is_simple and type_name not in simples:
                        tree.insert(item_insert, "end", text="", tags=("dummy",))
            elif converted_data["IsEnum"]:
                enum_obj: SDKClass = Helper.name_class_map[converted_data["Name"]]
                for idx, element in enum_obj.elements.items():
                    parent_insert = tree.insert(item_id, "end", text=f"{idx} {element}", tags=("monospaced",))
                pass
            elif converted_data["IsBitSize"]:
                pass
            elif converted_data["IsMap"]:
                map_key_type = converted_data["MapKeyType"]
                map_key_is_pointer = converted_data["MapKeyIsPointer"]
                map_value_type = converted_data["MapValueType"]
                map_value_is_pointer = converted_data["MapValueIsPointer"]
                map_length = mem.rm.read_int(address + 0xC)

                map_data: int = mem.rm.read_ptr(address)

                for i in range(map_length):
                    pair_offset = i * 0x18
                    key_address = map_data + pair_offset
                    value_address = map_data + pair_offset + 0x8

                    pair_index: int = mem.rm.read_int(map_data + pair_offset + 0x10)

                    text = f'TPair<{map_key_type}{"*" if map_key_is_pointer else ""}, {map_value_type}{"*" if map_value_is_pointer else ""}> 0x{i}'
                    data = (converted_data, key_address, value_address, pair_index, "TPair")
                    item_insert = tree.insert(item_id, "end", text=text, tags=("monospaced",), values=data)
                    tree.insert(item_insert, "end", text="", tags=("dummy",))

            elif converted_data["IsUnknownData"]:
                remaining_size = converted_data["Size"]
                offset = 0

                chain_str = get_parent_name_chain(item_id)
                
                unknown_data_props[chain_str] = []
                if chain_str not in unknown_data_order:
                    unknown_data_order[chain_str] = {}

                chunk_sizes = [8, 4, 2, 1]
                id = 0
                while remaining_size > 0:
                    if offset in unknown_data_order[chain_str].keys():
                        prop = unknown_data_order[chain_str][offset]
                        prop.offset = offset
                        label = prop.build_label()
                        prop.bytes = read_bytes(prop.address + prop.offset, prop.size)
                        prop.values = get_byte_data(prop.address + prop.offset)
                        values = (prop.id,)
                        insert = inspector_tree.insert(item_id, "end", text=label, tags=("monospaced",), values=values)
                        if prop.check_expandable():
                            inspector_tree.insert(insert, "end", text="", tags=("dummy",))
                        prop.node_id = insert
                        id += 1
                        offset += prop.size
                        remaining_size -= prop.size
                    else:
                        this_address = address + offset
                        values = ()
                        for chunk_size in chunk_sizes:
                            if remaining_size >= chunk_size:
                                bytes = read_bytes(this_address, chunk_size)
                                data = get_byte_data(this_address)
                                if chunk_size == 8:
                                    type = "Hex64"
                                elif chunk_size == 4:
                                    type = "Hex32"
                                elif chunk_size == 2:
                                    type = "Hex16"
                                elif chunk_size == 1:
                                    type = "Hex8"
                                comment = ""
                                
                                values = (id,)
                                name = generate_node_name(id)
                                prop = UnknownProperty(address, offset, type, name, comment, id)
                                prop.values = data
                                prop.size = chunk_size
                                prop.bytes = bytes
                                prop.parent_id = item_id
                                unknown_data_props[chain_str].append(prop)
                                unknown_data_order[chain_str][prop.offset] = prop

                                nodeid = tree.insert(item_id, "end", text=prop.build_label(), tags=("monospaced",), values=values)
                                prop.node_id = nodeid
                                offset += chunk_size
                                remaining_size -= chunk_size
                                id += 1
                                break
                            else:
                                continue

            else:
                try:
                    inspector_tree_on_class(tree, converted_data["TypeName"], item_id, address)
                except:
                    tree.insert(item_id, "end", text="Invalid Class", tags=("monospaced",))

        else:
            temp_name = get_name_from_id(item_id) if len(node_data) == 4 else node_data[0]
            inspector_tree_on_class(tree, temp_name, item_id, address)

    except:
        parent_id = inspector_tree.parent(item_id)
        chain_str = get_parent_name_chain(parent_id)
        offset = int(node_name.split(" ")[0], 16)
        prop = unknown_data_order[chain_str][offset]
        address = prop.address + prop.offset

        if prop.type == "Void Pointer":
                address = mem.rm.read_ptr(address)
                open_void_pointer_node(address, prop.buffer, item_id)
                return
        
        if prop.type == "Pointer" or prop.type == "Class Instance":
            if prop.type == "Pointer":
                address = mem.rm.read_ptr(address)

            inspector_tree_on_class(tree, prop.subtype, item_id, address)

        elif prop.type == "TArray":
            array_data: int = mem.rm.read_ptr(prop.address + prop.offset)
            array_length: int = mem.rm.read_int(prop.address + prop.offset + 8)
            is_array_of_ptr = False
            if "*" in prop.subtype:
                is_array_of_ptr = True
            type_name = prop.subtype.replace("*", "")
            for i in range(array_length):
                if is_array_of_ptr:
                    item_address = mem.rm.read_ptr(array_data + (i * 8))
                    text = f"{type_name} : {hex(array_data + (i * 8))} -> {hex(item_address)}"
                else:
                    typesize = Service.get_class_size_from_name(type_name)
                    item_address = array_data + (i * typesize)
                    if type_name in simples:
                        simple_value = read_type(item_address, type_name)
                        text = f"{type_name} = {simple_value}"
                    else:
                        text = f"{type_name} : {hex(item_address)}"

                data = [type_name, item_address]
                item_insert = tree.insert(item_id, "end", text=text, tags=("monospaced",), values=data)
                if type_name not in simples:
                    tree.insert(item_insert, "end", text="", tags=("dummy",))

def inspector_tree_on_class(tree: ttk.Treeview, class_name: str, item_id: str, address: int):
    classobj: SDKClass = Helper.name_class_map[class_name]
    if classobj.parent_class_name:
        parent_insert = tree.insert(item_id, "end", text=f"Super: {classobj.parent_class_name}", tags=("monospaced",), values=(classobj.parent_class_name, address,))
        tree.insert(parent_insert, "end", text="", tags=("dummy",))

    for property in classobj.properties.values():
        property: SDKProperty = property
        property.name = property.name.split("[")[0]
        if property.is_pointer:
            address_pointed_to = mem.rm.read_ptr(address + property.offset)
            prop_text = f"{property.type_name}* {property.name} : {hex(address + property.offset)} -> {hex(address_pointed_to)}"
            prop_values = (property.to_data(), address_pointed_to, address +  + property.offset)
            prop_insert = tree.insert(item_id, "end", text=prop_text, tags=("monospaced",), values=prop_values)
            if property.type_name not in simples and address_pointed_to > 0:
                tree.insert(prop_insert, "end", text="", tags=("dummy",))
            continue
        elif property.is_bit_size:
            bit_bool = mem.rm.read_bit_bool(address + property.offset, property.bit_number)
            property.type_name = "bit bool"
            prop_text = f"bit bool {property.name} = {bit_bool}"
        elif property.is_enum:
            value = mem.rm.read_int(address + property.offset)
            #Helper.logger.info(f"{property.name} in {Helper.name_class_map.keys()}")
            enum_obj: SDKClass = Helper.name_class_map[property.name]
            try:
                if value > len(enum_obj.elements):
                    value_text = enum_obj.elements[-1]
                else:
                    value_text = enum_obj.elements[value]
                prop_values = (property.to_data(), address + property.offset)
                enum_insert = tree.insert(item_id, "end", text=f"{property.type_name} {property.name} = {value_text} ({value}) [{hex(property.size)}]", tags=("monospaced",), values=prop_values)
                tree.insert(enum_insert, "end", text="", tags=("dummy",))
                continue
            except: continue
        elif property.is_map:
            map_length = mem.rm.read_int(address + property.offset + 0xC)
            prop_values = (property.to_data(), address + property.offset)
            key_size = Service.get_class_size_from_name(property.map_key_type)
            value_size = Service.get_class_size_from_name(property.map_value_type)
            prop_text = f'TMap<{property.map_key_type}{"*" if property.map_key_is_pointer else ""}, {property.map_value_type}{"*" if property.map_value_is_pointer else ""}> {property.name} ({map_length}) [0x50 ({hex(key_size)}, {hex(value_size)})]'
            prop_insert = tree.insert(item_id, "end", text=prop_text, tags=("monospaced",), values=prop_values)
            if map_length > 0 and map_length < 10000:
                tree.insert(prop_insert, "end", text="", tags=("dummy",))
            continue
        elif property.is_array:
            data = mem.rm.read_ptr(address + property.offset)
            length = mem.rm.read_int(address + property.offset + 8)
            max = mem.rm.read_int(address + property.offset + 12)
            property.tArray_data = data
            property.tArray_length = length
            property.tArray_max = max
            prop_text = f"TArray<{property.type_name}{'*' if property.is_array_of_ptr else ''}> {property.name} ({length}/{max}) [0x10 ({hex(property.size)})]"
            if property.tArray_length >= 255:
                prop_text += " (Invalid)"
            
            prop_values = (property.to_data(), address + property.offset)
            prop_insert = tree.insert(item_id, "end", text=prop_text, tags=("monospaced",), values=prop_values)
            if property.tArray_length > 0 and property.tArray_length < 255:
                tree.insert(prop_insert, "end", text="", tags=("dummy",))
            continue
        elif property.type_name in simples and not "UnknownData" in property.name:
            value = read_type(address + property.offset, property.type_name)
            prop_text = f"{property.type_name} {property.name} = {value} [{hex(property.size)}]"
        else:
            prop_text = f"{property.type_name} {property.name} [{hex(property.size)}]"
        prop_values = (property.to_data(), address + property.offset)
        prop_insert = tree.insert(item_id, "end", text=prop_text, tags=("monospaced",), values=prop_values)
        
        if property.type_name not in simples:
            tree.insert(prop_insert, "end", text="", tags=("dummy",))
        if "UnknownData" in property.name and not property.is_bit_size:
            tree.insert(prop_insert, "end", text="", tags=("dummy",))
    

def open_void_pointer_node(address: int, buffer: int, item_id: str):
    offset = 0
    chunk_sizes = [8, 4, 2, 1]
    while buffer > 0:
        this_address = address + offset
        values = ()
        for chunk_size in chunk_sizes:
            if buffer >= chunk_size:
                bytes = read_bytes(this_address, chunk_size)
                data = get_byte_data(this_address)
                pre_text = f'0x{offset:04X}  0x{this_address:016X}  '
                data_text = get_data_text(data, chunk_size)
                if data_text == "":
                    label = f'{pre_text}{bytes}'
                else:
                    label = f'{pre_text}{bytes} {data_text}'

                inspector_tree.insert(item_id, "end", text=label, tags=("monospaced",))
                offset += chunk_size
                buffer -= chunk_size
                break
            else:
                continue

def on_node_close(event: tk.Event):
    """
    Event for when you close a node, deletes all child nodes then adds a dummy node
    """
    item_id = event.widget.focus()
    close_child_nodes(event.widget, item_id)
    event.widget.delete(*event.widget.get_children(item_id))
    event.widget.insert(item_id, "end", text="", tags=("dummy",))

def reload_actor_tree():
    """
    Reloads the actor tree with the actors
    """
    actor_tree.delete(*actor_tree.get_children())
    for address, actor in mem.address_name_map.items():
        data = detect_type(actor)
        if address in attached_actors.keys():
            if data is not None and actor not in actor_filters and data != "AActor":
                actor_tree.insert("", "end", text=f"{hex(address)} : {actor} (Valid Attached)", tags=("monospaced", "attached"), values=data)
            else:
                actor_tree.insert("", "end", text=f"{hex(address)} : {actor} (Invalid Attached)", tags=("monospaced", "attached"), values=data)
        else:
            if data is not None and actor not in actor_filters and data != "AActor":
                actor_tree.insert("", "end", text=f"{hex(address)} : {actor} (Valid)", tags=("monospaced", "valid"), values=data)
            else:
                actor_tree.insert("", "end", text=f"{hex(address)} : {actor} (Invalid)", tags=("monospaced", "invalid"), values=data)

def search_val(se: str):
    global last_search
    last_search = se
    if not se:
        return
    
    reload_actor_tree()

    items_to_remove = []
    actor_tree.selection_clear()
    items = actor_tree.get_children()
    for item in items:
        text = actor_tree.item(item)["text"].split(" : ")[1].split(" ")[0]
        if se.lower() not in text.lower():
            items_to_remove.append(item)
                                
    for item in items_to_remove:
        actor_tree.delete(item)
    items_to_remove.clear()

def search(event: tk.Event = None):
    """
    Gets all instances of the string inside the Search input box "`search_entry`" and displays them in the `actor_tree`
    """
    se = search_entry.get()
    search_val(se)

def create_sdk_service():
    """
    Creates the sdk service instance, required for reading the actual sdk.
    """
    global Service
    Service = SDKService(json_config["sdk_location"])
    
def create_memory_handler():
    """
    Creates the memory handler, based nearly entierly on DougTheDruids framework :class:`SoTMemoryReader` class.\n
    I implore you to check his framework out!
    Doug's original framwork can be found at `https://github.com/DougTheDruid/SoT-ESP-Framework`
    """
    global mem
    start_time = time.time()
    mem = SoTMemoryHandler(Service)
    end_time = time.time()
    elapsed_time = round(end_time - start_time, 4)
    Helper.logger.info(f"SoTMemoryReader object created with an elapsed time of {elapsed_time} seconds")

def scan_actors():
    """
    Scans all actors in all levels, loads them into the `actor_tree` treeview and logs the time.
    """
    global last_search
    last_search = ""

    insp_start_time = time.time()
    mem.read_all_actors()
    reload_actor_tree()
    insp_end_time = time.time()
    insp_elapsed_time = insp_end_time - insp_start_time
    Helper.logger.info(f"Actors loaded into Viewbox with an elapsed time of {round(insp_elapsed_time, 4)}")

def toggle_idle_dc():
    """
    Toggles idle disconnect, useful when debugging/inspecting for longer durations
    """
    if mem.toggle_idle_disconnect():
        Helper.logger.info(f"Successfully changed Idle diconnect to {globals.idle_disconnect}")
    else:
        Helper.logger.info(f"Failed to change Idle diconnect")

def create_tkinter_window():
    """
    Creates the main tkinter window for the treeviews and application
    """
    global root
    root = Tk()
    root.title("SoT Inspector")
    root.geometry("1200x800")
    script_dir = os.path.dirname(os.path.abspath(__file__)).split("src")[0]
    icon_path = os.path.join(script_dir, "assets\\inspector-icon.png")
    root.iconphoto(True, tk.PhotoImage(file=icon_path))
    handles.append(root.winfo_id())

    main_frame = ttk.Frame(root)
    main_frame.pack(side="top", fill="both", expand=True)

    actor_frame = ttk.Frame(main_frame)
    actor_frame.pack(side="left", fill="both", expand=True)

    inspector_frame = ttk.Frame(main_frame)
    inspector_frame.pack(side="right", fill="both", expand=True)

    global actor_tree
    actor_tree = ttk.Treeview(actor_frame, style="Custom.Treeview", show='tree')
    actor_tree.pack(side="left", fill="both", expand=True)
    actor_tree.tag_configure("monospaced", font=("Courier New", 10))
    actor_tree.tag_configure("valid", foreground="blue")
    actor_tree.tag_configure("invalid", foreground="red")
    actor_tree.tag_configure("attached", foreground="green")

    global inspector_tree
    inspector_tree = ttk.Treeview(inspector_frame, style="Custom.Treeview", show='tree')
    inspector_tree.pack(side="right", fill="both", expand=True)
    inspector_tree.tag_configure("monospaced", font=("Courier New", 10))
    actor_tree.tag_configure("cblue", foreground="blue")
    actor_tree.tag_configure("cred", foreground="red")
    actor_tree.tag_configure("cgreen", foreground="green")
    actor_tree.tag_configure("cyellow", foreground="yellow")

    global actor_context_menu
    actor_context_menu = Menu(actor_tree, tearoff=False)
    global insp_context_menu
    insp_context_menu = Menu(inspector_tree, tearoff=False)
    
    actor_scrollbar_frame = ttk.Frame(actor_frame)
    actor_scrollbar_frame.pack(side="right", fill="y")
    actor_scrollbar = ttk.Scrollbar(actor_scrollbar_frame, orient="vertical", command=actor_tree.yview)
    actor_scrollbar.pack(side="right", fill="y")
    actor_tree.configure(yscrollcommand=actor_scrollbar.set)

    insp_scrollbar_frame = ttk.Frame(inspector_frame)
    insp_scrollbar_frame.pack(side="left", fill="y")
    insp_scrollbar = ttk.Scrollbar(insp_scrollbar_frame, orient="vertical", command=inspector_tree.yview)
    insp_scrollbar.pack(side="left", fill="y")
    inspector_tree.configure(yscrollcommand=insp_scrollbar.set)
    
    bottom_frame = ttk.Frame(main_frame)
    bottom_frame.pack(side="top")

    sdk_scan_button = Button(bottom_frame, text="Scan Actors", command=scan_actors)
    sdk_scan_button.pack(side="left")

    tracked_button = Button(bottom_frame, text="Tracked Vectors", command=open_tracked_vectors_window)
    tracked_button.pack(side="left")

    global idle_dc_button
    idle_dc_button = Button(bottom_frame, text="Enable Anti AFK", command=toggle_idle_dc)
    idle_dc_button.pack(side="left")

    search_frame = ttk.Frame(main_frame)
    search_frame.pack(side="top")

    search_label = Label(search_frame, text="Search:")
    search_label.pack(side="left")

    global search_entry
    search_entry = Entry(search_frame)
    search_entry.pack(side="left", fill="x", expand=True)
    search_entry.bind("<Return>", search)

    search_button = Button(search_frame, text="Search", command=search)
    search_button.pack(side="left")

    actor_tree.bind("<Button-3>", show_actor_context_menu)

    inspector_tree.bind("<<TreeviewOpen>>", on_insp_node_open_init)
    inspector_tree.bind("<<TreeviewClose>>", on_node_close)
    inspector_tree.bind("<Button-3>", show_insp_context_menu)

    scan_actors()
    fast_update_loop()
    update_inspector_tree_nodes()

    total_end_time = time.time()
    total_elapsed_time = total_end_time - total_start_time
    Helper.logger.info(f"Total elapsed time {round(total_elapsed_time, 4)}")
    root.mainloop()

def my_coords_to_vector(my_coords: dict):
    return Vector3(my_coords["x"], my_coords["y"], my_coords["z"])

def build_pyglet_label(label, distance, screen_coords):
    return pyglet.text.Label(f"{label} [ {distance}m ]",
                        x=screen_coords[0] + 13,
                        y=screen_coords[1] + -5)

def build_circle(screen_coords, color):
    return pyglet.shapes.Circle(screen_coords[0], screen_coords[1],
                    8, color=color)

def run_pyglet():
    Helper.logger.info("Creating pyglet window")
    config = pyglet.gl.Config(double_buffer=True, depth_size=24, alpha_size=8)
    if window_handle:
        sot_window = win32gui.GetWindowRect(window_handle)
        win_x = sot_window[0]
        win_y = sot_window[1]
        win_w = sot_window[2] - sot_window[0]
        win_h = sot_window[3] - sot_window[1]
    else:
        win_x = 0
        win_y = 0
        win_w = win32api.GetSystemMetrics(0)
        win_h = win32api.GetSystemMetrics(1)

    window = pyglet.window.Window(win_w, win_h,
                                 vsync=False, style='overlay', config=config,
                                 caption="ESP Overlay")
    hwnd = window._hwnd
    window.set_location(win_x, win_y)
    Helper.logger.info("Created pyglet window")

    @window.event
    def on_draw():
        # if not mem.rm.is_proc_active():
        #     Helper.logger.warning("Sot Exited, exiting...")
        #     messagebox.showinfo("Sot Exited", "SoT Closed, exiting...")
        #     exit()


        # global exiting
        # if not exiting:
        #     if win32api.GetAsyncKeyState(0x23) & 0x8000:
        #         Helper.logger.info("[END] Pressed, exiting")
        #         exiting = True
        #         messagebox.showinfo("[END] Pressed", "End Pressed, exiting")
        #         exit()
        # else:
        #     return

        window.clear()

        if window_handle:
            sot_window = win32gui.GetWindowRect(window_handle)
            win_x = sot_window[0]
            win_y = sot_window[1]
            win_w = sot_window[2] - sot_window[0]
            win_h = sot_window[3] - sot_window[1]
        else:
            win_x = 0
            win_y = 0
            win_w = win32api.GetSystemMetrics(0)
            win_h = win32api.GetSystemMetrics(1)

        window.set_location(win_x, win_y)
        window.set_size(win_w, win_h)

        foreground_window = win32gui.GetForegroundWindow()
        handles.clear()
        if window_handle:
            handles.append(window_handle)
            handles.append(win32gui.FindWindow(None, "SoT Inspector"))
            handles.append(win32gui.FindWindow(None, "Tracked Vectors"))
        else:
            handles.append(foreground_window)

        if foreground_window in handles:
            fps_display.draw()
            if len(tracked_vectors) > 0:
                mem.update_my_coords()
            for renderobj in tracked_vectors:
                vector = mem.rm.read_vector3_obj(renderobj.address)
                renderobj.location = Vector3(vector["x"], vector["y"], vector["z"])

                screen_coords = Render.object_to_screen(mem.my_coords, renderobj.location, win_w, win_h)
                if screen_coords:
                    distance = Render.calculate_distance(my_coords_to_vector(mem.my_coords), renderobj.location)
                    text_label = build_pyglet_label(renderobj.name, distance, screen_coords)
                    icon = build_circle(screen_coords, (255, 0, 0))

                    text_label.draw()
                    icon.draw()

                    text_label.delete()
                    icon.delete()

    pyglet.clock.schedule_interval(check_sot_running, 5)

    fps_display = pyglet.window.FPSDisplay(window)

    Helper.logger.info("Starting pyglet loop")
    pyglet.app.run(interval=1/json_config["fps_target"])

def check_sot_running():
    if not mem.rm._process_is_active():
        Helper.logger.warning("Sot Exited, exiting...")
        messagebox.showinfo("Sot Exited", "SoT Closed, exiting...")
        exit()

def main():
    """
    main() function, default function for many python projects
    """
    global total_start_time
    total_start_time = time.time()
    config_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config.json')
    global json_config
    try:
        with open(config_file_path, 'r') as json_file:
            json_config = json.load(json_file)
        if json_config["sdk_location"] in sdk_path_filters:
            messagebox.showerror("Invalid SDK", f'Invalid sdk path "{json_config["sdk_location"]}"')
            exit()
    except FileNotFoundError:
        messagebox.showerror("Could not find file", "The 'config.json' file does not exist.")
        exit()
    except json.JSONDecodeError:
        messagebox.showerror("Could not decode file", "Error decoding JSON in 'config.json'.")
        exit()

    create_sdk_service()
    scan_sdk() if json_config["sdk_location"] is not None else None
    create_memory_handler()

    if json_config["rendering"]:
        Helper.logger.info("Creating pyglet")
        pyglet_thread = threading.Thread(target=run_pyglet)
        pyglet_thread.start()
    else:
        Helper.logger.info("Not Creating Pyglet")

    Helper.logger.info("Creating tkinter")
    create_tkinter_window()

if __name__ == '__main__':
    main()
