import logging
import os

log_dir = 'Logs'
log_filename = 'SDK (1).log'
log_filepath = os.path.join(log_dir, log_filename)

if not os.path.exists(log_dir):
    os.makedirs(log_dir)

if os.path.isfile(log_filepath):
    file_exists = True
    counter = 1
    while file_exists:
        counter += 1
        log_filename = f'SDK ({counter}).log'
        log_filepath = os.path.join(log_dir, log_filename)
        file_exists = os.path.isfile(log_filepath)

logging.basicConfig(filename=log_filepath, level=logging.DEBUG,
                    format='%(asctime)s.%(msecs)03d %(levelname)s %(message)s',datefmt='%H:%M:%S', filemode='a')

logger = logging.getLogger()

player = {}

mem = None
Service = None

class_names = []
name_class_map = {}
enum_names = []
class_size_map = {
    "TArray": 0x10,
}
class_var_offsets: dict[str, int] = {}

def remove_numbers(string: str):
    result = ''
    for char in string:
        if not char.isdigit():
            result += char
    return result

# def profiler(func):
    # def wrapper(*args, **kwargs):
    #     with cProfile.Profile() as pr:
    #         result = func(*args, **kwargs)

    #     stats = pstats.Stats(pr)
    #     stats.sort_stats(pstats.SortKey.TIME)
    #     stats.print_stats()
    #     return result
    # return wrapper

def find_actor_class(name: str):
    if name is None or name == "":
        return None
    
    name = remove_numbers(name)
    if "U" + name in name_class_map.keys():
        return name_class_map["U" + name]
    elif name in name_class_map.keys():
        return name_class_map[name]
    elif "A" + name in name_class_map.keys():
        return name_class_map["A" + name]
    elif "A" + name + "_C" in name_class_map.keys():
        return name_class_map["A" + name + "_C"]
    elif "A" + name.replace("BP_", "") in name_class_map.keys():
        return name_class_map["A" + name.replace("BP_", "")]
    elif "A" + name.replace("_C", "") in name_class_map.keys():
        return name_class_map["A" + name.replace("_C", "")]
    elif "A" + name.replace("BP_", "").replace("_C", "") in name_class_map.keys():
        return name_class_map["A" + name.replace("BP_", "").replace("_C", "")]
    elif "ItemInfo" in name:
        return name_class_map["AItemInfo"]
    elif "Wieldable" in name:
        return name_class_map["AItemInfo"]
    elif name == "BP_Cannon_ShipPartMMC_C":
        return name_class_map["ABP_Cannon_C"]
    return None

def find_class_name(name: str):
    if name is None or name == "" or name == "None":
        return ""
    
    name = remove_numbers(name)
    if "U" + name in name_class_map.keys():
        return "U" + name
    elif name in name_class_map.keys():
        return name
    elif "A" + name in name_class_map.keys():
        return "A" + name
    elif "A" + name + "_C" in name_class_map.keys():
        return "A" + name + "_C"
    elif "A" + name.replace("BP_", "") in name_class_map.keys():
        return "A" + name.replace("BP_", "")
    elif "A" + name.replace("_C", "") in name_class_map.keys():
        return "A" + name.replace("_C", "")
    elif "A" + name.replace("BP_", "").replace("_C", "") in name_class_map.keys():
        return "A" + name.replace("BP_", "").replace("_C", "")
    elif "ItemInfo" in name:
        return "AItemInfo"
    elif "Wieldable" in name:
        return "AItemInfo"
    elif name == "BP_Cannon_ShipPartMMC_C":
        return "ABP_Cannon_C"
    return name