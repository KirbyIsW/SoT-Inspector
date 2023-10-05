import struct
from Helper import logger
from memory_helper import ReadMemory
from SDKservice import *
from SDKClasses import *
import globals

class SoTMemoryHandler:
    """
    Wrapper class to handle reading data from the game, parsing what is
    important, and returning it to be used
    """
    def __init__(self, Service: SDKService):
        """
        Upon initialization of this object, we want to find the base address
        for the SoTGame.exe, then begin to load in the static addresses for the
        uWorld, gName, gObject, and uLevel objects.

        We also poll the local_player object to get a first round of coords.
        When running read_actors, we update the local players coordinates
        using the camera-manager object

        Also initialize a number of class variables which help us cache some
        basic information
        """
        self.actor_name_map: dict[int, str] = {}
        self.name_address_map: dict[str, int] = {}
        self.address_name_map: dict[int, str] = {}

        self.SDK = Service
        self.rm = ReadMemory("SoTGame.exe")
        base_address = self.rm.base_address
        logger.info(f"Process ID: {self.rm.pid}")

        u_world_offset = self.rm.read_ulong(
            base_address + self.rm.u_world_base + 3
        )
        u_world = base_address + self.rm.u_world_base + u_world_offset + 7
        self.u_world = self.rm.read_ptr(u_world)
        logger.info(f"SoT uWorld Address: {hex(self.u_world)}")


        g_name_offset = self.rm.read_ulong(
            base_address + self.rm.g_name_base + 3
        )
        g_name = base_address + self.rm.g_name_base + g_name_offset + 7
        self.g_name = self.rm.read_ptr(g_name)
        logger.info(f"SoT gName Address: {hex(self.g_name)}")

        globals.local_player = self.load_local_player()
        globals.local_player_controller = self.rm.read_ptr(
            globals.local_player + self.SDK.find_sdk_offset('UPlayer.PlayerController')
        )
        globals.local_root_component = globals.local_player_controller + self.SDK.find_sdk_offset('AActor.RootComponent')
        globals.idle_dc_address = globals.local_player_controller + self.SDK.find_sdk_offset('AOnlineAthenaPlayerController.IdleDisconnectEnabled')
        globals.idle_disconnect = self.rm.read_bool(globals.idle_dc_address)

        Helper.logger.info(f"Idle Disconnect Address: {hex(globals.idle_dc_address)}")
        Helper.logger.info(f"Idle Disconnect Enabled: {globals.idle_disconnect}")
        self.update_my_coords()

        self.actor_name_map[-2] = "ULocalPlayer"
        self.actor_name_map[-1] = "UWorld"
        
        self.read_all_actors()

    def update_idle_disconnect(self):
        globals.idle_disconnect = self.rm.read_bool(globals.idle_dc_address)

    def toggle_idle_disconnect(self) -> bool:
        if self.rm.write_bool(globals.idle_dc_address, not globals.idle_disconnect):
            globals.idle_disconnect = not globals.idle_disconnect
            return True
        return False

    def update_my_coords(self):
        """
        Function to update the players coordinates and camera information
        storing that new info back into the my_coords field. Necessary as
        we dont always run a full scan and we need a way to update ourselves
        """
        manager = self.rm.read_ptr(
            globals.local_player_controller + self.SDK.find_sdk_offset('APlayerController.PlayerCameraManager')
        )
        self.my_coords = self._coord_builder(
            manager,
            self.SDK.find_sdk_offset('APlayerCameraManager.CameraCache')
            + self.SDK.find_sdk_offset('FCameraCacheEntry.POV'),
            fov=True)
        Helper.player = self.my_coords

    def _coord_builder(self, actor_address: int, offset=0x78, camera=True,
                       fov=False) -> dict:
        """
        Given a specific actor, loads the coordinates for that actor given
        a number of parameters to define the output
        :param int actor_address: Actors base memory address
        :param int offset: Offset from actor address to beginning of coords
        :param bool camera: If you want the camera info as well
        :param bool fov: If you want the FoV info as well
        :rtype: dict
        :return: A dictionary containing the coordinate information
        for a specific actor
        """
        if fov:
            actor_bytes = self.rm.read_bytes(actor_address + offset, 44)
            unpacked = struct.unpack("<ffffff16pf", actor_bytes)
        else:
            actor_bytes = self.rm.read_bytes(actor_address + offset, 24)
            unpacked = struct.unpack("<ffffff", actor_bytes)

        coordinate_dict = {"x": unpacked[0]/100, "y": unpacked[1]/100,
                           "z": unpacked[2]/100}
        if camera:
            coordinate_dict["cam_x"] = unpacked[3]
            coordinate_dict["cam_y"] = unpacked[4]
            coordinate_dict["cam_z"] = unpacked[5]
        if fov:
            coordinate_dict['fov'] = unpacked[7]

        return coordinate_dict

    def load_local_player(self) -> int:
        """
        Returns the local player object out of uWorld.UGameInstance.
        Used to get the players coordinates before reading any actors
        :rtype: int
        :return: Memory address of the local player object
        """
        game_instance = self.rm.read_ptr(
            self.u_world + self.SDK.find_sdk_offset('UWorld.OwningGameInstance')
        )
        local_player = self.rm.read_ptr(
            game_instance + self.SDK.find_sdk_offset('UGameInstance.LocalPlayers')
        )
        return self.rm.read_ptr(local_player)

    def read_all_actors(self):
        """
        Calls the read_actors method on each level, starting with the
        persistant level (Default).
        """
        self.address_name_map.clear()
        self.address_name_map[globals.local_player] = "ULocalPlayer"
        self.address_name_map[self.u_world] = "UWorld"

        self.levels_ptr = self.rm.read_ptr(self.u_world + self.SDK.find_sdk_offset("UWorld.Levels"))
        self.u_level_count = self.rm.read_uint32(self.u_world + self.SDK.find_sdk_offset("UWorld.Levels") + 8)

        for i in range(self.u_level_count):
            next_u_level_address = self.rm.read_ptr(self.levels_ptr + (i * 8))
            self.read_actors(next_u_level_address)

    def read_actors(self, u_level):
        """
        Represents a full scan of every actor within our render distance in the current level.
        :param u_level: Level address as an int
        """

        actor_raw = self.rm.read_bytes(u_level + 0xa0, 0xC)
        actor_data = struct.unpack("<Qi", actor_raw)

        level_actors_raw = self.rm.read_bytes(actor_data[0], actor_data[1] * 8)
        for x in range(0, actor_data[1]):
            raw_name = ""
            actor_address = int.from_bytes(level_actors_raw[(x*8):(x*8+8)], byteorder='little', signed=False)
            actor_id = self.rm.read_int(
                actor_address + 24
            )

            if actor_id not in self.actor_name_map and actor_id != 0:
                try:
                    raw_name = self.rm.read_gname(actor_id)
                    self.actor_name_map[actor_id] = raw_name
                except Exception as e:
                    logger.error(f"Unable to find actor name: {e}")
            elif actor_id in self.actor_name_map:
                raw_name = self.actor_name_map.get(actor_id)

                
            self.name_address_map[raw_name] = actor_address
            self.address_name_map[actor_address] = raw_name