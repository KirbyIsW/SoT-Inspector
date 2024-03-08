# SoT-Inspector
A deep dive into actors loaded into Sea of Thieves, loaded with a ReClass.NET knockoff and coded python.

If you have any problems or questions, post them on the [UC-Thread](https://www.unknowncheats.me/forum/sea-of-thieves/605014-sot-inspector.html) 

You are very welcome to edit or change things you dont seem fit. I am a very amateur python programmer so the code is really ugly. I am aware that it's around 5000 lines of pure spagetti code but what can you do. I'm really happy to see other peoples additions or changes! Please share them on the forums or make a pull request.

Report any bugs you find in the github "[issues](https://github.com/KirbyIsW/SoT-Inspector/issues)" tab.

Credit to [Caldor](https://www.unknowncheats.me/forum/members/5105182.html) for figuring this stuff out with me, check him out!

### Setup
- Make sure you have python installed, preferably a later version but any version above 3 should do.
- Extract github files to folder, in root folder (one with `src` folder in it) right click and press `Open in Terminal`.  Then in the Command Prompt window, simply type `pip install -r requirements.txt` and press enter, this will download the required dependencies.

- Head into `config.json` located in the root folder, when using UEDumper dumps , change `sdk_type` to `UEDumper`. Otherwise leave it as `"default"`. Also edit the `sdk_location` element to be your sdk location.
it might look something like this: `sdk_location = "C:\\SoTStuff\\SDK"`. Double-backslashes are important

- In `config.json` you may also choose if you want to activate pyglet rendering aswell as change the fps, pretty sure that 60fps is the best choice. Have noticed some glitches with higher / lower fps's. This is used for tracking vectors locations with screen rendering. Might develop more rendering stuff.

- Now run main.py by running in in any ide or run the `run.bat` script in the root directory.

## Notes / Todo
- Horizontal sliders for treeviews (Tkinter is annoying)

# Functions
- Actor-Property browser
  - Browse actors properties, using tkinters treeview, dynamically loads objects so should be basically instant!
  - Open up structures such as TArrays, TMaps and pointers to search around for values
  - Limited memory-writing. Write things such as FStrings, ints, floats and doubles, aswell as change bools. Adding more is quite easy
- Value, property and address searcher
  - Have you found a health variable in cheat engine? Slap the address into `SoT-Inspector` to find in what actor it belongs.
  - Want to find where the HealthComponent of a player is? Search for `healthcomponent` in the property type searcher to find it!
- Unknown data recompilation tools
  - Includes a tool very similar to the popular reversing tool [ReClass.NET](https://github.com/ReClassNET/ReClass.NET)
  - Lets you explore UnknownData to find out intersting stuff about the game. For example i found keybindings from the game using this.
- Rendering
  - Want to know where in the world a vector you found is? If you have rendering activated in `config.json` simply right-click and press `Track Vector` which will draw it in the world. Open the Tracked Vectors tab to edit names.
- Anti AFK for longer sessions of property searching
- Logging for statistics