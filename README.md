# SoT-Inspector
A deep dive into actors loaded into Sea of Thieves, loaded with a ReClass.NET knockoff and coded in the fastest programming language ever, Python!

If you have any problems or questions, my discord is `kirbyw`
You are very welcome to edit or change things you dont seem fit. I am a very amateur python programmer so the code is really ugly, and i am aware "around 4000 lines of pure spagetti code :)". I'm really happy to see other peoples additions or changes! Please share with my discord or on the forums

Credit to [Caldor](https://www.unknowncheats.me/forum/members/5105182.html) for insipration from his own Inspector project in C#, check him out!

### Setup
- Make sure you have python installed, preferably a later version but any version above 3 should do.
- Extract github files to folder, in root folder (one with src folder in it) right click and press `Open in Terminal`.  Then in the Command Prompt window, simply type `pip install -r requirements.txt` and press enter, this will download the required dependencies
- Head into `config.json` located in the root folder, edit the `sdk_location` element to be your sdk location  
it might look something like this: `sdk_location = "C:\\SoTStuff\\SDK"`. Double-backslashes are important
  - Note: Right now the program is only tailored towards UnrealDumper-4.10 by [guttir14](https://github.com/guttir14/UnrealDumper-4.25/tree/UnrealDumper-4.10), please do check it out, if you are not intrested in dumping yourself, head on over to [mogistink](https://www.unknowncheats.me/forum/members/3434160.html)'s UnknownCheats page and look at his posts to find high quality dumps of the latest sdk, found under `Uploads`. Check out the [Todo](https://github.com/KirbyIsW/SoT-Inspector#notes--todo) section where i mention a potential fix
- In `config.json` you may also choose if you want to activate pyglet rendering aswell as change the fps, pretty sure that 60fps is the best choice, have noticed some glitches with higher / lower fps's.
- Now run main.py by running the `run.bat` script in the root directory.

## Notes / Todo
- Python's `io.open` (`with open("file.ext", "r") as file`) has some caching stuff, so the first time you run the program after a while of not using it, it might take 10-20 sec to startup, and sadly there is not really anything i can do about this. But the launches after that shouldn't take more than 2-3 seconds.
- Change from using a predumped sdk to dynamic gobject scanning.
- Upgrade searching within actors aswell as unknown-data browser.
- Vertical sliders for treeviews (Tkinter is annoying)

# Functions
- Actor-Property browser
  - Browse actors properties, using tkinters treeview, dynamically loads objects so should be basically instant!
  - Open up structures such as TArrays, TMaps and pointers to search around for values
  - Limited memory-writing. Write things such as FStrings, ints, floats and doubles, aswell as change bools.
- Value, property and address searcher
  - Have you found a health variable in cheat engine? Slap the address into `SoT-Inspector` to find in what actor it belongs.
  - Want to find where the HealthComponent of a player is? Search for `healthcomponent` in the property type searcher to find it!
- Unknown data recompilation tools
  - Includes a tool very similar to the popular reversing tool [ReClass.NET](https://github.com/ReClassNET/ReClass.NET)
  - Has type changing, subtype changing, is a little bit buggy right now, something to improve.
- Rendering
  - Want to know where in the world a vector you found is? If you have rendering activated in `config.json` simply right-click and press `Track Vector` which will draw it in the world. Open the Tracked Vectors tab to edit names.
- Anti AFK for longer sessions of looking around
- Limited Logging for statistics
