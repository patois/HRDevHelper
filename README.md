# HRDevHelper

This plugin for the HexRays decompiler creates a graph of a decompiled
function's AST using IDA's internal graph viewer. It zooms in on the graph
view at 100%, attaches it to the currently active decompiler widget and
focuses on the node that belongs to the current C item.

This plugin is helpful for learning about the c-tree items of the
HexRays AST. It can be used for developing and debugging scripts and
plugins for the HexRays decompiler.

Using a dark color IDA theme is recommended.

## Usage
The plugin can be run with a decompiler window focused, by pressing
the "Ctrl-Shift-." hotkey. Doing so visualizes the ctree of the currently
decompiled function. Navigating the decompiled code using the mouse/keyboard
will highlight graph nodes that are linked to the current decompiled line.
Selecting multiple lines will have the same effect on the graph. 

### Hotkeys (view focused on the HRDevHelper widget):
* S: Toggle sync (center graph on current node/item)
* C: The color scheme used by the plugin can be customized by pressing 'c'.
A dialog will appear asking for 6 colors in RGB format.

![HRDevHelper animated gif](/rsrc/hrdevhelper.gif?raw=true)
