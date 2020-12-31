# HRDevHelper

This plugin for the HexRays decompiler creates a graph of a decompiled
function's AST using IDA's internal graph viewer. It zooms in on the graph
view at 100%, attaches it to the currently active decompiler widget and
focuses on the node that belongs to the current C item.

This plugin is helpful for learning about the c-tree items of the
HexRays AST. It can be used for developing and debugging scripts and
plugins for the HexRays decompiler.

## Usage
The plugin can be run with a decompiler window focused, by pressing
the "Ctrl-Shift-." hotkey.

### Hotkeys (view focused on the HRDevHelper widget):
* C: The color scheme used by the plugin can be customized by pressing 'c'.
A dialog will appear asking for 5 colors in RGB format.
* S: Toggle sync (center graph on current node/item)

![HRDevHelper animated gif](/rsrc/hrdevhelper.gif?raw=true)
