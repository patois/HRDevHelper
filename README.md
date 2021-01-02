# HRDevHelper

This plugin for the HexRays decompiler creates a graph of a decompiled
function's AST using IDA's internal graph viewer. It zooms in on the graph
view at 100%, attaches it to the currently active decompiler widget and
focuses on the node that belongs to the current C item.

![HRDevHelper animated gif](/rsrc/hrdevhelper.gif?raw=true)

This plugin is helpful for learning about the c-tree items of the
HexRays AST. It can be used for developing and debugging scripts and
plugins for the HexRays decompiler.

The plugin's default colors are optimized to work with dark IDA color themes.
Default colors and other settings (zoom, dock position etc.) can be tweaked by
editing the plugin's configuration file that is created after running the plugin
for the first time.

## Installation
Copy hrdevhelper.py to ./IDA/plugins/

## Usage
The plugin can be run with a decompiler window focused, by pressing
the "Ctrl-Shift-." hotkey. Doing so visualizes the ctree of the currently
decompiled function. Navigating the decompiled code using the mouse/keyboard
will highlight graph nodes that are linked to the current decompiled line.
Selecting multiple lines will highlight corresponding nodes the graph. 

### Hotkeys (view focused on the HRDevHelper widget):
* C: Dynamically toggle "center on current item/node" functionality.
