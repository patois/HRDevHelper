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

## Plugin Hotkeys (focus on any decompiler view)
* "Ctrl-Shift-." creates a graph of the current decompiled function
* "Ctrl-." creates a subgraph of the current decompiled function. The subgraph's root
  is the item pointed to by the decompiler view's text cursor.
* "Ctrl-Alt-L" dumps current function's ctree to a lambda expression (copy/paste and use with hxtb-shell)
* "Ctrl-L" dumps current sub-ctree to lambda expression (copy/paste and use with hxtb-shell)

The freshly generated graph can be navigated using the mouse and/or keyboard.
Nodes that are linked to the current decompiled line are highlighted in the graph.
Making a selection of lines will highlight corresponding graph nodes.

### Graph Hotkeys (focus on any HRDevHelper graph/subgraph):
* C: Toggle "center on current item/node" functionality.
* D: Increase debug/verbosity of particular nodes 
