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
for the first time. The HRDevhelper.cfg configuration file can be found in the [IDA user directory](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/).

## Installation
Copy hrdevhelper.py to ./IDA/plugins/

## Plugin Usage & Hotkeys
The plugin's functionality is accessible via Hexrays context menus (right click
on a decompiler view) and is otherwise accessible via hotkeys:
* "show ctree" creates a graph of all ctree items of the current decompiled function.
* "show sub-tree" creates a graph of all ctree items of the current decompiled function.
  The subgraph's root is determined via the current decompiler view's text cursor.
* "show context" opens a context viewer that, among other information, displays the current
  sub-tree's citems as a lambda expression that can be copy-pasted and used with [Hexrays toolbox / hxtb-shell](https://github.com/patois/HexraysToolbox).

The generated graphs can be interacted with using the mouse and/or keyboard.
Nodes that are linked to the current decompiled line are visually highlighted in the graph.
Making a selection of lines will highlight corresponding graph nodes.

### Graph Hotkeys (focus on any HRDevHelper graph/subgraph):
* C: Toggle "center on current item/node" functionality (switches synchronization on/off).
* D: Increase debug/verbosity of particular nodes 
