# HRDevHelper

HRDevHelper is an extension for the Hexrays decompiler written in IDAPython and is meant to be a helpful tool for debugging and developing your own Hexrays plugins and scripts. The plugin draws its usefulness from displaying a graph of a decompiled function's respective ctree and creating visual links between its underlying decompiled code and the graphs' individual items.

![HRDevHelper animated gif](/rsrc/hrdevhelper.gif?raw=true)

When invoked, HRDevHelper creates and attaches a ctree graph to the currently active decompiler widget and centers the graph's view on the current ctree item. Subsequently navigating the decompiled code visually highlights corresponding ctree items in the graph.  

The plugin's default colors are optimized to work with dark IDA color themes. Default colors and other settings (zoom, dock position etc.) can be configured by
editing the plugin's configuration file that is created after running the plugin for the first time. The HRDevhelper.cfg configuration file can be found in the [IDA user directory](https://hex-rays.com/blog/igors-tip-of-the-week-33-idas-user-directory-idausr/).

## Installation
Copy hrdevhelper.py and the hrdh folder to ./IDA/plugins/ and restart IDA.

## Plugin Usage & Shortcuts
The plugin's functionality is accessible via right-click in a decompiler view or otherwise via keyboard shortcuts:

* "show ctree" creates a graph of all ctree items of the current decompiled function.
* "show sub-tree" creates a graph of ctree items that belong to the current expression.
  The subgraph's root is determined via the current decompiler view's text cursor.
* "show context" opens a context viewer that, among other information, displays the current
  sub-tree's citems as a lambda expression. This expression can be used with and directly copy-pasted into hxtb-shell that comes with the [HexraysToolbox](https://github.com/patois/HexraysToolbox) script.

By default, HRDevHelper visually highlights all ctree items in a graph that correspond to a current single decompiled line of code. Making a selection of multiple lines highlights nodes accordingly.

![HRDevHelper context view](/rsrc/hrdevctx.png?raw=true)

In addition to the keyboard shortcuts that are made available in decompiler views, the graphs created by HRDevHelper have additional keyboard shortcuts in place as shown below. 

### Graph Hotkeys (focus on any HRDevHelper graph/subgraph):
* C: Toggle "center on current item/node" functionality (switches synchronization on/off).
* D: Increase debug/verbosity of particular nodes 
