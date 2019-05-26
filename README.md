# HRDevHelper

This plugin for the HexRays decompiler creates a graph of a decompiled
function using IDA's internal graph viewer. It zooms in on the graph
view to 100%, attaches it to the currently active decompiler window and
sets the focus on the item that the decompiler view's cursor points to.

May be helpful for learning about the different c-tree items of a
decompiled function which can be used when developing and debugging
scripts and plugins for the HexRays decompiler.

The plugin can be run with a decompiler window focused, by pressing
the "Ctrl-Shift-." hotkey.

The color scheme used by the plugin can be customized by pressing 'c'.
A dialog will appear asking for 5 colors in RGB format.
Go check out https://www.color-hex.com, pick a palette, and simply
copy-paste it into the dialog.

Code is heavily based on the vds5.py example that comes with IDAPython.

![HRDevHelper animated gif](/rsrc/hrdevhelper.gif?raw=true)