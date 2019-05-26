import idaapi
import ida_pro
import ida_hexrays
import ida_kernwin
import ida_gdl
import ida_lines
import ida_graph
import ida_moves
import re

__author__ = "Dennis Elser"

"""
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

Known issues:
  - grouping nodes will mess up colors and cause IDA to
    display a warning.
  - Internally, the graph is recreated and refreshed every
    time a new item is selected (performance)
  - IDA does not support labels for edges
  - calling GraphViewer.Refresh() from a hook causes an interr
"""

palette_sbteal = """
    https://www.color-hex.com/color-palette/309
    #007777       -> cit_...
    #006666       -> cit_block
    #005555       -> cot_call
    #004444       -> cot_...
    #003333       -> cit_loop
"""

palette_good_shelter = """
    https://www.color-hex.com/color-palette/78342
    #99944f     (153,148,79)
    #767b4c     (118,123,76)
    #54614a     (84,97,74)
    #314847     (49,72,71)
    #0e2f44     (14,47,68)
"""

palette_dark = """
    #757575      -> highlight
    #065a21      -> loop
    #5a063f      -> call
    #4d4d4d      -> cit
    #000000      -> cot
"""

PALETTE_DEFAULT = palette_dark

DOCK_POSITION = ida_kernwin.DP_RIGHT # DP_... or None
ZOOM = 1.0 # default zoom level for graph

# -----------------------------------------------------------------------
class vd_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self, cg):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.cg = cg

    def _update_graph(self, cfunc=None, highlight=None):
        if self.cg:
            if cfunc:
                gb = graph_builder_t(self.cg)
                gb.apply_to(cfunc.body, None)
            self.cg.set_highlight(highlight)
            # TODO: apparently, calling GraphViewer.Refresh() is
            # a bad idea from within a hook. Causes interr 51058.
            self.cg.Refresh()
        return

    def func_printed(self, cfunc):
        # function refreshed
        self._update_graph(cfunc=cfunc, highlight=None)
        return 0

    def curpos(self, vu):
        # cursor pos changed -> highlight current node
        if self.cg:
            vu.get_current_item(ida_hexrays.USE_KEYBOARD)
            highlight = vu.item.e if vu.item.is_citem() else None
            self._update_graph(cfunc=None, highlight=highlight)
        return 0

# -----------------------------------------------------------------------
class cfunc_graph_t(ida_graph.GraphViewer):
    def __init__(self, highlight, close_open=False):
        global PALETTE_DEFAULT

        self.title = "HRDevHelper"
        ida_graph.GraphViewer.__init__(self, self.title, close_open)
        self.cur_palette = PALETTE_DEFAULT
        self.apply_colors(self.cur_palette)
        self.items = [] # list of citem_t
        self.highlight = highlight
        self.succs = [] # list of lists of next nodes
        self.preds = [] # list of lists of previous nodes
        self.vd_hooks = vd_hooks_t(self)
        self.vd_hooks.hook()

    def reinit(self):
        self.items = []
        self.succs = []
        self.preds = []
        self.Clear()

    def swapcol(self, x):
        return (((x & 0x000000FF) << 16) |
                 (x & 0x0000FF00) |
                ((x & 0x00FF0000) >> 16))

    def deserialize_color_hex(self, s):
        x = re.findall(r"[#]\w+\b", s)
        return [self.swapcol(int(color[1:], 16)) for color in x]

    def apply_colors(self, s):
        global CL_NODE_CIT
        global CL_NODE_HIGHLIGHT
        global CL_NODE_COT_CALL
        global CL_NODE_COT
        global CL_NODE_CIT_LOOP

        (CL_NODE_HIGHLIGHT,
            CL_NODE_CIT_LOOP,
            CL_NODE_COT_CALL,
            CL_NODE_CIT,
            CL_NODE_COT) = self.deserialize_color_hex(s)
        self.cur_palette = s
        self.Refresh()
        return

    def zoom_and_dock(self, vu_title, zoom, dock_position=None):
        widget = ida_kernwin.find_widget(self.title)
        if widget:
            if dock_position is not None:
                gli = ida_moves.graph_location_info_t()
                if ida_graph.viewer_get_gli(gli, widget):
                    gli.zoom = zoom
                    ida_graph.viewer_set_gli(widget, gli)
            ida_kernwin.set_dock_pos(self.title, vu_title, dock_position)
            self.Refresh()

    def set_highlight(self, highlight):
        self.highlight = highlight

    def nsucc(self, n):
        return len(self.succs[n]) if self.size() else 0

    def npred(self, n):
        return len(self.preds[n]) if self.size() else 0

    def succ(self, n, i):
        return self.succs[n][i]

    def pred(self, n, i):
        return self.preds[n][i]

    def size(self):
        return len(self.preds)

    def add_node(self):
        n = self.size()

        def resize(array, new_size):
            if new_size > len(array):
                while len(array) < new_size:
                    array.append([])
            else:
                array = array[:new_size]
            return array

        self.preds = resize(self.preds, n+1)
        self.succs = resize(self.succs, n+1)
        return n

    def add_edge(self, x, y):
        self.preds[y].append(x)
        self.succs[x].append(y)

    def get_expr_name(self, expr):
        name = expr.print1(None)
        name = ida_lines.tag_remove(name)
        name = ida_pro.str2user(name)
        return name

    def get_node_label(self, n):
        global CL_NODE_HIGHLIGHT
        global CL_NODE_CIT
        global CL_NODE_COT
        global CL_NODE_COT_CALL
        global CL_NODE_LILAC

        item = self.items[n]
        op = item.op
        insn = item.cinsn
        expr = item.cexpr
        type_name = ida_hexrays.get_ctype_name(op)
        parts = []
        if op == ida_hexrays.cot_ptr:
            parts.append("%s.%d" % (type_name, expr.ptrsize))
        elif op == ida_hexrays.cot_memptr:
            parts.append("%s.%d (m=%d)" % (type_name, expr.ptrsize, expr.m))
        elif op == ida_hexrays.cot_memref:
            parts.append("%s (m=%d)" % (type_name, expr.m,))
        elif op in [
                ida_hexrays.cot_obj,
                ida_hexrays.cot_var]:
            name = self.get_expr_name(expr)
            parts.append("%s.%d %s" % (type_name, expr.refwidth, name))
        elif op in [
                ida_hexrays.cot_num,
                ida_hexrays.cot_helper,
                ida_hexrays.cot_str]:
            name = self.get_expr_name(expr)
            parts.append("%s %s" % (type_name, name,))
        elif op == ida_hexrays.cit_goto:
            parts.append("%s LABEL_%d" % (type_name, insn.cgoto.label_num))
        elif op == ida_hexrays.cit_asm:
            parts.append("%s <asm statements; unsupported ATM>" % type_name)
            # parts.append(" %a.%d" % ())
        else:
            parts.append("%s" % type_name)

        parts.append("ea: %08X" % item.ea)
        if item.is_expr() and not expr.type.empty():
            tstr = expr.type._print()
            parts.append(tstr if tstr else "?")
        return "\n".join(parts)

    def get_node_color(self, n):
        global CL_NODE_HIGHLIGHT
        global CL_NODE_CIT
        global CL_NODE_COT
        global CL_NODE_COT_CALL
        global CL_NODE_LILAC

        item = self.items[n]
        if self.highlight is not None and item.obj_id == self.highlight.obj_id:
            return (True, CL_NODE_HIGHLIGHT)

        # handle COT_
        if item.is_expr():
            # handle call
            if item.op == ida_hexrays.cot_call:
                return (False, CL_NODE_COT_CALL)
            return (False, CL_NODE_COT)

        # handle CIT_
        if item.op in [ida_hexrays.cit_do,
                ida_hexrays.cit_while, 
                ida_hexrays.cit_for]:
            return (False, CL_NODE_CIT_LOOP)
        return (False, CL_NODE_CIT)

    def OnViewKeydown(self, key, state):
        global PALETTE_DEFAULT

        c = chr(key & 0xFF)

        if c == 'C':
            s = ida_kernwin.ask_text(0,
                self.cur_palette,
                "Paste palette from color-hex.com")
            if s:
                try:
                    self.apply_colors(s)
                except:
                    pass
        return True

    def OnClose(self):
        if self.vd_hooks:
            self.vd_hooks.unhook()

    def OnRefresh(self):
        nodes = {}
        self.Clear()

        # nodes
        for n in xrange(len(self.items)):
            item = self.items[n]
            node_label = self.get_node_label(n)
            hl, color = self.get_node_color(n)
            nid = self.AddNode(("%s" % node_label, color))
            nodes[item] = nid
            if hl:
                widget = ida_kernwin.find_widget(self._title)
                ida_graph.viewer_center_on(widget, nid)

        # edges
        for n in xrange(len(self.items)):
            item = self.items[n]

            for i in xrange(self.nsucc(n)):
                t = self.succ(n, i)
                # original code removed, edges may not have labels in IDA
                self.AddEdge(nodes[item], nodes[self.items[t]])

        return True

    def OnGetText(self, node_id):
        return self[node_id]

    def OnClick(self, node_id):
        #print "clk & ignore"
        return False

    def OnDblClick(self, node_id):
        ida_kernwin.jumpto(self.items[node_id].ea)
        return True

    def OnHint(self, node_id):
        """we'll have the hint to display
        the node's text so it stays readable
        if zoomed out"""
        return self.get_node_label(node_id)

# -----------------------------------------------------------------------
class graph_builder_t(ida_hexrays.ctree_parentee_t):

    def __init__(self, cg):
        ida_hexrays.ctree_parentee_t.__init__(self)
        self.init(cg)

    def init(self, cg):
        self.cg = cg
        self.cg.reinit()
        self.reverse = {} # citem_t -> node#

    def add_node(self, i):
        for k in self.reverse.keys():
            if i.obj_id == k.obj_id:
                ida_kernwin.warning("bad ctree - duplicate nodes! (i.ea=%x)" % i.ea)
                return -1

        n = self.cg.add_node()
        if n <= len(self.cg.items):
            self.cg.items.append(i)
        self.cg.items[n] = i
        self.reverse[i] = n
        return n

    def process(self, i):
        n = self.add_node(i)
        if n < 0:
            return n
        if len(self.parents) > 1:
            lp = self.parents.back().obj_id
            for k, v in self.reverse.items():
                if k.obj_id == lp:
                    p = v
                    break
            self.cg.add_edge(p, n)
        return 0

    def visit_insn(self, i):
        return self.process(i)

    def visit_expr(self, e):
        return self.process(e)

# -----------------------------------------------------------------------
class HRDevHelper(idaapi.plugin_t):
    comment = ''
    help = ''
    wanted_name = 'HRDevHelper'
    wanted_hotkey = 'Ctrl-Shift-.'
    hxehook = None
    flags = idaapi.PLUGIN_DRAW

    def init(self):
        return idaapi.PLUGIN_KEEP if ida_hexrays.init_hexrays_plugin() else idaapi.PLUGIN_SKIP

    def run(self, arg):
        global DOCK_POSITION
        global ZOOM

        w = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(w)
            vu_title = ida_kernwin.get_widget_title(w)
            if vu:
                vu.get_current_item(ida_hexrays.USE_KEYBOARD)
                highlight = vu.item.e if vu.item.is_citem() else None
                # create graphviewer
                cg = cfunc_graph_t(highlight, True)
                # build graph for current function
                gb = graph_builder_t(cg)
                gb.apply_to(vu.cfunc.body, None)
                # show graph
                cg.Show()

                # set zoom and dock position
                cg.zoom_and_dock(vu_title, ZOOM, DOCK_POSITION)

    def term(self):
        pass

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return HRDevHelper()