import idaapi
import ida_pro
import ida_hexrays
import ida_kernwin
import ida_gdl
import ida_lines
import ida_graph
import ida_moves

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


Code is heavily based on the vds5.py example that comes with IDAPython.

Known issues:
  - grouping nodes will mess up colors and cause IDA to
    display a warning.
  - Internally, the graph is recreated and refreshed every
    time a new item is selected (performance)
  - IDA does not support labels for edges
"""

DOCK_POSITION = ida_kernwin.DP_RIGHT # DP_... or None

CL_WHITE            = ((255)+  (255<<8)+  (255<<16)) #   0
CL_BLUE             = ((0  )+  (0  <<8)+  (255<<16)) #   1
CL_RED              = ((255)+  (0  <<8)+  (0  <<16)) #   2
CL_GREEN            = ((0  )+  (255<<8)+  (0  <<16)) #   3
CL_YELLOW           = ((255)+  (255<<8)+  (0  <<16)) #   4
CL_MAGENTA          = ((255)+  (0  <<8)+  (255<<16)) #   5
CL_CYAN             = ((0  )+  (255<<8)+  (255<<16)) #   6
CL_DARKGREY         = ((85 )+  (85 <<8)+  (85 <<16)) #   7
CL_DARKBLUE         = ((0  )+  (0  <<8)+  (128<<16)) #   8
CL_DARKRED          = ((128)+  (0  <<8)+  (0  <<16)) #   9
CL_DARKGREEN        = ((0  )+  (128<<8)+  (0  <<16)) #  10
CL_DARKYELLOW       = ((128)+  (128<<8)+  (0  <<16)) #  11
CL_DARKMAGENTA      = ((128)+  (0  <<8)+  (128<<16)) #  12
CL_DARKCYAN         = ((0  )+  (128<<8)+  (128<<16)) #  13
CL_GOLD             = ((255)+  (215<<8)+  (0  <<16)) #  14
CL_LIGHTGREY        = ((170)+  (170<<8)+  (170<<16)) #  15
CL_LIGHTBLUE        = ((128)+  (128<<8)+  (255<<16)) #  16
CL_LIGHTRED         = ((255)+  (128<<8)+  (128<<16)) #  17
CL_LIGHTGREEN       = ((128)+  (255<<8)+  (128<<16)) #  18
CL_LIGHTYELLOW      = ((255)+  (255<<8)+  (128<<16)) #  19
CL_LIGHTMAGENTA     = ((255)+  (128<<8)+  (255<<16)) #  20
CL_LIGHTCYAN        = ((128)+  (255<<8)+  (255<<16)) #  21
CL_LILAC            = ((238)+  (130<<8)+  (238<<16)) #  22
CL_TURQUOISE        = ((64 )+  (224<<8)+  (208<<16)) #  23
CL_AQUAMARINE       = ((127)+  (255<<8)+  (212<<16)) #  24
CL_KHAKI            = ((240)+  (230<<8)+  (140<<16)) #  25
CL_PURPLE           = ((160)+  (32 <<8)+  (240<<16)) #  26
CL_YELLOWGREEN      = ((154)+  (205<<8)+  (50 <<16)) #  27
CL_PINK             = ((255)+  (192<<8)+  (203<<16)) #  28
CL_ORANGE           = ((255)+  (165<<8)+  (0  <<16)) #  29
CL_ORCHID           = ((218)+  (112<<8)+  (214<<16)) #  30
CL_BLACK            = ((0  )+  (0  <<8)+  (0  <<16)) #  31

CL_EDGE_NORMAL = CL_BLACK
CL_EDGE_HIGHLIGHT = CL_DARKRED

class vd_hooks_t(ida_hexrays.Hexrays_Hooks):
    def __init__(self, cg):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.cg = cg

    def func_printed(self, cfunc):
        # cfunc renewed -> regenerate graph
        if self.cg:
            gb = graph_builder_t(self.cg)
            gb.apply_to(cfunc.body, None)
            self.cg.set_highlight(None)
            self.cg.Refresh()
        return 0

    def curpos(self, vu):
        # cursor pos changed -> highlight current node
        if self.cg:
            vu.get_current_item(ida_hexrays.USE_KEYBOARD)
            highlight = vu.item.e if vu.item.is_citem() else None
            self.cg.set_highlight(highlight)
            self.cg.Refresh()
        return 0

class cfunc_graph_t(ida_graph.GraphViewer):
    def __init__(self, highlight, close_open=False):
        self.title = "HRDevHelper"
        ida_graph.GraphViewer.__init__(self, self.title, close_open)
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
        global CL_EDGE_HIGHLIGHT
        global CL_EDGE_NORMAL

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
        item = self.items[n]
        if self.highlight is not None and item.obj_id == self.highlight.obj_id:
            return (True, CL_EDGE_HIGHLIGHT)
        return (False, CL_EDGE_NORMAL)

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

    def dump(self):
        idaapi.msg("%d items:" % len(self.items))
        for i in self.items:
            idaapi.msg("\t%s (%08x)" % (i, i.ea))

        idaapi.msg("succs:")
        for s in self.succs:
            idaapi.msg("\t%s" % s)

        idaapi.msg("preds:")
        for p in self.preds:
            idaapi.msg("\t%s" % p)


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
                self.cg.dump()
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

def cg_zoom_and_dock(title, vu_title, dock_position=None):
    widget = ida_kernwin.find_widget(title)
    if widget:
        if dock_position is not None:
            gli = ida_moves.graph_location_info_t()
            if ida_graph.viewer_get_gli(gli, widget):
                gli.zoom = 1.0
                ida_graph.viewer_set_gli(widget, gli)
        ida_kernwin.set_dock_pos(title, vu_title, dock_position)

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
                cg_zoom_and_dock(cg._title, vu_title, DOCK_POSITION)
                cg.Refresh()

    def term(self):
        pass

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return HRDevHelper()