import ida_idaapi
import ida_pro
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_graph
import ida_moves
import ida_lines
import ida_diskio
import re
import os
import configparser

__author__ = "https://github.com/patois/"

PLUGIN_NAME = "HRDevHelper"
CFG_FILENAME = "%s.cfg" % PLUGIN_NAME

CONFIG_DEFAULT = """; Config file for HRDevHelper (https://github.com/patois/HRDevHelper)

; options
;   center:   center current node
;   zoom:     1.0 = 100%
;   dockpos:  one of the DP_... constants from ida_kernwin
[options]
center=True
zoom=1.0
dockpos=DP_RIGHT

; RGB colors in hex
[frame_palette]
default=000000
focus=32ade1
highlight=ffae1b

; RGB colors in hex
[node_palette]
loop=663333
call=202050
cit=000000
cot=222222

; SCOLOR_... constants from ida_lines
[text_palette]
default=SCOLOR_DEFAULT
highlight=SCOLOR_EXTRA
;highlight=SCOLOR_SYMBOL
"""

# -----------------------------------------------------------------------
def get_cfg_filename():
    """returns full path for config file."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "%s" % CFG_FILENAME)

# -----------------------------------------------------------------------
def load_cfg(reload=False):
    """loads HRDevHelper configuration."""
    
    config = {}
    cfg_file = get_cfg_filename()
    ida_kernwin.msg("%s: %sloading %s...\n" % (PLUGIN_NAME,
        "re" if reload else "",
        cfg_file))
    if not os.path.isfile(cfg_file):
        ida_kernwin.msg("%s: default configuration (%s) does not exist!\n" % (PLUGIN_NAME, cfg_file))
        ida_kernwin.msg("Creating default configuration\n")
        try:
            with open(cfg_file, "w") as f:
                f.write("%s" % CONFIG_DEFAULT)
        except:
            ida_kernwin.msg("failed!\n")
            return config
        return load_cfg(reload=True)

    configfile = configparser.RawConfigParser()
    configfile.readfp(open(cfg_file))

    # read all sections
    try:
        for section in configfile.sections():
            config[section] = {}

            if section in ["node_palette", "frame_palette"]:
                for name, value in configfile.items(section):
                    config[section][name] = swapcol(int(value, 0x10))
            elif section == "text_palette":
                for name, value in configfile.items(section):
                    config[section][name] = getattr(globals()["ida_lines"], value)
            elif section == "options":
                for name, value in configfile.items(section):
                    if name in ["center"]:
                        config[section][name] = configfile[section].getboolean(name)
                    elif name in ["zoom"]:
                        config[section][name] = float(value)
                    elif name in ["dockpos"]:
                        config[section][name] = getattr(globals()["ida_kernwin"], value)
        ida_kernwin.msg("done!\n")
    except:
        raise RuntimeError
    return config

# -----------------------------------------------------------------------
def swapcol(x):
    return (((x & 0x000000FF) << 16) |
                (x & 0x0000FF00) |
            ((x & 0x00FF0000) >> 16))

# -----------------------------------------------------------------------
def get_obj_ids(vdui, lnnum):
    obj_ids = []
    pc = vdui.cfunc.get_pseudocode()
    if lnnum >= len(pc):
        return obj_ids
    line = pc[lnnum].line
    tag = ida_lines.COLOR_ON + chr(ida_lines.COLOR_ADDR)
    pos = line.find(tag)
    while pos != -1 and len(line[pos+len(tag):]) >= ida_lines.COLOR_ADDR_SIZE:
        addr = line[pos+len(tag):pos+len(tag)+ida_lines.COLOR_ADDR_SIZE]
        idx = int(addr, 16)
        a = ida_hexrays.ctree_anchor_t()
        a.value = idx
        if a.is_valid_anchor() and a.is_citem_anchor():
            item = vdui.cfunc.treeitems.at(a.get_index())
            if item:
                obj_ids.append(item.obj_id)
        pos = line.find(tag, pos+len(tag)+ida_lines.COLOR_ADDR_SIZE)
    return obj_ids

# -----------------------------------------------------------------------
def get_selected_lines(vdui):
    vdui.get_current_item(ida_hexrays.USE_KEYBOARD)
    line_numbers = []
    w = vdui.ct
    p0 = ida_kernwin.twinpos_t()
    p1 = ida_kernwin.twinpos_t()
    if ida_kernwin.read_selection(w, p0, p1):
        place0 = p0.place(w)
        place1 = p1.place(w)
        a = place0.as_simpleline_place_t(place0).n
        b = place1.as_simpleline_place_t(place1).n
        line_numbers = [i for i in range(a, b+1)]
    else:
        line_numbers = [vdui.cpos.lnnum]
    return line_numbers

# -----------------------------------------------------------------------
class cfunc_graph_t(ida_graph.GraphViewer):
    def __init__(self, focus, config, close_open=False, subtitle=None):
        self.title = "%s%s" % (PLUGIN_NAME, " [%s]" % subtitle if subtitle else "") 
        ida_graph.GraphViewer.__init__(self, self.title, close_open)

        class vd_hooks_t(ida_hexrays.Hexrays_Hooks):
            def __init__(self, cg):
                ida_hexrays.Hexrays_Hooks.__init__(self)
                self.cg = cg

            def refresh_pseudocode(self, vu):
                # function refreshed
                self.cg.update(cfunc=vu.cfunc, focus=None)
                return 0

            def curpos(self, vu):
                # cursor pos changed -> highlight nodes that belong to current line
                if self.cg and vu.get_current_item(ida_hexrays.USE_KEYBOARD):
                    objs = []
                    line_numbers = get_selected_lines(vu)
                    for n in line_numbers:
                        objs += get_obj_ids(vu, n)
                    focusitem = vu.item.e if vu.item.is_citem() else None
                    self.cg.update(cfunc=None, objs=objs, focus=focusitem.obj_id if focusitem else None)
                return 0

        # apply config
        #  - options
        self.config = config
        self.center_node = self.config["options"]["center"]
        #  - frame colors
        self.COLOR_FRAME_DEFAULT = self.config["frame_palette"]["default"]
        self.COLOR_FRAME_HIGHLIGHT = self.config["frame_palette"]["highlight"]
        self.COLOR_FRAME_FOCUS = self.config["frame_palette"]["focus"]
        #  - node colors
        self.COLOR_NODE_CIT_LOOP = self.config["node_palette"]["loop"]
        self.COLOR_NODE_COT_CALL = self.config["node_palette"]["call"]
        self.COLOR_NODE_CIT = self.config["node_palette"]["cit"]
        self.COLOR_NODE_COT = self.config["node_palette"]["cot"]
        #  - text colors
        self.COLOR_TEXT_DEFAULT = self.config["text_palette"]["default"]
        self.COLOR_TEXT_HIGHLIGHT = self.config["text_palette"]["highlight"]
        #  - other settings
        self.zoom = self.config["options"]["zoom"]
        self.dock_position = self.config["options"]["dockpos"]

        # can be toggled with hotkey in order for the graph
        # to include debug/verbose output
        self.debug = False
        self.redraw = True
        self.items = [] # list of citem_t
        self._set_focus(focus)

        self.objs = []
        self.succs = [] # list of lists of next nodes
        self.preds = [] # list of lists of previous nodes

        self.vd_hooks = vd_hooks_t(self)
        self.vd_hooks.hook()

    def reinit(self):
        self.items = []
        self.succs = []
        self.preds = []
        self.Clear()

    def add_node(self):
        n = self._size()

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

    def zoom_and_dock(self, target):
        widget = ida_kernwin.get_current_widget()
        if widget and self.dock_position:
            gli = ida_moves.graph_location_info_t()
            if ida_graph.viewer_get_gli(gli, widget):
                gli.zoom = self.zoom
                ida_graph.viewer_set_gli(widget, gli)
            ida_kernwin.set_dock_pos(
                ida_kernwin.get_widget_title(widget),
                ida_kernwin.get_widget_title(target),
                self.dock_position)
            self.Refresh()

    def update(self, cfunc=None, objs=None, focus=None):
        if cfunc:
            gb = graph_builder_t(self, cfunc)
            gb.apply_to(cfunc.body, cfunc.body)
            self.redraw = True
        self._set_focus(focus)
        self._set_objs(objs)
        self.Refresh()
        return

    def _set_focus(self, focus):
        self.focus = focus

    def _set_objs(self, objs):
        self.objs = objs

    def _nsucc(self, n):
        return len(self.succs[n]) if self._size() else 0

    def _npred(self, n):
        return len(self.preds[n]) if self._size() else 0

    def _succ(self, n, i):
        return self.succs[n][i]

    def _pred(self, n, i):
        return self.preds[n][i]

    def _size(self):
        return len(self.preds)

    def _get_expr_name(self, expr):
        name = expr.print1(None)
        name = ida_lines.tag_remove(name)
        name = ida_pro.str2user(name)
        return name

    def _get_node_label(self, n, highlight_node=False):
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
            name = self._get_expr_name(expr)
            parts.append("%s.%d %s" % (type_name, expr.refwidth, name))
        elif op in [
                ida_hexrays.cot_num,
                ida_hexrays.cot_helper,
                ida_hexrays.cot_str]:
            name = self._get_expr_name(expr)
            parts.append("%s %s" % (type_name, name,))
        elif op == ida_hexrays.cit_goto:
            parts.append("%s LABEL_%d" % (type_name, insn.cgoto.label_num))
        elif op == ida_hexrays.cit_asm:
            parts.append("%s <asm statements; unsupported ATM>" % type_name)
            # parts.append(" %a.%d" % ())
        else:
            parts.append("%s" % type_name)

        parts.append("ea: %x" % item.ea)
        # add type
        if item.is_expr() and not expr.type.empty():
            tstr = expr.type._print()
            parts.append(tstr if tstr else "?")

        if self.debug:
            parts.append("-"*20)
            parts.append("obj_id: %x" % item.obj_id)
            if op is ida_hexrays.cot_var:
                parts.append("idx: %d" % expr.v.idx)
                lv = expr.v.getv()                        
                if lv:
                    parts.append("width: %d" % lv.width)
                    parts.append("defblk: %d" % lv.defblk)
                    parts.append("cmt: %s" % lv.cmt)
                    parts.append("arg_var: %r" % lv.is_arg_var)
                    parts.append("thisarg: %r" % lv.is_thisarg())
                    parts.append("result_var: %r" % lv.is_result_var)
                    parts.append("used_byref: %r" % lv.is_used_byref())
                    parts.append("mapdst_var: %r" % lv.is_mapdst_var)
                    parts.append("overlapped_var: %r" % lv.is_overlapped_var)
                    parts.append("floating_var: %r" % lv.is_floating_var)
                    parts.append("typed: %r" % lv.typed)
                    if self.debug > 1:
                        parts.append("divisor: %d" % lv.divisor)
                        parts.append("automapped: %r" % lv.is_automapped())
                        parts.append("fake_var: %r" % lv.is_fake_var)
                        parts.append("spoiled_var: %r" % lv.is_spoiled_var)
                        parts.append("noptr_var: %r" % lv.is_noptr_var())
                        parts.append("forced_var: %r" % lv.is_forced_var())
                        parts.append("dummy_arg: %r" % lv.is_dummy_arg())
                        parts.append("used: %r" % lv.used)
                        parts.append("user_info: %r" % lv.has_user_info)
                        parts.append("user_name: %r" % lv.has_user_name)
                        parts.append("user_type: %r" % lv.has_user_type)
                        parts.append("regname: %r" % lv.has_regname())
                        parts.append("mreg_done: %r" % lv.mreg_done)
                        parts.append("nice_name: %r" % lv.has_nice_name)
                        parts.append("unknown_width: %r" % lv.is_unknown_width)
                        parts.append("in_asm: %r" % lv.in_asm())
                        parts.append("notarg: %r" % lv.is_notarg())
                        parts.append("decl_unused: %r" % lv.is_decl_unused())
            elif op is ida_hexrays.cot_obj:
                    parts.append("obj_ea: %x" % expr.obj_ea)

        # disable hightlight color for now -> requires labels to be re-generated/graph to be redrawn
        #scolor = self.COLOR_TEXT_HIGHLIGHT if highlight_node else self.COLOR_TEXT_DEFAULT
        scolor = self.COLOR_TEXT_DEFAULT
        parts = [ida_lines.COLSTR("%s" % part, scolor) for part in parts]
        return "\n".join(parts)

    def _get_node_info(self, n):
        item = self.items[n]
        color = 0
        focus_node = False
        highlight_node = False

        # is curent node an item that belongs to current pseudocode line?
        if self.objs is not None and item.obj_id in self.objs:
            highlight_node = True

        if self.focus is not None and item.obj_id == self.focus:
            focus_node = True

        # handle COT_
        if item.is_expr():
            # handle call
            if item.op == ida_hexrays.cot_call:
                color = self.COLOR_NODE_COT_CALL
            else:
                color = self.COLOR_NODE_COT
        # handle CIT_
        elif ida_hexrays.is_loop(item.op):
            color = self.COLOR_NODE_CIT_LOOP
        else:
            color = self.COLOR_NODE_CIT

        return (focus_node, highlight_node, color)

    def OnViewKeydown(self, key, state):
        c = chr(key & 0xFF)

        if c == 'C':
            self.center_node = not self.center_node
            ida_kernwin.msg("%s: centering %sabled\n" % (PLUGIN_NAME, "en" if self.center_node else "dis"))
        elif c == 'D':
            self.debug = (self.debug+1)%3
            ida_kernwin.msg("%s: debug %d\n" % (PLUGIN_NAME, self.debug))
            self.redraw = True
            self.Refresh()
        return True

    def OnClose(self):
        if self.vd_hooks:
            self.vd_hooks.unhook()

    def OnRefresh(self):
        """
        @return: Returning True tells the graph viewer to use the items. Otherwise old items will be used.
        """
        focus_node_id = None
        if self.redraw:
            self.nodes = {}
            self.Clear()

            # nodes
            for n in range(len(self.items)):
                item = self.items[n]
                focus_node, highlight_node, color = self._get_node_info(n)
                node_label = self._get_node_label(n, highlight_node=highlight_node)
                nid = self.AddNode((node_label, color))

                framecol = self.COLOR_FRAME_DEFAULT
                if highlight_node:
                    framecol = self.COLOR_FRAME_HIGHLIGHT
                if focus_node:
                    framecol = self.COLOR_FRAME_FOCUS

                p = ida_graph.node_info_t()            
                p.frame_color = framecol
                self.SetNodeInfo(nid, p, ida_graph.NIF_FRAME_COLOR)
                self.nodes[item.obj_id] = nid

                if focus_node:
                    focus_node_id = nid

            # edges
            for n in range(len(self.items)):
                item = self.items[n]

                for i in range(self._nsucc(n)):
                    t = self._succ(n, i)
                    self.AddEdge(self.nodes[item.obj_id], self.nodes[self.items[t].obj_id])

            if self.center_node and focus_node_id:
                widget = ida_kernwin.find_widget(self._title)
                ida_graph.viewer_center_on(widget, focus_node_id)

            self.redraw = False
            # use new graph
            return True

        for n in range(len(self.items)):
            item = self.items[n]
            focus_node, highlight_node, color = self._get_node_info(n)
            nid = self.nodes[item.obj_id]

            framecol = self.COLOR_FRAME_DEFAULT
            if highlight_node:
                framecol = self.COLOR_FRAME_HIGHLIGHT
            if focus_node:
                focus_node_id = nid
                framecol = self.COLOR_FRAME_FOCUS

            p = ida_graph.node_info_t()            
            p.frame_color = framecol
            self.SetNodeInfo(nid, p, ida_graph.NIF_FRAME_COLOR)

        if self.center_node and focus_node_id:
            widget = ida_kernwin.find_widget(self._title)
            ida_graph.viewer_center_on(widget, focus_node_id)
        return False

    def OnGetText(self, node_id):
        return self[node_id]
    
    def OnDblClick(self, node_id):
        target_ea = self.items[node_id].ea
        r = ida_kernwin.get_highlight(ida_kernwin.get_current_viewer())
        if r:
            text, _ = r
            # ghetto-convert hex strings to int
            try:
                target_ea = int(text, 16)
            except ValueError:
                pass

        ida_kernwin.jumpto(target_ea)
        return True

    def OnHint(self, node_id):
        return self._get_node_label(node_id)

# -----------------------------------------------------------------------
class graph_builder_t(ida_hexrays.ctree_parentee_t):
    def __init__(self, cg, cf=None):
        ida_hexrays.ctree_parentee_t.__init__(self)
        self.cg = cg
        self.n_items = len(cf.treeitems) if cf else None
        self.n_processed = 0
        self.cg.reinit()
        self.reverse = {} # citem_t -> node#
        if self.n_items:
            ida_kernwin.show_wait_box("%s: building graph" % PLUGIN_NAME)

    def _add_node(self, i):
        n = self.cg.add_node()
        if n <= len(self.cg.items):
            self.cg.items.append(i)
        self.cg.items[n] = i
        self.reverse[i.obj_id] = n
        return n

    def _process(self, i):
        n = self._add_node(i)
        self.n_processed += 1
        if n < 0:
            return n
        if len(self.parents) > 1:
            lp = self.parents.back().obj_id
            for k_obj_id, v in self.reverse.items():
                if k_obj_id == lp:
                    p = v
                    break
            self.cg.add_edge(p, n)
        if self.n_items:
            if self.n_processed >= self.n_items:
                ida_kernwin.hide_wait_box()
            if ida_kernwin.user_cancelled():
                return 1
        return 0

    def visit_insn(self, i):
        return self._process(i)

    def visit_expr(self, e):
        return self._process(e)

# -----------------------------------------------------------------------
def show_ctree_graph(create_subgraph=False):
    w = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_PSEUDOCODE:
        vu = ida_hexrays.get_widget_vdui(w)
        if vu:
            vu.get_current_item(ida_hexrays.USE_KEYBOARD)
            focusitem = vu.item.e if vu.item.is_citem() else None
            sub = None
            if create_subgraph:
                if not focusitem:
                    ida_kernwin.msg("%s: cursor must be placed on a citem!\n" % PLUGIN_NAME)
                    return
                sub = "subgraph %x" % focusitem.obj_id
            # create graphviewer
            cg = cfunc_graph_t(
                focusitem,
                HRDevHelper.config,
                close_open=True,
                subtitle=sub)
            # build graph for current function
            gb = graph_builder_t(cg, None if create_subgraph else vu.cfunc)
            gb.apply_to(focusitem if create_subgraph else vu.cfunc.body, vu.cfunc.body)
            # show graph
            cg.Show()
            # set zoom and dock position
            cg.zoom_and_dock(w)
    return

# -----------------------------------------------------------------------
class graph_dumper_t(ida_hexrays.ctree_parentee_t):
    def __init__(self):
        ida_hexrays.ctree_parentee_t.__init__(self)
        self.lines = []
        self.nodes = {}

    def _add_node(self,i):
        ci = i.cexpr if i.is_expr() else i.cinsn
        p = self.parents.back()
        pi = p.cexpr if p.is_expr() else p.cinsn
        pi_op = pi.op
        ci_obj_id = ci.obj_id
        label = "<error>"
        if len(self.parents) > 1:
            elem = "<error>"
            if pi_op is ida_hexrays.cot_call:
                if pi.x.obj_id == ci_obj_id:
                    elem = "x"
                else:
                    argc = len(pi.a)
                    for j in range(argc):
                        if ci_obj_id == pi.a[j].obj_id:
                            elem = "a[%d]" % j
                            break
            elif pi_op is ida_hexrays.cit_expr:
                if pi.cexpr.obj_id == ci_obj_id:
                    elem = "cexpr"
            elif pi_op is ida_hexrays.cit_block:
                blockc = len(pi.cblock)
                for j in range(blockc):
                    if pi.cblock[j].obj_id == ci_obj_id:
                        elem = "cblock[%d]" % j
                        break
            elif pi_op is ida_hexrays.cit_if:
                if pi.cif.expr.obj_id == ci_obj_id:
                    elem = "cif.expr"
                elif pi.cif.ithen.obj_id == ci_obj_id:
                    elem = "cif.ithen"
                elif pi.cif.ielse and pi.cif.ielse.obj_id == ci_obj_id:
                    elem = "cif.ielse"
            elif pi_op is ida_hexrays.cit_return:
                if pi.creturn.expr.obj_id == ci_obj_id:
                    elem = "creturn.expr"
            elif pi_op is ida_hexrays.cit_for:
                if pi.cfor.expr.obj_id == ci_obj_id:
                    elem = "cfor.expr"
                elif pi.cfor.init.obj_id == ci_obj_id:
                    elem = "cfor.init"
                elif pi.cfor.step.obj_id == ci_obj_id:
                    elem = "cfor.step"
                elif pi.cfor.body.obj_id == ci_obj_id:
                    elem = "cfor.body"
            elif pi_op is ida_hexrays.cit_while:
                if pi.cwhile.expr.obj_id == ci_obj_id:
                    elem = "cwhile.expr"
                elif pi.cwhile.body.obj_id == ci_obj_id:
                    elem = "cwhile.body"
            elif pi_op is ida_hexrays.cit_do:
                if pi.cdo.expr.obj_id == ci_obj_id:
                    elem = "cdo.expr"
                elif pi.cdo.body.obj_id == ci_obj_id:
                    elem = "cdo.body"
            elif pi_op is ida_hexrays.cit_switch:
                switchc = len(pi.cswitch.cases)
                if pi.cswitch.expr.obj_id == ci_obj_id:
                    elem = "cswitch.expr"
                else:
                    for j in range(switchc):
                        if pi.cswitch.cases[j].obj_id == ci_obj_id:
                            elem = "cswitch.cases[%d]" % j
                            break
            elif pi_op is ida_hexrays.cit_goto:
                pass
            else:
                if ida_hexrays.op_uses_x(pi_op) and pi.x.obj_id == ci_obj_id:
                    elem = "x"
                elif ida_hexrays.op_uses_y(pi_op) and pi.y.obj_id == ci_obj_id:
                    elem = "y"
                elif ida_hexrays.op_uses_z(pi_op) and pi.z.obj_id == ci_obj_id:
                    elem = "z"
            label = "%s.%s" % (self.nodes[pi.obj_id], elem)
        else:
            label = "i"
        self.nodes[ci_obj_id] = label
        return (ci_obj_id, label)

    def _append_lambda_expression(self, i, label, include_data=False):
        def to_mask(n):
            mask = 0
            for i in range(n):
                mask |= 0xff << 8*i
            return mask
        ci = i.cexpr if i.is_expr() else i.cinsn
        expr1 = "%s.op is idaapi.c%ct_%s" % (label, "o" if i.is_expr() else "i", ida_hexrays.get_ctype_name(ci.op))
        expr2 = None
        if include_data:
            # TODO
            if i.op is ida_hexrays.cot_num: #in [ida_hexrays.cot_num, ida_hexrays.cot_helper, ida_hexrays.cot_str]:
                #expr2 = "%s.numval() == %s" % (label, get_expr_name(i))
                #print("%x %d" % (i.ea, ord(i.n.nf.org_nbytes)))
                expr2 = "%s.numval() == 0x%x" % (label, i.numval() & to_mask(ord(i.n.nf.org_nbytes)))
        self.lines.append(expr1)
        if expr2:
            self.lines.append(expr2)
        return

    def _process(self, i):
        _, label = self._add_node(i)
        self._append_lambda_expression(i, label, include_data=False)
        return 0

    def visit_insn(self, i):
        return self._process(i)

    def visit_expr(self, e):
        return self._process(e)

# -----------------------------------------------------------------------
def dump_ctree_to_lambda(create_subgraph=False):
    w = ida_kernwin.get_current_widget()
    if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_PSEUDOCODE:
        vu = ida_hexrays.get_widget_vdui(w)
        if vu:
            vu.get_current_item(ida_hexrays.USE_KEYBOARD)
            focusitem = vu.cfunc.body
            if create_subgraph:
                focusitem = vu.item.e if vu.item.is_citem() else None
            if focusitem:
                gd = graph_dumper_t()
                gd.apply_to(focusitem, vu.cfunc.body)
                lines = "(%s)" % " and\n".join(gd.lines)
                ida_kernwin.msg("%s\n%x:\n%s" % ("-"*80, ida_kernwin.get_screen_ea(), lines))

# -----------------------------------------------------------------------
class context_viewer_t(ida_kernwin.Form):
    INSTANCE = None

    def __init__(self):
        F = ida_kernwin.Form
        form = r"""STARTITEM {id:mstr_pexp}
BUTTON YES NONE
BUTTON NO NONE
BUTTON CANCEL NONE
%s - Context View

{FormChangeCb}
item:   {lbl_exp}
.op:    {lbl_op}
.ea:    {lbl_ea}
.obj_id:{lbl_objid}

<##Python expression:{mstr_pexp}>

address:{lbl_sea}""" % PLUGIN_NAME
        t = ida_kernwin.textctrl_info_t()
        controls = {
            "lbl_exp": F.StringLabel(""),
            "lbl_op": F.StringLabel(""),
            "lbl_ea": F.StringLabel(""),
            "lbl_objid": F.StringLabel(""),
            "lbl_sea": F.StringLabel(""),
            "mstr_pexp": F.MultiLineTextControl(
                text="",
                flags=t.TXTF_FIXEDFONT | t.TXTF_READONLY,
                tabsize=2, width=500, swidth=128),
            'FormChangeCb': F.FormChangeCb(self.OnFormChange)}
        self.hooks = None
        F.__init__(self, form, controls)

    def OnFormChange(self, fid):
        if fid == -1: # init form
            # install vd hook
            self.OnFormInit()
        elif fid == -5: # close form? (undocumented?)
            # uninstall vd hook
            self.OnFormClose()
        return 1

    def OnFormInit(self):
        class vd_hooks_t(ida_hexrays.Hexrays_Hooks):
            def __init__(self, ev):
                ida_hexrays.Hexrays_Hooks.__init__(self)
                self.ev = ev
            def refresh_pseudocode(self, vu):
                # function refreshed
                self.ev._update(vu)
                return 0
            def curpos(self, vu):
                self.ev._update(vu)
                return 0
        if not self.hooks:
            self.hooks = vd_hooks_t(self)
            self.hooks.hook()

        w = ida_kernwin.get_current_widget()
        if ida_kernwin.get_widget_type(w) == ida_kernwin.BWN_PSEUDOCODE:
            vu = ida_hexrays.get_widget_vdui(w)
            if vu:
                self._update(vu)
        return

    def OnFormClose(self):
        if self.hooks:
            self.hooks.unhook()
            self.hooks = None
        return

    def _update(self, vu):
        if vu:
            focus = None
            if vu.get_current_item(ida_hexrays.USE_KEYBOARD):
                focus = vu.item.e if vu.item.is_citem() else None
            _ea = _exp = _type = _objid = "???"
            if vu.get_current_item(ida_hexrays.USE_KEYBOARD):
                item = vu.item.it
                isexpr = item.is_expr()
                item_type = ida_hexrays.get_ctype_name(item.op)
                if isexpr:
                    _exp = item.cexpr.print1(None)
                    _exp = ida_lines.tag_remove(_exp)
                _ea = "%x" % item.ea
                _type = "c%ct_%s" % ("o" if isexpr else "i", item_type)
                _objid = "%x" % item.obj_id
            self.SetControlValue(self.lbl_ea, _ea)
            self.SetControlValue(self.lbl_exp, _exp)
            self.SetControlValue(self.lbl_op, _type)
            self.SetControlValue(self.lbl_objid, _objid)
            gd = graph_dumper_t()
            gd.apply_to(vu.cfunc.body if not focus else focus, vu.cfunc.body)
            expr = "(%s)" % " and\n".join(gd.lines)
            tc = self.GetControlValue(self.mstr_pexp)
            tc.text = expr
            self.SetControlValue(self.mstr_pexp, tc)
            self.SetControlValue(self.lbl_sea, "%x" % ida_kernwin.get_screen_ea())
        return

    @staticmethod
    def open():
        if context_viewer_t.INSTANCE is None:
            form = context_viewer_t()
            form.modal = False
            f, _ = form.Compile()
            context_viewer_t.INSTANCE = f
        return context_viewer_t.INSTANCE.Open()

# -----------------------------------------------------------------------
class hotkey_handler_t(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if ctx.action == HRDevHelper.get_action_name(HRDevHelper.act_show_ctree):
            show_ctree_graph()
        elif ctx.action == HRDevHelper.get_action_name(HRDevHelper.act_show_sub_tree):
            show_ctree_graph(create_subgraph=True)
        elif ctx.action == HRDevHelper.get_action_name(HRDevHelper.act_show_context):
            context_viewer_t.open()
        else:
            ida_kernwin.warning("Not implemented")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

# ----------------------------------------------------------------------------
class ui_event_handler_t(ida_kernwin.UI_Hooks):
    def __init__(self, actions):
        ida_kernwin.UI_Hooks.__init__(self)
        self.actions = actions
 
    def finish_populating_widget_popup(self, widget, popup_handle):       
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            class menu_handler_t(ida_kernwin.action_handler_t):
                def __init__(self, name):
                    ida_kernwin.action_handler_t.__init__(self)
                    self.name = name

                def activate(self, ctx):
                    if self.name == HRDevHelper.get_action_name(HRDevHelper.act_show_ctree):
                        show_ctree_graph()
                    elif self.name == HRDevHelper.get_action_name(HRDevHelper.act_show_sub_tree):
                        show_ctree_graph(create_subgraph=True)
                    elif self.name == HRDevHelper.get_action_name(HRDevHelper.act_show_context):
                        context_viewer_t.open()
                    else:
                        ida_kernwin.warning("Not implemented")                    
                    return 1

                def update(self, ctx):
                    return ida_kernwin.AST_ENABLE_FOR_WIDGET

            for actname, data in self.actions.items():
                desc, hotkey = data
                action_desc = ida_kernwin.action_desc_t(
                    actname,
                    desc,
                    menu_handler_t(actname),
                    hotkey,
                    None,
                    -1)
                ida_kernwin.attach_dynamic_action_to_popup(widget, popup_handle, action_desc, "%s/" % PLUGIN_NAME)

# -----------------------------------------------------------------------
class HRDevHelper(ida_idaapi.plugin_t):
    comment = ""
    help = ""
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    flags = ida_idaapi.PLUGIN_DRAW | ida_idaapi.PLUGIN_HIDE
    act_show_ctree = "show ctree"
    act_show_sub_tree = "show sub-tree"
    act_show_context = "show context"
    config = None

    @staticmethod
    def get_action_name(desc):
        return "%s:%s" % (PLUGIN_NAME, desc)

    def _register_action(self, hotkey, desc):
        actname = HRDevHelper.get_action_name(desc)
        print(actname)
        if ida_kernwin.register_action(ida_kernwin.action_desc_t(
            actname,
            desc,
            hotkey_handler_t(),
            hotkey,
            None,
            -1)):
            self._registered_actions[actname] = (desc, hotkey)
        else:
            ida_kernwin.warning("%s: failed registering action" % PLUGIN_NAME)

    def _install(self):
        self._register_action("Ctrl-.", HRDevHelper.act_show_ctree)
        self._register_action("Ctrl-Shift-.", HRDevHelper.act_show_sub_tree)
        self._register_action("V", HRDevHelper.act_show_context)
        self.ui_hooks = ui_event_handler_t(self._registered_actions)
        self.ui_hooks.hook()

    def _uninstall(self):
        self.ui_hooks.unhook()
        for desc in self._registered_actions:
            ida_kernwin.unregister_action(desc)

    def init(self):
        self._registered_actions = {}
        result = ida_idaapi.PLUGIN_SKIP
        if ida_hexrays.init_hexrays_plugin():
            try:
                HRDevHelper.config = load_cfg()
            except:
                ida_kernwin.warning(("%s failed parsing %s.\n"
                    "If fixing this config file manually doesn't help, please delete the file and re-run the plugin.\n\n"
                    "The plugin will now terminate." % (PLUGIN_NAME, get_cfg_filename())))
            else:
                self._install()
                result = ida_idaapi.PLUGIN_KEEP 
        return result

    def run(self, arg):
        pass

    def term(self):
        self._uninstall()

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return HRDevHelper()
