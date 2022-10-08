import sys
import ida_graph
import ida_hexrays
import ida_kernwin
import ida_moves
import ida_lines
import ida_pro
import hrdh.tools as tools
from hrdh.config import PLUGIN_NAME

# -----------------------------------------------------------------------
class cfunc_graph_t(ida_graph.GraphViewer):
    def __init__(self, focus, config, close_open=False, subtitle=None):
        self.title = "%s%s" % (PLUGIN_NAME, " [%s]" % subtitle if subtitle else "")
        self.config = config
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
                    line_numbers = tools.get_selected_lines(vu)
                    for n in line_numbers:
                        objs += tools.get_obj_ids(vu, n)
                    focusitem = vu.item.e if vu.item.is_citem() else None
                    self.cg.update(cfunc=None, objs=objs, focus=focusitem.obj_id if focusitem else None)
                return 0

        # apply config
        #  - options
        self.center_node = self.config["options"]["center"]
        # hotkeys/actions
        #self.
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
def show_ctree_graph(config, create_subgraph=False):
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
                config,
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
