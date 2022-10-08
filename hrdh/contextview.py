import ida_kernwin
import ida_lines
import ida_hexrays
from hrdh.config import PLUGIN_NAME

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
            _ea = _exp = _type = _objid = "???"
            if vu.get_current_item(ida_hexrays.USE_KEYBOARD):
                focus = vu.item.e if vu.item.is_citem() else None
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
