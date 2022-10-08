import ida_hexrays
import ida_lines
import ida_kernwin

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