import ida_kernwin
from hrdevhelper import HRDevHelper
import hrdh.contextview as cview
import hrdh.graph as graph
from hrdh.config import PLUGIN_NAME

# -----------------------------------------------------------------------
class hotkey_handler_t(ida_kernwin.action_handler_t):
    def __init__(self, config):
        self.config = config
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        if ctx.action == HRDevHelper.get_action_name(HRDevHelper.act_show_ctree):
            graph.show_ctree_graph(self.config)
        elif ctx.action == HRDevHelper.get_action_name(HRDevHelper.act_show_sub_tree):
            graph.show_ctree_graph(self.config, create_subgraph=True)
        elif ctx.action == HRDevHelper.get_action_name(HRDevHelper.act_show_context):
            cview.context_viewer_t.open()
        else:
            ida_kernwin.warning("Not implemented")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_WIDGET if ctx.widget_type == ida_kernwin.BWN_PSEUDOCODE else ida_kernwin.AST_DISABLE_FOR_WIDGET

# ----------------------------------------------------------------------------
class ui_event_handler_t(ida_kernwin.UI_Hooks):
    def __init__(self, actions, config):
        self.actions = actions
        self.config = config
        ida_kernwin.UI_Hooks.__init__(self)
 
    def finish_populating_widget_popup(self, widget, popup_handle):       
        if ida_kernwin.get_widget_type(widget) == ida_kernwin.BWN_PSEUDOCODE:
            class menu_handler_t(ida_kernwin.action_handler_t):
                def __init__(self, name):
                    ida_kernwin.action_handler_t.__init__(self)
                    self.name = name

                def activate(self, ctx):
                    if self.name == HRDevHelper.get_action_name(HRDevHelper.act_show_ctree):
                        graph.show_ctree_graph(self.config)
                    elif self.name == HRDevHelper.get_action_name(HRDevHelper.act_show_sub_tree):
                        graph.show_ctree_graph(self.config, create_subgraph=True)
                    elif self.name == HRDevHelper.get_action_name(HRDevHelper.act_show_context):
                        cview.context_viewer_t.open()
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
