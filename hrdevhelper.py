import ida_idaapi
import ida_hexrays
import ida_kernwin
import hrdh.config as cfg
import hrdh.handler as handler
import hrdh.contextview as cview
import hrdh.graph as graph

__author__ = "https://github.com/patois/"

# -----------------------------------------------------------------------
class HRDevHelper(ida_idaapi.plugin_t):
    comment = ""
    help = ""
    wanted_name = cfg.PLUGIN_NAME
    wanted_hotkey = ""
    flags = ida_idaapi.PLUGIN_DRAW
    if not cfg.DEBUG:
        flags |= ida_idaapi.PLUGIN_HIDE
    act_show_ctree = "show ctree"
    act_show_sub_tree = "show sub-tree"
    act_show_context = "show context"
    config = None

    @staticmethod
    def get_action_name(desc):
        return "%s:%s" % (cfg.PLUGIN_NAME, desc)

    def _register_action(self, hotkey, desc):
        actname = HRDevHelper.get_action_name(desc)
        ida_kernwin.msg("%s -> %s" % (hotkey, actname))
        if ida_kernwin.register_action(ida_kernwin.action_desc_t(
            actname,
            desc,
            handler.hotkey_handler_t(HRDevHelper.config),
            hotkey,
            None,
            -1)):
            self._registered_actions[actname] = (desc, hotkey)
        else:
            ida_kernwin.warning("%s: failed to register action" % cfg.PLUGIN_NAME)

    def _install(self):
        self._register_action(HRDevHelper.config["show_tree"], HRDevHelper.act_show_ctree)
        self._register_action(HRDevHelper.config["show_subtree"], HRDevHelper.act_show_sub_tree)
        self._register_action(HRDevHelper.config["show_context"], HRDevHelper.act_show_context)
        self.ui_hooks = handler.ui_event_handler_t(self._registered_actions, HRDevHelper.config)
        self.ui_hooks.hook()
        return True

    def _uninstall(self):
        if self.installed:
            self.ui_hooks.unhook()
            for desc in self._registered_actions:
                ida_kernwin.unregister_action(desc)

    def init(self):
        self.installed = False
        self._registered_actions = {}
        result = ida_idaapi.PLUGIN_SKIP
        if ida_hexrays.init_hexrays_plugin():
            try:
                HRDevHelper.config = cfg.load_cfg()
            except:
                ida_kernwin.warning(("%s failed parsing %s.\n"
                    "If fixing this config file manually doesn't help, please delete the file and re-run the plugin.\n\n"
                    "The plugin will now terminate." % (
                        cfg.PLUGIN_NAME,
                        cfg.get_cfg_filename())))
            else:
                self.installed = self._install()
                result = ida_idaapi.PLUGIN_KEEP 
        return result

    def run(self, arg):
        if cfg.DEBUG:
            print(HRDevHelper.config)

    def term(self):
        self._uninstall()

# -----------------------------------------------------------------------
def PLUGIN_ENTRY():   
    return HRDevHelper()
