import configparser
import os
import ida_diskio
import ida_kernwin
import ida_lines

PLUGIN_NAME = "HRDevHelper"
DEBUG = False

CFG_FILENAME = "%s.cfg" % PLUGIN_NAME
CFG_DEFAULT_HOTKEY_SHOW_TREE = "Ctrl-."
CFG_DEFAULT_HOTKEY_SHOW_SUBTREE = "Ctrl-Shift-."
CFG_DEFAULT_HOTKEY_SHOW_CONTEXT = "C"

# -----------------------------------------------------------------------
def get_cfg_filename():
    """returns full path for config file."""
    return os.path.join(
        ida_diskio.get_user_idadir(),
        "cfg",
        "%s" % CFG_FILENAME)

# -----------------------------------------------------------------------
def get_default_cfg():
    config = configparser.ConfigParser()
    config["options"] = {
        "center":"True",
        "zoom":"1.0",
        "dockpos":"DP_RIGHT"
    }
    config["hotkeys"] = {
        "show_tree":CFG_DEFAULT_HOTKEY_SHOW_TREE,
        "show_subtree":CFG_DEFAULT_HOTKEY_SHOW_SUBTREE,
        "show_context":CFG_DEFAULT_HOTKEY_SHOW_CONTEXT
    }
    config["frame_palette"] = {
        "default":"073763",
        "focus":"cc0000",
        "highlight":"f1c232"
    }
    config["node_palette"] = {
        "loop":"b6d7a8",
        "call":"b4a7d6",
        "cit":"9fc5e8",
        "cot":"eeeeee",
        ";loop":"663333",
        ";call":"202050",
        ";cit":"000000",
        ";cot":"222222"
    }
    config["text_palette"] = {
        "default":"SCOLOR_DEFAULT",
        "highlight":"SCOLOR_EXTRA"
    }
    return config

# ----------------------------------------------------------------------------
def create_cfg_file():
    result = True
    config = get_default_cfg()
    config_path = get_cfg_filename()
    try:
        os.makedirs(os.path.dirname(config_path), exist_ok=True)
        with open(config_path, "w") as cfg_file:
            config.write(cfg_file)
    except:
        result = False
    return result

# -----------------------------------------------------------------------
def process_cfg(cfg):
    config = {}

    def swapcol(x):
        return (((x & 0x000000FF) << 16) |
                    (x & 0x0000FF00) |
                ((x & 0x00FF0000) >> 16))

    # read all sections
    try:
        for section in cfg.sections():
            config[section] = {}

            if section in ["node_palette", "frame_palette"]:
                for name, value in cfg.items(section):
                    config[section][name] = swapcol(int(value, 0x10))
            elif section == "text_palette":
                for name, value in cfg.items(section):
                    config[section][name] = getattr(globals()["ida_lines"], value)
            elif section == "options":
                for name, value in cfg.items(section):
                    if name in ["center"]:
                        config[section][name] = cfg[section].getboolean(name)
                    elif name in ["zoom"]:
                        config[section][name] = float(value)
                    elif name in ["dockpos"]:
                        config[section][name] = getattr(globals()["ida_kernwin"], value)
            elif section == "hotkeys":
                config["show_tree"] = cfg.get("hotkeys", "show_tree", fallback=CFG_DEFAULT_HOTKEY_SHOW_TREE)
                config["show_subtree"] = cfg.get("hotkeys", "show_subtree", fallback=CFG_DEFAULT_HOTKEY_SHOW_SUBTREE)
                config["show_context"] = cfg.get("hotkeys", "show_context", fallback=CFG_DEFAULT_HOTKEY_SHOW_CONTEXT)
    except Exception as e:
        print(e)
        raise RuntimeError
    return config

# -----------------------------------------------------------------------
def load_cfg(reload=False):
    """loads HRDevHelper configuration."""
    
    config = get_default_cfg()
    cfg_file = get_cfg_filename()
    ida_kernwin.msg("%s: %sloading %s...\n" % (PLUGIN_NAME,
        "re" if reload else "",
        cfg_file))
    if not os.path.isfile(cfg_file):
        ida_kernwin.msg("%s: default configuration (%s) does not exist!\n" % (PLUGIN_NAME, cfg_file))
        ida_kernwin.msg("%s: creating default configuration\n" % PLUGIN_NAME)
        if not create_cfg_file():
            ida_kernwin.msg("%s: Failed to create default configuration file!\n" % PLUGIN_NAME)
            return process_cfg(config)
        return load_cfg(reload=True)

    config.read(cfg_file)
    return process_cfg(config)
