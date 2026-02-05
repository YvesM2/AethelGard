"""
AethelGard Knowledge Base (V14.5 Complete)
Authoritative Process & Behavior Knowledge Base
"""

# ============================================================
# 1. KNOWN GOOD (SYSTEM CRITICALS) — STATIC WHITELIST
# Tier-1 Drop Logic:
# If (Name + Path + Parent) match → DROP immediately
# ============================================================

PROCESS_SCHEMA = {

    # --- Core Boot / Kernel Chain ---
    "system": {"paths": [], "parents": []},
    "registry": {"paths": [], "parents": ["system"]},
    "memory_compression": {"paths": [], "parents": ["system"]},
    "memcompression": {"paths": [], "parents": ["system"]}, # Volatility Alias
    "smss.exe": {"paths": [r"c:\windows\system32\smss.exe"], "parents": ["system"]},
    "csrss.exe": {"paths": [r"c:\windows\system32\csrss.exe"], "parents": ["smss.exe"]},
    "wininit.exe": {"paths": [r"c:\windows\system32\wininit.exe"], "parents": ["smss.exe"]},
    "services.exe": {"paths": [r"c:\windows\system32\services.exe"], "parents": ["wininit.exe"]},
    "lsass.exe": {"paths": [r"c:\windows\system32\lsass.exe"], "parents": ["wininit.exe"]},
    "lsm.exe": {"paths": [r"c:\windows\system32\lsm.exe"], "parents": ["wininit.exe"]},
    "winlogon.exe": {"paths": [r"c:\windows\system32\winlogon.exe"], "parents": ["smss.exe"]},
    
    # --- Service Hosts ---
    "svchost.exe": {
        "paths": [r"c:\windows\system32\svchost.exe", r"c:\windows\syswow64\svchost.exe"],
        "parents": ["services.exe", "mpcmdrun.exe", "msmpeng.exe"]
    },
    "dllhost.exe": {
        "paths": [r"c:\windows\system32\dllhost.exe", r"c:\windows\syswow64\dllhost.exe"],
        "parents": ["svchost.exe", "services.exe", "explorer.exe"]
    },
    "fontdrvhost.exe": {
        "paths": [r"c:\windows\system32\fontdrvhost.exe"],
        "parents": ["winlogon.exe", "umfd-0", "umfd-1"]
    },
    "fontdrvhost.ex": { # Truncation Alias
        "paths": [r"c:\windows\system32\fontdrvhost.exe"],
        "parents": ["winlogon.exe"]
    },
    "wudfhost.exe": {
        "paths": [r"c:\windows\system32\wudfhost.exe"],
        "parents": ["services.exe"]
    },

    # --- Desktop / Session ---
    "explorer.exe": {"paths": [r"c:\windows\explorer.exe"], "parents": ["userinit.exe", "winlogon.exe"]},
    "dwm.exe": {"paths": [r"c:\windows\system32\dwm.exe"], "parents": ["winlogon.exe", "svchost.exe"]},
    "ctfmon.exe": {"paths": [r"c:\windows\system32\ctfmon.exe"], "parents": ["taskhostw.exe", "svchost.exe"]},
    "taskhost.exe": {"paths": [r"c:\windows\system32\taskhost.exe"], "parents": ["services.exe", "svchost.exe"]},
    "taskhostw.exe": {"paths": [r"c:\windows\system32\taskhostw.exe"], "parents": ["services.exe", "svchost.exe"]},
    "sihost.exe": {"paths": [r"c:\windows\system32\sihost.exe"], "parents": ["svchost.exe"]},
    "applicationframehost.exe": {"paths": [r"c:\windows\system32\applicationframehost.exe"], "parents": ["svchost.exe"]},
    "userinit.exe": {"paths": [r"c:\windows\system32\userinit.exe"], "parents": ["winlogon.exe", "dwm.exe"]},

    # --- Modern Windows UI & Runtime ---
    "textinputhost.exe": {
        "paths": [r"c:\windows\system32\textinputhost.exe", r"c:\windows\syswow64\textinputhost.exe"],
        "parents": ["svchost.exe"]
    },
    "searchapp.exe": {
        "paths": [r"c:\windows\systemapps\microsoft.windows.search_cw5n1h2txyewy\searchapp.exe"],
        "parents": ["svchost.exe"]
    },
    "startmenuexperiencehost.exe": {
        "paths": [r"c:\windows\systemapps\microsoft.windows.startmenuexperiencehost_cw5n1h2txyewy\startmenuexperiencehost.exe"],
        "parents": ["svchost.exe"]
    },
    "shellexperiencehost.exe": {
        "paths": [r"c:\windows\systemapps\shellexperiencehost_cw5n1h2txyewy\shellexperiencehost.exe"],
        "parents": ["svchost.exe"]
    },
    "systemsettings.exe": {
        "paths": [r"c:\windows\immersivecontrolpanel\systemsettings.exe"],
        "parents": ["svchost.exe", "explorer.exe"]
    },
    "runtimebroker.exe": {
        "paths": [r"c:\windows\system32\runtimebroker.exe"],
        "parents": ["svchost.exe"]
    },
    "runtimebroker.": { # Truncation Alias
        "paths": [r"c:\windows\system32\runtimebroker.exe"],
        "parents": ["svchost.exe"]
    },
    "backgroundtaskhost.exe": {
        "paths": [r"c:\windows\system32\backgroundtaskhost.exe"],
        "parents": ["svchost.exe", "services.exe"]
    },
    "backgroundtask": { # Truncation Alias
        "paths": [r"c:\windows\system32\backgroundtaskhost.exe"],
        "parents": ["svchost.exe"]
    },
    "smartscreen.exe": {
        "paths": [r"c:\windows\system32\smartscreen.exe"],
        "parents": ["svchost.exe"]
    },

    # --- Windows Defender & Security ---
    "msmpeng.exe": {
        "paths": [r"c:\program files\windows defender\msmpeng.exe", r"c:\programdata\microsoft\windows defender\platform\*\msmpeng.exe"],
        "parents": ["services.exe"]
    },
    "nissrv.exe": {
        "paths": [r"c:\program files\windows defender\nissrv.exe"],
        "parents": ["services.exe"]
    },
    "securityhealthservice.exe": {
        "paths": [r"c:\windows\system32\securityhealthservice.exe"],
        "parents": ["services.exe"]
    },
    "sechealthui.exe": {
        "paths": [r"c:\windows\system32\sechealthui.exe"],
        "parents": ["svchost.exe", "explorer.exe"]
    },
    "sgrmbroker.exe": {
        "paths": [r"c:\windows\system32\sgrmbroker.exe"],
        "parents": ["services.exe"]
    },
    "aggregatorhost.exe": {
        "paths": [r"c:\windows\system32\aggregatorhost.exe"],
        "parents": ["svchost.exe"]
    },
    "mpdefendercore.exe": {
         "paths": [r"c:\program files\windows defender\mpdefendercore.exe", r"c:\programdata\microsoft\windows defender\platform\*\mpdefendercore.exe"],
         "parents": ["services.exe"]
    },

    # --- Core Windows Services ---
    "spoolsv.exe": {"paths": [r"c:\windows\system32\spoolsv.exe"], "parents": ["services.exe"]},
    "sppsvc.exe": {"paths": [r"c:\windows\system32\sppsvc.exe"], "parents": ["services.exe"]},
    "searchindexer.exe": {"paths": [r"c:\windows\system32\searchindexer.exe"], "parents": ["services.exe"]},
    "audiodg.exe": {"paths": [r"c:\windows\system32\audiodg.exe"], "parents": ["svchost.exe"]},
    "wmiprvse.exe": {"paths": [r"c:\windows\system32\wbem\wmiprvse.exe"], "parents": ["svchost.exe", "services.exe"]},
    "msdtc.exe": {"paths": [r"c:\windows\system32\msdtc.exe"], "parents": ["services.exe"]},
    "dashost.exe": {"paths": [r"c:\windows\system32\dashost.exe"], "parents": ["svchost.exe", "services.exe"]},
    "consent.exe": {"paths": [r"c:\windows\system32\consent.exe"], "parents": ["svchost.exe", "spoolsv.exe"]},
    
    # --- BROWSERS & APPS (Common Userland) ---
    "msedge.exe": {
        "paths": [r"c:\program files (x86)\microsoft\edge\application\msedge.exe", r"c:\program files\microsoft\edge\application\msedge.exe"],
        "parents": ["explorer.exe", "svchost.exe", "msedge.exe"]
    },
    "chrome.exe": {
        "paths": [r"c:\program files\google\chrome\application\chrome.exe", r"c:\program files (x86)\google\chrome\application\chrome.exe"],
        "parents": ["explorer.exe", "chrome.exe"]
    },
    "firefox.exe": {
        "paths": [r"c:\program files\mozilla firefox\firefox.exe"],
        "parents": ["explorer.exe", "firefox.exe"]
    },
    "brave.exe": {
        "paths": [r"c:\program files\bravesoftware\brave-browser\application\brave.exe"],
        "parents": ["explorer.exe", "brave.exe"]
    },
    "opera.exe": {
        "paths": [r"c:\users\*\appdata\local\programs\opera\opera.exe", r"c:\program files\opera\launcher.exe"],
        "parents": ["explorer.exe", "opera.exe"]
    },
    "onedrive.exe": {
        "paths": [r"c:\users\*\appdata\local\microsoft\onedrive\onedrive.exe", r"c:\program files\microsoft onedrive\onedrive.exe"],
        "parents": ["explorer.exe"]
    },
    "discord.exe": {
        "paths": [r"c:\users\*\appdata\local\discord\app-*\discord.exe"],
        "parents": ["explorer.exe", "discord.exe"]
    },
    "teams.exe": {
        "paths": [r"c:\users\*\appdata\local\microsoft\teams\current\teams.exe", r"c:\program files\microsoft\teams\current\teams.exe"],
        "parents": ["explorer.exe", "teams.exe"]
    },
    "slack.exe": {
         "paths": [r"c:\users\*\appdata\local\slack\app-*\slack.exe"],
         "parents": ["explorer.exe", "slack.exe"]
    },

    # --- UPDATERS & COMMON APPS (V14.5 Additions) ---
    "googleupdate.exe": {
        "paths": [r"c:\program files (x86)\google\update\googleupdate.exe", r"c:\program files\google\update\googleupdate.exe", r"c:\users\*\appdata\local\google\update\googleupdate.exe"],
        "parents": ["explorer.exe", "services.exe", "taskeng.exe"]
    },
    "googleupdate.e": { # Truncation Alias
        "paths": [r"c:\program files (x86)\google\update\googleupdate.exe"],
        "parents": ["services.exe"]
    },
    "microsoftedgeupdate.exe": {
        "paths": [r"c:\program files (x86)\microsoft\edgeupdate\microsoftedgeupdate.exe"],
        "parents": ["services.exe"]
    },
    "microsoftedgeu": { # Truncation Alias
        "paths": [r"c:\program files (x86)\microsoft\edgeupdate\microsoftedgeupdate.exe"],
        "parents": ["services.exe"]
    },
    "skypeapp.exe": {
        "paths": [r"c:\program files\windowsapps\microsoft.skypeapp*\skypeapp.exe"],
        "parents": ["svchost.exe", "runtimebroker.exe"]
    },
    "skypebackgroun": { # Truncation Alias
        "paths": [r"c:\program files\windowsapps\microsoft.skypeapp*\skypebackgroundhost.exe"],
        "parents": ["svchost.exe"]
    },
    "microsoft.phot": { # Truncation Alias
        "paths": [r"c:\program files\windowsapps\microsoft.windows.photos*\microsoft.photos.exe"],
        "parents": ["svchost.exe"]
    },
    "calculator.exe": {
        "paths": [r"c:\program files\windowsapps\microsoft.windowscalculator*\calculator.exe"],
        "parents": ["svchost.exe", "runtimebroker.exe"]
    },
    "winstore.app.exe": {
        "paths": [r"c:\program files\windowsapps\microsoft.windowsstore*\winstore.app.exe"],
        "parents": ["svchost.exe", "runtimebroker.exe"]
    },

    # --- Virtualization ---
    "vmtoolsd.exe": {"paths": [r"c:\program files\vmware\vmware tools\vmtoolsd.exe"], "parents": ["services.exe", "explorer.exe"]},
    "vboxservice.exe": {"paths": [r"c:\windows\system32\vboxservice.exe", r"c:\program files\oracle\virtualbox\vboxservice.exe"], "parents": ["services.exe"]},
    "vboxservice.ex": {"paths": [r"c:\windows\system32\vboxservice.exe"], "parents": ["services.exe"]},
    "vm3dservice.exe": {"paths": [r"c:\windows\system32\vm3dservice.exe"], "parents": ["winlogon.exe"]},
    "vm3dservice.ex": {"paths": [r"c:\windows\system32\vm3dservice.exe"], "parents": ["winlogon.exe"]},
    "vgauthservice.exe": {"paths": [r"c:\program files\vmware\vmware tools\vmware vgauth\vgauthservice.exe"], "parents": ["services.exe"]}
}

# ============================================================
# 2. HIGH ACTIVITY PROFILE — EXPECTED NOISE
# ============================================================

HIGH_ACTIVITY_APPS = {
    # Browsers
    "chrome.exe", "firefox.exe", "msedge.exe", "microsoftedgecp.exe", "brave.exe", "opera.exe",

    # Electron / Dev / Chat
    "discord.exe", "teams.exe", "slack.exe", "spotify.exe", "code.exe",
    "skypeapp.exe", "skypebackgroun",

    # Gaming / Store
    "steam.exe", "epicgameslauncher.exe", "winstore.app.exe",

    # Cloud Sync
    "onedrive.exe", "dropbox.exe", "googledrivesync.exe", "filecoauth.exe",

    # Windows Noise
    "runtimebroker.exe", "backgroundtaskhost.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "smartscreen.exe", "wmpnetwk.exe", "wmiprvse.exe", "sppsvc.exe", "audiodg.exe",
    "fontdrvhost.exe", "dashost.exe", "dllhost.exe", "registry", "memory_compression",
    "sgrmbroker.exe", "nissrv.exe", "securityhealthservice.exe", "applicationframehost.exe",
    "browser_broker.exe", "searchapp.exe", "textinputhost.exe", "startmenuexperiencehost.exe",
    "shellexperiencehost.exe", "systemsettings.exe", "msmpeng.exe", "sechealthui.exe", "wudfhost.exe",
    "aggregatorhost.exe", "mpdefendercore.exe", "consent.exe", "procexp64.exe", "ftk imager.exe",
    "microsoft.photos.exe", "calculator.exe",

    # Truncation Aliases (Volatility 15-char Limit)
    "runtimebroker.", "runtimebroker",
    "fontdrvhost.ex", "fontdrvhost.e",
    "shellexperienc", 
    "microsoftedgec", "microsoftedges", "microsoftedge.", "microsoftedgeu",
    "startmenuexper", 
    "sechealthui.ex",
    "vm3dservice.ex", "vboxservice.ex", "vgauthservice.",
    "msedgewebview2", "msedgewebview.",
    "phoneexperienc", "memcompression", "backgroundtask",
    "skypebackgroun", "microsoft.phot", "googleupdate.e"
}

# 3. SAFE APPS Alias
SAFE_APPS = HIGH_ACTIVITY_APPS

# 4. PROFILE VIOLATIONS
PROFILE_VIOLATIONS = {
    "spawns_shell": {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "bash.exe"},
    "loads_suspicious_dll": {"wow64.dll", "mscoree.dll", "clr.dll"},
    "connects_to_port": {4444, 1337, 6667, 3389, 5900, 9001}
}

# 5. YARA SIGNATURES
YARA_SIGNATURES = {
    "mimikatz": "Hacktool.Mimikatz",
    "meterpreter": "Metasploit.Meterpreter",
    "beacon": "CobaltStrike.Beacon",
    "lunarms": "Generic.Malware.Agent",
    "xmrig": "Coinminer.XMRig",
    "sharp": "Hacktool.SharpHound",
    "trickbot": "Trojan.Trickbot",
    "emotet": "Trojan.Emotet"
}

# 6. HIGH VALUE TARGETS
HIGH_VALUE_TARGETS = {
    "powershell.exe", "pwsh.exe", 
    "wscript.exe", "cscript.exe", 
    "mshta.exe", "rundll32.exe", 
    "regsvr32.exe", "bitsadmin.exe", 
    "certutil.exe", "hh.exe", "bginfo.exe"
}
