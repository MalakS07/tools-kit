# ToolsKit_GO
ToolsKit is a lightweight Windows command‑line utility designed to simplify system maintenance and troubleshooting. It provides a guided, menu‑based interface and automatically elevates to administrator mode when required.

Features
• Adjust Windows Explorer visibility (hidden files, extensions, system files)
• Repair system files using DISM and SFC, with auto‑saved summaries
• Repair boot records with automatic UEFI/BIOS detection
• Run CHKDSK with optional report extraction
• Control crash auto‑restart behavior (BCDEdit/Registry)
• Manage Wi‑Fi networks and profiles
• Clear DNS cache, TEMP files, and Microsoft Store cache

Requirements
• Windows 10 or 11
• Administrator privileges
• Command Prompt or PowerShell

Usage
Run the executable and select an option from the menu. Follow on‑screen prompts. Some operations may require a reboot. Logs and reports are saved in the "logs" folder when applicable.

Notes
Use boot repair functions carefully. CHKDSK /r may take significant time. Running certain operations from the Windows Recovery Environment (WinRE) is recommended.
----------------------------------------------------------
