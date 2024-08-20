import subprocess
import time

import pyautogui
import pygetwindow as gw

scripts = [
    "Pledge/pledge.py",
    "Registrar/registrar.py",
    "MASA/masa.py",
    "Authorities/authority.py",
]
titles = ["Pledge", "Registrar", "MASA", "Authority"]

# Launch each script in a separate command prompt window and set a custom title
for script, title in zip(scripts, titles):
    subprocess.Popen(
        f"cmd /k title {title} && py {script}",
        creationflags=subprocess.CREATE_NEW_CONSOLE,
    )

# Allow some time for the windows to open
time.sleep(5)

windows = []
for title in titles:
    window = gw.getWindowsWithTitle(title)
    if window:
        windows.append(window[0])

# Define screen layout
screen_width, screen_height = pyautogui.size()
window_width = screen_width // 2
window_height = screen_height // 2

positions = [
    (0, 0),  # Top-left
    (window_width, 0),  # Top-right
    (0, window_height),  # Bottom-left
    (window_width, window_height),  # Bottom-right
]

# Align the windows on the screen
for window, pos in zip(windows, positions):
    try:
        window.moveTo(pos[0], pos[1])
        window.resizeTo(window_width, window_height)
    except Exception as e:
        pass
