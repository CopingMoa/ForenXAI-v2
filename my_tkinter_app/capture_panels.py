"""
capture_panels.py
=================

Opens XaiTab with the sample capture and saves a PNG of each of the three
panels. Used to show the tab without needing a PCAP and a full pipeline run.

    python capture_panels.py            -> panel_1.png, panel_2.png, panel_3.png
"""

import os
import sys
import tkinter as tk
from tkinter import ttk

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from views.xai_tab import XaiTab                       # noqa: E402

SAMPLE_CSV = os.path.join(HERE, "sample_data", "sample_flows.csv")


def grab(path):
    """Screenshot the whole virtual screen via .NET."""
    import subprocess
    ps = f'''
Add-Type -AssemblyName System.Windows.Forms,System.Drawing
$b = [System.Windows.Forms.SystemInformation]::VirtualScreen
$bmp = New-Object System.Drawing.Bitmap $b.Width, $b.Height
$g = [System.Drawing.Graphics]::FromImage($bmp)
$g.CopyFromScreen($b.Location, [System.Drawing.Point]::Empty, $bmp.Size)
$bmp.Save("{path}", [System.Drawing.Imaging.ImageFormat]::Png)
$g.Dispose(); $bmp.Dispose()
'''
    subprocess.run(["powershell", "-NoProfile", "-Command", ps],
                   capture_output=True)


def main():
    root = tk.Tk()
    root.title("ForenXAI - XAI panels")
    root.geometry("1500x920+20+20")

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)
    tab = XaiTab(notebook, "ForenXAI_Cases")

    case = {
        "case_id": "CASE_20260908_001",
        "pcap_sha256": "a3f1c92e" + "b7d40e15" * 7,
        "pcap_path": "sample_capture.pcap",
        "generated_csv_path": SAMPLE_CSV,
        "total_flows": 1500,
        "benign_flows": 217,
        "threat_flows": 1283,
    }

    steps = iter([
        (0, "panel_1.png"),
        (1, "panel_2.png"),
        (2, "panel_3.png"),
    ])

    def next_step():
        try:
            index, name = next(steps)
        except StopIteration:
            print("done", flush=True)
            root.quit()
            return
        tab.panel_nb.select(index)
        root.update()
        root.after(900, lambda: (grab(os.path.join(HERE, name)),
                                 print("saved", name, flush=True),
                                 root.after(400, next_step)))

    def wait_for_analysis():
        if tab.panels:
            # Select the first finding so panels 2 and 3 have content.
            root.after(600, next_step)
        else:
            root.after(200, wait_for_analysis)

    tab.update_xai_results(case, None)
    root.after(500, wait_for_analysis)
    root.after(120_000, root.quit)
    root.mainloop()


if __name__ == "__main__":
    main()
