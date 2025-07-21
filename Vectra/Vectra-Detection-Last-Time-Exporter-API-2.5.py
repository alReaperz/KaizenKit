import os
import ssl
import requests
from datetime import datetime
from pytz import timezone
import tkinter as tk
from tkinter import messagebox
import pandas as pd
import json
import webbrowser
import threading
import urllib.parse
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from core.theme import add_theme_switcher

# Global variable to store the output filename
stored_filename = None

class SystemCertAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.ssl_context = ssl.create_default_context()
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

# Expansion settings
special_expand_keys = ["tags"]
special_static_values = {"tags": {"false positive", "true positive", ""}}
expand_arrays = []

flatten_keys = [
    "id", "state", "threat", "certainty", "detection_category",
    "detection_type", "created_timestamp", "first_timestamp",
    "last_timestamp", "src_ip", "src_host.id", "src_host.ip",
    "src_host.name", "src_account.id", "src_account.name",
    "src_host.is_key_asset", "targets_key_asset", "is_triaged",
    "custom_detection", "triage_rule_id", "filtered_by_ai",
    "filtered_by_user", "filtered_by_rule"
] + special_expand_keys

categories = [
    ("C2", "COMMAND & CONTROL", 1),
    ("Botnet", "BOTNET ACTIVITY", 1),
    ("Recon", "RECONNAISSANCE", 1),
    ("Lateral", "LATERAL MOVEMENT", 1),
    ("Exfil", "EXFILTRATION", 1),
    ("Info", "INFO", 0)
]
category_vars = {}

# JSON flattening

def flatten_json(json_object, keys_to_include):
    flat_data = {}
    for key in keys_to_include:
        parts = key.split('.')
        value = json_object
        try:
            for part in parts:
                value = value.get(part) if isinstance(value, dict) else None
            if key in special_expand_keys and isinstance(value, list):
                static_vals = special_static_values.get(key, set())
                dynamic = [i for i in value if str(i).strip().lower() not in static_vals]
                static = [i for i in value if str(i).strip().lower() in static_vals]
                flat_data[f"sorted_{key}"] = dynamic + static
            elif isinstance(value, list):
                if key in expand_arrays:
                    for i, el in enumerate(value):
                        flat_data[f"{key}_{i+1}"] = el
                else:
                    flat_data[key] = ", ".join(map(str, value))
            else:
                flat_data[key] = value if value not in (None, "") else "N/A"
        except Exception:
            flat_data[key] = "N/A"
    return flat_data

# Query execution
def run_query():
    global stored_filename
    server = vectra_server_entry.get().strip()
    token = api_key_entry.get().strip()
    start = start_time_entry.get().strip()
    end = end_time_entry.get().strip()

    if not server or not token or not start or not end:
        messagebox.showerror("Input Error", "All fields are required!")
        return
    selected = [val for lbl, val, _ in categories if category_vars[lbl].get()]
    if not selected:
        messagebox.showerror("Input Error", "Please select at least one detection category.")
        return

    submit_button.config(state='disabled')
    status_label.config(text="Processing...", bootstyle="info")
    root.update()

    try:
        local_tz = timezone("Asia/Kuala_Lumpur")
        st_dt = datetime.strptime(start, "%Y-%m-%d %H:%M")
        et_dt = datetime.strptime(end, "%Y-%m-%d %H:%M")
        st_utc = local_tz.localize(st_dt).astimezone(timezone("UTC")).strftime("%Y-%m-%dT%H%M")
        et_utc = local_tz.localize(et_dt).astimezone(timezone("UTC")).strftime("%Y-%m-%dT%H%M")
        cat_q = " OR ".join([f'detection.category:"{c}"' for c in selected])
        time_q = f"detection.last_timestamp:[{st_utc} TO {et_utc}]"
        full_q = f"({cat_q}) AND {time_q}"
        encoded = urllib.parse.quote(full_q)
        url = f"https://{server}/api/v2.5/search/detections/?page_size=5000&query_string={encoded}"
        headers = {"Authorization": f"Token {token}"}

        with requests.Session() as sess:
            sess.mount("https://", SystemCertAdapter())
            resp = sess.get(url, headers=headers)
            resp.raise_for_status()

        dl = os.path.join(os.path.expanduser("~"), "Downloads")
        fname = f"detections_{start}_{end}.json".replace(" ", "T").replace(":", "").replace("-", "")
        path = os.path.join(dl, fname)
        cnt = 1
        while os.path.exists(path):
            path = os.path.join(dl, f"{fname.split('.')[0]}_{cnt}.json")
            cnt += 1

        stored_filename = path
        with open(path, 'w') as f:
            f.write(resp.text)

        messagebox.showinfo("Success", f"Data saved to: {path}")
        status_label.config(text=f"File saved: {path}", bootstyle="success")
    except Exception as e:
        messagebox.showerror("Error", str(e))
        status_label.config(text="Failed.", bootstyle="danger")
    finally:
        submit_button.config(state='normal')

# Excel flattening
def flatten_to_excel():
    global stored_filename
    try:
        if not stored_filename:
            messagebox.showerror("Error", "Run query first.")
            return
        with open(stored_filename) as jf:
            data = json.load(jf)
        if 'results' not in data or not isinstance(data['results'], list):
            messagebox.showerror("Error", "No 'results' in JSON.")
            return
        flat = [flatten_json(it, flatten_keys) for it in data['results']]
        # post-process special keys
        for sk in special_expand_keys:
            static = special_static_values.get(sk, set())
            max_dyn = max(len([i for i in rec.get(f"sorted_{sk}", []) if str(i).strip().lower() not in static]) for rec in flat)
            max_st = max(len([i for i in rec.get(f"sorted_{sk}", []) if str(i).strip().lower() in static]) for rec in flat)
            for rec in flat:
                sl = rec.get(f"sorted_{sk}", [])
                dyn = [i for i in sl if str(i).strip().lower() not in static]
                stc = [i for i in sl if str(i).strip().lower() in static]
                for i in range(max_dyn): rec[f"{sk}_{i+1}"] = dyn[i] if i < len(dyn) else ''
                for j in range(max_st): rec[f"{sk}_{max_dyn+j+1}"] = stc[j] if j < len(stc) else ''
                rec.pop(f"sorted_{sk}", None)
        df = pd.DataFrame(flat).fillna("N/A")
        xlsx = stored_filename.replace('.json', '.xlsx')
        df.to_excel(xlsx, index=False)
        messagebox.showinfo("Success", f"Excel saved: {xlsx}")
        status_label.config(text=f"Excel saved: {xlsx}", bootstyle="success")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# Thread wrappers
def threaded_query(): threading.Thread(target=run_query).start()
def threaded_flatten(): threading.Thread(target=flatten_to_excel).start()

def open_url(evt=None):
    webbrowser.open("https://github.com/alReaperz/KaizenKit/blob/main/Vectra/Vectra-Detection-First-Time-Exporter-API-2.5.py")

# GUI Setup
def main():
    global root, vectra_server_entry, api_key_entry, \
           start_time_entry, end_time_entry, submit_button, status_label

    root = ttk.Window(themename="darkly")
    root.title("Vectra Detection First Time Exporter API 2.5 by alReaperz")
    style = ttk.Style("darkly")
    add_theme_switcher(root, style)

    frame = ttk.Frame(root, padding=10)
    frame.pack(fill='both', expand=True)

    labels = ["Vectra Brain FQDN:", "API Token:",
              "Start Time (YYYY-MM-DD HH:MM):", "End Time (YYYY-MM-DD HH:MM):"]
    entries = []
    for i, text in enumerate(labels):
        ttk.Label(frame, text=text).grid(row=i, column=0, sticky='w', pady=5)
        ent = ttk.Entry(frame, width=50)
        ent.grid(row=i, column=1, sticky='ew', pady=5)
        entries.append(ent)
    vectra_server_entry, api_key_entry, start_time_entry, end_time_entry = entries

    # Categories
    cat_frame = ttk.Frame(frame)
    cat_frame.grid(row=4, column=0, columnspan=2, pady=5, sticky='w')
    ttk.Label(cat_frame, text="Select Detection Categories:").grid(row=0, column=0, columnspan=len(categories), sticky='w')
    for idx, (lbl, _, dflt) in enumerate(categories):
        var = tk.IntVar(value=dflt)
        category_vars[lbl] = var
        cb = ttk.Checkbutton(cat_frame, text=lbl, variable=var)
        cb.grid(row=1, column=idx, padx=5)

    submit_button = ttk.Button(frame, text="Run Query", bootstyle="primary", command=threaded_query)
    submit_button.grid(row=5, column=0, columnspan=2, pady=(10,5), sticky='ew')

    flatten_btn = ttk.Button(frame, text="Flatten to Excel", bootstyle="secondary", command=threaded_flatten)
    flatten_btn.grid(row=6, column=0, columnspan=2, pady=5, sticky='ew')

    status_label = ttk.Label(frame, text="Waiting for input...", bootstyle="light")
    status_label.grid(row=7, column=0, columnspan=2, pady=10, sticky='w')

    frame.columnconfigure(1, weight=1)

    info = tk.Label(
    root,
    text="?", 
    fg="blue", 
    cursor="hand2", 
    font=("Arial", 12, "bold")
    )
    info.place(relx=1.0, rely=1.0, anchor='se', x=-10, y=-10)
    info.bind("<Button-1>", open_url)

    root.mainloop()

if __name__ == '__main__':
    main()
