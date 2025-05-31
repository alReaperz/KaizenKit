"""
Vectra Detection Tags Exporter API 2.5 v1 by alReaperz

Summary:
- GUI tool to query the Vectra Detection API for specific detection IDs loaded from a CSV file.
- Imports detection IDs (CSV header: 'detection_id', case-insensitive) via file-browse dialog (handles BOM).
- Accepts user inputs: Vectra Brain FQDN and API token.
- Validates that the given Vectra FQDN can be resolved via DNS; errors out early if not.
- Batches IDs in groups of 10, builds an OR-based query per batch, retrieves data from “/api/v2.5/search/detections/”,
  and combines all results into one list.
- Runs both the query and the “flatten JSON→Excel” steps on background threads so the GUI never freezes.
- Saves full JSON output (named “detection_tags_<timestamp>.json”) into the user's Downloads folder, ensuring no
  filename collision.
- Clears the API token field after successfully saving JSON to avoid leaving credentials on screen.
- Optional “-verbose” (or “-v”/“--verbose”) CLI flag: when present, prints tracebacks and console logs to stdout
  for easier debugging.
- Flattening: extracts each detection's 'id' plus its 'tags', then sorts tags into “dynamic” vs. “static” sets
  (`{'false positive','true positive',''}`). It creates N columns for all dynamic tags (first) followed by M columns
  for all static tags (second), padding with empty strings when fewer tags exist. If the target .xlsx is open,
  shows a friendly “file in use” error instead of crashing.
- Includes an info-label (“?”) that links to the GitHub repository for this tool.

Requirements (Python 3.x):
  os, ssl, requests, datetime, tkinter (messagebox & filedialog), pandas, json, webbrowser, threading, csv,
  urllib.parse, sys, traceback, socket
"""

import os
import ssl
import requests
from datetime import datetime
import ttkbootstrap as ttk
from ttkbootstrap.constants import *
from tkinter import messagebox, filedialog, END
import pandas as pd
import json
import webbrowser
import threading
import csv
import urllib.parse
import sys
import traceback
import socket

# ------------------------- Theme‐Switcher Helper ------------------------- #

def add_theme_switcher(parent, style):
    """
    Add Darkly/Lumen theme switcher buttons to the parent widget.
    Accepts a ttk.Style instance.
    """
    frame = ttk.Frame(parent)
    frame.pack(fill="x", padx=10, pady=5, anchor="e")

    darkly = ttk.Label(frame, text="Darkly", cursor="hand2", bootstyle="primary")
    darkly.pack(side="right", padx=5)
    darkly.bind("<Button-1>", lambda e: style.theme_use("darkly"))

    lumen = ttk.Label(frame, text="Lumen", cursor="hand2", bootstyle="primary")
    lumen.pack(side="right", padx=5)
    lumen.bind("<Button-1>", lambda e: style.theme_use("lumen"))


# ------------------------- Global Settings ------------------------- #

# Parse verbose flag from command-line
VERBOSE = any(arg in ('-verbose','--verbose','-v') for arg in sys.argv[1:])
if VERBOSE:
    print("Verbose mode enabled")

detection_ids = []         # List of IDs imported from CSV
stored_filename = None     # Path to saved JSON
BATCH_SIZE = 10            # Number of IDs per API call batch

# Keys to flatten
special_expand_keys = ['tags']
special_static_values = { 'tags': {'false positive', 'true positive', ''} }
flatten_keys = ['id'] + special_expand_keys


# ------------------------- Custom HTTPS Adapter ------------------------- #

class SystemCertAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.ssl_context = ssl.create_default_context()
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)


# ------------------------- Flatten JSON Helper ------------------------- #

def flatten_json(json_obj, keys_to_include):
    flat = {}
    for key in keys_to_include:
        parts = key.split('.')
        val = json_obj
        try:
            for part in parts:
                val = val.get(part, None) if isinstance(val, dict) else None

            if key in special_expand_keys:
                if isinstance(val, list):
                    static = special_static_values.get(key, set())
                    dyn, st = [], []
                    for item in val:
                        norm = str(item).strip().lower()
                        (st if norm in static else dyn).append(item)
                    flat[f'sorted_{key}'] = dyn + st
                else:
                    flat[f'sorted_{key}'] = []
            elif isinstance(val, list):
                flat[key] = ', '.join(map(str, val))
            else:
                flat[key] = val if val not in (None, '') else 'N/A'

        except Exception as e:
            flat[key] = 'N/A'
            if VERBOSE:
                print(f"Error flattening key '{key}': {e}")
                traceback.print_exc()

    return flat


# ------------------------- CSV Loading ------------------------- #

def load_csv():
    global detection_ids
    path = filedialog.askopenfilename(
        filetypes=[('CSV files','*.csv'), ('All files','*.*')]
    )
    if not path:
        return

    try:
        # Handle BOM and encoding
        with open(path, newline='', encoding='utf-8-sig') as f:
            reader = csv.DictReader(f)
            headers_lc = [h.strip().lower() for h in (reader.fieldnames or [])]
            if 'detection_id' not in headers_lc:
                raise ValueError("CSV must have 'detection_id' header (case-insensitive). Found: %s" % reader.fieldnames)

            # Get actual header name for values
            col = reader.fieldnames[headers_lc.index('detection_id')]
            detection_ids = [
                row[col].strip()
                for row in reader
                if row.get(col) and row[col].strip()
            ]

            if not detection_ids:
                messagebox.showwarning(
                    "Warning",
                    "CSV was loaded but contained no non-empty detection_id values."
                )

        csv_label.config(text=os.path.basename(path))
        status_label.config(text=f"Loaded {len(detection_ids)} IDs", foreground="green")

        if VERBOSE:
            print(f"Loaded IDs from {path}: {detection_ids}")

    except Exception as e:
        detection_ids = []
        if VERBOSE:
            print(f"Error loading CSV {path}: {e}")
            traceback.print_exc()
        messagebox.showerror("Error", f"Failed to load CSV:\n{e}")
        status_label.config(text="Failed to load CSV", foreground="red")


# ------------------------- Run Query + Save JSON ------------------------- #

def run_query():
    global stored_filename, detection_ids

    vectra = vectra_server_entry.get().strip()
    token = api_key_entry.get().strip()

    if not vectra or not token:
        messagebox.showerror('Input Error', 'Vectra FQDN and API token are required!')
        return

    # DNS resolution check
    try:
        socket.gethostbyname(vectra)
    except socket.error:
        messagebox.showerror('Input Error',
                             'Cannot resolve Vectra FQDN. Please check the hostname.')
        return

    if not detection_ids:
        messagebox.showerror('Input Error', 'Please load a CSV with detection IDs first.')
        return

    submit_button.config(state=ttk.DISABLED)
    status_label.config(text='Processing request...', foreground="blue")
    root.update_idletasks()

    try:
        all_results = []

        # Batch IDs into groups of BATCH_SIZE
        for idx in range(0, len(detection_ids), BATCH_SIZE):
            batch = detection_ids[idx:idx+BATCH_SIZE]
            batch_num     = idx // BATCH_SIZE + 1
            total_batches = (len(detection_ids) - 1) // BATCH_SIZE + 1
            status_label.config(text=f"Processing batch {batch_num}/{total_batches}...", foreground="blue")
            root.update_idletasks()

            # Build OR‐based query string
            q = ' OR '.join([f'detection.id:\"{id_}\"' for id_ in batch])
            enc = urllib.parse.quote(q)
            url = f"https://{vectra}/api/v2.5/search/detections/?page_size=5000&query_string={enc}"

            if VERBOSE:
                print(f"Query URL: {url}")

            headers = {'Authorization': f'Token {token}'}
            with requests.Session() as s:
                s.mount('https://', SystemCertAdapter())
                resp = s.get(url, headers=headers)
                resp.raise_for_status()
                json_data = resp.json().get('results', [])
                all_results.extend(json_data)

                if VERBOSE:
                    print(f"Batch {batch_num}: Retrieved {len(json_data)} results")

        # Save combined JSON into Downloads
        dl = os.path.join(os.path.expanduser('~'), 'Downloads')
        ts = datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
        fname = f'detection_tags_{ts}.json'
        out = os.path.join(dl, fname)
        cnt = 1
        while os.path.exists(out):
            out = os.path.join(dl, f"{fname.split('.')[0]}_{cnt}.json")
            cnt += 1

        stored_filename = out
        with open(out, 'w') as jf:
            json.dump({'results': all_results}, jf, indent=2)

        # Notify user + clear API token field
        messagebox.showinfo('Success', f'Data saved to: {out}')
        status_label.config(text=f'File saved: {out}', foreground="green")
        api_key_entry.delete(0, END)

        if VERBOSE:
            print(f"Full JSON output path: {out}")

    except requests.exceptions.RequestException as e:
        if VERBOSE:
            print(f"Request error: {e}")
            traceback.print_exc()
        messagebox.showerror('Request Error', f'Error during API request:\n{e}')
        status_label.config(text='Request failed.', foreground="red")

    except Exception as e:
        if VERBOSE:
            print(f"Unexpected error in run_query: {e}")
            traceback.print_exc()
        messagebox.showerror('Error', f'An unexpected error occurred:\n{e}')
        status_label.config(text='An error occurred.', foreground="red")

    finally:
        submit_button.config(state=ttk.NORMAL)


# ------------------------- Flatten JSON → Excel ------------------------- #

def flatten_json_to_excel():
    global stored_filename

    try:
        if not stored_filename:
            messagebox.showerror('Error', 'No data file available. Please run the query first.')
            return

        with open(stored_filename, 'r') as jf:
            data = json.load(jf).get('results', [])

        rows = [flatten_json(item, flatten_keys) for item in data]

        # Process tags into separate dynamic/static columns
        for key in special_expand_keys:
            static = special_static_values.get(key, set())

            max_dyn = max(
                (len([v for v in r.get(f'sorted_{key}', []) if str(v).strip().lower() not in static])
                 for r in rows),
                default=0
            )
            max_st = max(
                (len([v for v in r.get(f'sorted_{key}', []) if str(v).strip().lower() in static])
                 for r in rows),
                default=0
            )

            for r in rows:
                sl = r.pop(f'sorted_{key}', [])
                dyn = [v for v in sl if str(v).strip().lower() not in static]
                st  = [v for v in sl if str(v).strip().lower() in static]

                for i in range(max_dyn):
                    r[f'{key}_{i+1}'] = dyn[i] if i < len(dyn) else ''
                for j in range(max_st):
                    r[f'{key}_{max_dyn+j+1}'] = st[j] if j < len(st) else ''

        df = pd.DataFrame(rows)
        out_xlsx = stored_filename.replace('.json', '.xlsx')

        try:
            df.to_excel(out_xlsx, index=False)
        except PermissionError:
            messagebox.showerror(
                'Permission Error',
                f"The file:\n\n{out_xlsx}\n\nis currently open. Please close it and try again."
            )
            return

        messagebox.showinfo('Success', f'Excel file created: {out_xlsx}')
        status_label.config(text=f'Excel saved: {out_xlsx}', foreground="green")

        if VERBOSE:
            print(f"Excel output path: {out_xlsx}")

    except Exception as e:
        if VERBOSE:
            print(f"Error converting to Excel: {e}")
            traceback.print_exc()
        messagebox.showerror('Error', f'Error converting to Excel:\n{e}')


# ------------------------- Thread Wrappers ------------------------- #

def threaded_run_query():
    threading.Thread(target=run_query).start()

def threaded_flatten():
    threading.Thread(target=flatten_json_to_excel).start()


# ------------------------- Open GitHub URL ------------------------- #

def open_url(event=None):
    webbrowser.open(
        'https://github.com/alReaperz/KaizenKit/blob/main/Vectra/Vectra-Detection-Exporter-API-2.5-v3.py'
    )


# ------------------------- Main GUI ------------------------- #

def main():
    global root, csv_label, status_label, vectra_server_entry, api_key_entry, submit_button

    # Create a ttkbootstrap window with “darkly” theme by default
    root = ttk.Window(themename="darkly")
    root.title('Vectra Detection Tags Exporter API 2.5 v1 by alReaperz')

    # Obtain the Style object so we can switch themes later
    style = ttk.Style()

    # Add the Darkly/Lumen switcher at the top
    add_theme_switcher(root, style)

    # Main content frame
    content = ttk.Frame(root, padding=10)
    content.pack(fill="both", expand=True)

    # Row 0: Load CSV
    load_btn = ttk.Button(
        content,
        text='Load CSV',
        command=load_csv,
        bootstyle=PRIMARY
    )
    load_btn.grid(row=0, column=0, pady=5)

    csv_label = ttk.Label(content, text='No CSV loaded')
    csv_label.grid(row=0, column=1, sticky="w", padx=5)

    # Row 1: Vectra FQDN
    vectra_label = ttk.Label(content, text='Vectra Brain FQDN:')
    vectra_label.grid(row=1, column=0, sticky="w", padx=10, pady=5)

    vectra_server_entry = ttk.Entry(content, width=50)
    vectra_server_entry.grid(row=1, column=1, padx=10, pady=5)

    # Row 2: API Token
    token_label = ttk.Label(content, text='API Token:')
    token_label.grid(row=2, column=0, sticky="w", padx=10, pady=5)

    api_key_entry = ttk.Entry(content, show='*', width=50)
    api_key_entry.grid(row=2, column=1, padx=10, pady=5)

    # Row 3: Run Query Button
    submit_button = ttk.Button(
        content,
        text='Run Query',
        command=threaded_run_query,
        bootstyle=SUCCESS
    )
    submit_button.grid(row=3, column=0, columnspan=2, pady=10)

    # Row 4: Flatten → Excel Button
    flatten_button = ttk.Button(
        content,
        text='Flatten to Excel',
        command=threaded_flatten,
        bootstyle=INFO
    )
    flatten_button.grid(row=4, column=0, columnspan=2, pady=10)

    # Row 5: Status Label
    status_label = ttk.Label(content, text='Waiting for input...', foreground="black")
    status_label.grid(row=5, column=0, columnspan=2, pady=10)

    # Info label (bottom-right corner) for GitHub link
    info = ttk.Label(root, text='?', cursor="hand2", foreground="blue", font=('Arial', 12, 'bold'))
    info.place(relx=1.0, rely=1.0, anchor='se', x=-10, y=-10)
    info.bind('<Button-1>', open_url)

    root.mainloop()


if __name__ == "__main__":
    main()
