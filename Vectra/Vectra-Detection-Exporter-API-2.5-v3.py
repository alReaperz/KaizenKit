import os
import ssl
import requests
from datetime import datetime
from pytz import timezone
import tkinter as tk
from tkinter import messagebox
import pandas as pd
import json
import webbrowser  # Used to open the URL
import threading
import urllib.parse

# Global variable to store the output filename
stored_filename = None

# Custom HTTPS Adapter to use the system's root CA certificates
class SystemCertAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args, **kwargs):
        self.ssl_context = ssl.create_default_context()
        super().__init__(*args, **kwargs)
    def init_poolmanager(self, *args, **kwargs):
        kwargs["ssl_context"] = self.ssl_context
        return super().init_poolmanager(*args, **kwargs)

# ---------------------------------------------------------------------------
# Variables for controlling expansion behavior:
#
# List of keys that will be handled with special logic (dynamic/static sorting)
# special_expand_keys = ["tags", "comments"]
special_expand_keys = ["tags"]

# For each key in special_expand_keys, define a set of values (normalized to lowercase)
# that should be treated as "static" and always appear at the end.
special_static_values = {
    "tags": {"false positive", "true positive", ""}
    # "comments": {"escalated", ""}  # Add other static values for "comments" as needed.
}

# Keys in this list will be simply expanded (without special sorting)
expand_arrays = []  # (You can add other keys here if needed.)
# ---------------------------------------------------------------------------

# Define keys to flatten (for all keys in the JSON that we want)
flatten_keys = [
    "id", "state", "threat", "certainty", "detection_category", "detection_type",
    "created_timestamp", "first_timestamp", "last_timestamp", "src_ip", "src_host.id",
    "src_host.ip", "src_host.name", "src_account.id", "src_account.name", "src_host.is_key_asset",
    "targets_key_asset", "is_triaged", "custom_detection", "triage_rule_id", "filtered_by_ai",
    "filtered_by_user", "filtered_by_rule"
] + special_expand_keys  # Add our special keys to the list

# Function to flatten JSON data
def flatten_json(json_object, keys_to_include):
    flat_data = {}
    for key in keys_to_include:
        # Process nested keys (dot notation)
        parts = key.split(".")
        value = json_object
        try:
            for part in parts:
                value = value[part] if isinstance(value, dict) else None
            # Special handling for keys in special_expand_keys
            if key in special_expand_keys:
                if isinstance(value, list):
                    # Get the static set for this key (default to empty set if not defined)
                    static_values = special_static_values.get(key, set())
                    dynamic_items = []
                    static_items = []
                    for item in value:
                        # Normalize item (as a string) for comparison
                        norm = str(item).strip().lower()
                        if norm in static_values:
                            static_items.append(item)
                        else:
                            dynamic_items.append(item)
                    # Save the combined sorted list (dynamic first, then static)
                    flat_data[f"sorted_{key}"] = dynamic_items + static_items
                else:
                    flat_data[f"sorted_{key}"] = []
            # For keys that are in the regular expand_arrays list
            elif isinstance(value, list):
                if key in expand_arrays:
                    for i, element in enumerate(value):
                        flat_data[f"{key}_{i+1}"] = element
                else:
                    flat_data[key] = ", ".join(map(str, value))
            else:
                flat_data[key] = value if value not in (None, "") else "N/A"
        except (KeyError, TypeError):
            flat_data[key] = "N/A"
    return flat_data

# --------------------- Detection Category Checkboxes -----------------------
# List of tuples: (Label on GUI, API value, default state)
categories = [
    ("C2", "COMMAND & CONTROL", 1),
    ("Botnet", "BOTNET ACTIVITY", 1),
    ("Recon", "RECONNAISSANCE", 1),
    ("Lateral", "LATERAL MOVEMENT", 1),
    ("Exfil", "EXFILTRATION", 1),
    ("Info", "INFO", 0)
]
category_vars = {}  # To hold tk.IntVar for each category

# ---------------------------------------------------------------------------

# Run query and process data
def run_query():
    global stored_filename  # Use the global stored_filename variable

    # Get user inputs from the GUI
    vectra_server = vectra_server_entry.get().strip()
    api_key = api_key_entry.get().strip()
    start_time = start_time_entry.get().strip()
    end_time = end_time_entry.get().strip()

    # Validate required text inputs
    if not vectra_server or not api_key or not start_time or not end_time:
        messagebox.showerror("Input Error", "All fields are required!")
        return

    # Validate that at least one detection category checkbox is selected
    selected_categories = [val for lbl, val, _ in categories if category_vars[lbl].get() == 1]
    if not selected_categories:
        messagebox.showerror("Input Error", "Please select at least one detection category.")
        return

    # Disable the button and update status
    submit_button.config(state=tk.DISABLED)
    status_label.config(text="Processing request... Please wait.", fg="blue")
    root.update()

    try:
        # Convert local (GMT+8) time to UTC
        local_tz = timezone("Asia/Kuala_Lumpur")
        start_time_dt = datetime.strptime(start_time, "%Y-%m-%d %H:%M")
        end_time_dt = datetime.strptime(end_time, "%Y-%m-%d %H:%M")
        start_time_utc = local_tz.localize(start_time_dt).astimezone(timezone("UTC")).strftime("%Y-%m-%dT%H%M")
        end_time_utc = local_tz.localize(end_time_dt).astimezone(timezone("UTC")).strftime("%Y-%m-%dT%H%M")

        # Build the detection.category part of the query
        category_query = " OR ".join([f'detection.category:"{cat}"' for cat in selected_categories])
        # Build the time part of the query using detection.first_timestamp
        time_query = f"detection.first_timestamp:[{start_time_utc} TO {end_time_utc}]"
        # Combine queries: note the categories are wrapped in parentheses
        full_query = f"({category_query}) AND {time_query}"

        # URL-encode the query string
        encoded_query = urllib.parse.quote(full_query)

        # Build the URL and headers
        url = f"https://{vectra_server}/api/v2.5/search/detections/?page_size=5000&query_string={encoded_query}"
        headers = {"Authorization": f"Token {api_key}"}

        # Make the API call
        with requests.Session() as session:
            session.mount("https://", SystemCertAdapter())
            response = session.get(url, headers=headers)
            response.raise_for_status()  # Raise error for HTTP codes >= 400

        # Save JSON output to the Downloads folder with a unique filename
        downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        file_name = f"detections_{start_time}_{end_time}.json".replace(" ", "T").replace(":", "").replace("-", "")
        counter = 1
        output_path = os.path.join(downloads_folder, file_name)
        while os.path.exists(output_path):
            output_path = os.path.join(downloads_folder, f"{file_name.split('.')[0]}_{counter}.json")
            counter += 1

        stored_filename = output_path
        with open(output_path, "w") as output_file:
            output_file.write(response.text)

        messagebox.showinfo("Success", f"Data saved to: {output_path}")
        status_label.config(text=f"File saved: {output_path}", fg="green")

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Request Error", f"Error during API request:\n{e}")
        status_label.config(text="Request failed.", fg="red")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")
        status_label.config(text="An error occurred.", fg="red")
    finally:
        submit_button.config(state=tk.NORMAL)

# Flatten the JSON to Excel with fixed columns for special keys
def flatten_json_to_excel():
    global stored_filename  # Access the global stored_filename variable
    try:
        if stored_filename is None:
            messagebox.showerror("Error", "No data file available. Please run the query first.")
            return

        # Read the stored JSON file
        with open(stored_filename, "r") as json_file:
            data = json.load(json_file)

        # Check that "results" exists and is a list
        if "results" not in data or not isinstance(data["results"], list):
            messagebox.showerror("Error", "No 'results' array found in the JSON file.")
            return

        # Flatten each detection record
        flattened_data = [flatten_json(item, flatten_keys) for item in data["results"]]

        # --- Post-process each special key to create fixed columns --- 
        for special_key in special_expand_keys:
            # Get the static set for this key (using the dictionary)
            static_set = special_static_values.get(special_key, set())
            max_dynamic = 0
            max_static = 0
            for record in flattened_data:
                sorted_list = record.get(f"sorted_{special_key}", [])
                # Separate the list into dynamic and static using normalized values
                dynamic_items = [item for item in sorted_list if str(item).strip().lower() not in static_set]
                static_items = [item for item in sorted_list if str(item).strip().lower() in static_set]
                record[f"_{special_key}_dynamic"] = dynamic_items
                record[f"_{special_key}_static"] = static_items
                if len(dynamic_items) > max_dynamic:
                    max_dynamic = len(dynamic_items)
                if len(static_items) > max_static:
                    max_static = len(static_items)
            # Create fixed columns for this special key
            for record in flattened_data:
                dynamic_items = record.get(f"_{special_key}_dynamic", [])
                static_items = record.get(f"_{special_key}_static", [])
                # Dynamic columns: names like "<special_key>_1", "<special_key>_2", ...
                for i in range(max_dynamic):
                    col_name = f"{special_key}_{i+1}"
                    record[col_name] = dynamic_items[i] if i < len(dynamic_items) else ""
                # Static columns: continue numbering after dynamic columns
                for j in range(max_static):
                    col_name = f"{special_key}_{max_dynamic + j + 1}"
                    record[col_name] = static_items[j] if j < len(static_items) else ""
                # Remove temporary keys for this special key
                for temp_key in [f"sorted_{special_key}", f"_{special_key}_dynamic", f"_{special_key}_static"]:
                    record.pop(temp_key, None)
        # ---------------------------------------------------------------------

        df = pd.DataFrame(flattened_data)
        df.fillna("N/A", inplace=True)

        output_file_path = stored_filename.replace(".json", ".xlsx")
        df.to_excel(output_file_path, index=False)

        messagebox.showinfo("Success", f"Excel file created successfully at: {output_file_path}")
        status_label.config(text=f"Excel file saved: {output_file_path}", fg="green")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while converting to Excel:\n{e}")

# Helper functions to run tasks in a separate thread
def threaded_run_query():
    threading.Thread(target=run_query).start()

def threaded_flatten_json_to_excel():
    threading.Thread(target=flatten_json_to_excel).start()

# Function to open the URL when clicking on the info label
def open_url(event=None):
    url = "https://github.com/alReaperz/KaizenKit/blob/main/Vectra/Vectra-Detection-Exporter-API-2.5-v3.py"
    webbrowser.open(url)

# ------------------------- GUI Setup -------------------------
root = tk.Tk()
root.title("Vectra Detection Exporter API 2.5 v3 by alReaperz")

content_frame = tk.Frame(root)
content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

# Row 0: Vectra Brain FQDN
tk.Label(content_frame, text="Vectra Brain FQDN:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
vectra_server_entry = tk.Entry(content_frame, width=50)
vectra_server_entry.grid(row=0, column=1, padx=10, pady=5)

# Row 1: API Token
tk.Label(content_frame, text="API Token:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
api_key_entry = tk.Entry(content_frame, show="*", width=50)
api_key_entry.grid(row=1, column=1, padx=10, pady=5)

# Row 2: Start Time
tk.Label(content_frame, text="Start Time (YYYY-MM-DD HH:MM):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
start_time_entry = tk.Entry(content_frame, width=50)
start_time_entry.grid(row=2, column=1, padx=10, pady=5)

# Row 3: End Time
tk.Label(content_frame, text="End Time (YYYY-MM-DD HH:MM):").grid(row=3, column=0, sticky="w", padx=10, pady=5)
end_time_entry = tk.Entry(content_frame, width=50)
end_time_entry.grid(row=3, column=1, padx=10, pady=5)

# Row 4: Detection Category Checkboxes
checkbox_frame = tk.Frame(content_frame)
checkbox_frame.grid(row=4, column=0, columnspan=2, pady=5)
tk.Label(checkbox_frame, text="Select Detection Categories:").grid(row=0, column=0, columnspan=6, sticky="w")
col = 0
for label, api_value, default in categories:
    var = tk.IntVar(value=default)
    category_vars[label] = var
    cb = tk.Checkbutton(checkbox_frame, text=label, variable=var)
    cb.grid(row=1, column=col, padx=5, pady=5)
    col += 1

# Row 5: Run Query Button
submit_button = tk.Button(content_frame, text="Run Query", command=threaded_run_query)
submit_button.grid(row=5, column=0, columnspan=2, pady=10)

# Row 6: Flatten to Excel Button
flatten_button = tk.Button(content_frame, text="Flatten to Excel", command=threaded_flatten_json_to_excel)
flatten_button.grid(row=6, column=0, columnspan=2, pady=10)

# Row 7: Status Label
status_label = tk.Label(content_frame, text="Waiting for input...", fg="black")
status_label.grid(row=7, column=0, columnspan=2, pady=10)

# Info label (bottom right corner)
info_label = tk.Label(root, text="?", fg="blue", cursor="hand2", font=("Arial", 12, "bold"))
info_label.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-10)
info_label.bind("<Button-1>", open_url)

root.mainloop()
