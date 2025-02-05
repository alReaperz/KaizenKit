import os
import ssl
import requests
from datetime import datetime
from pytz import timezone
import tkinter as tk
from tkinter import messagebox
import pandas as pd
import json
import sys
import webbrowser  # Used to open the URL

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

# Define keys to flatten
flatten_keys = [
    "id", "state", "threat", "certainty", "detection_category", "detection_type",
    "created_timestamp", "first_timestamp", "last_timestamp", "src_ip", "src_host.id",
    "src_host.ip", "src_host.name", "src_account", "src_host.is_key_asset", "targets_key_asset",
    "is_triaged", "custom_detection", "triage_rule_id", "filtered_by_ai", "filtered_by_user",
    "filtered_by_rule", "tags"
]

# Define which arrays to expand into columns
expand_arrays = ["tags"]

# Function to flatten JSON data
def flatten_json(json_object, keys_to_include):
    flat_data = {}
    for key in keys_to_include:
        parts = key.split(".")
        value = json_object
        try:
            for part in parts:
                value = value[part] if isinstance(value, dict) else None
            # Handle arrays
            if isinstance(value, list):
                if key in expand_arrays:  # Expand arrays into separate columns
                    for i, element in enumerate(value):
                        flat_data[f"{key}_{i+1}"] = element
                else:
                    flat_data[key] = ", ".join(map(str, value))
            else:
                flat_data[key] = value if value not in (None, "") else "N/A"
        except (KeyError, TypeError):
            flat_data[key] = "N/A"
    return flat_data

# Run query and process data
def run_query():
    global stored_filename  # Use the global stored_filename variable

    # First, get user inputs from the GUI
    vectra_server = vectra_server_entry.get().strip()
    api_key = api_key_entry.get().strip()
    start_time = start_time_entry.get().strip()
    end_time = end_time_entry.get().strip()

    # Validate inputs BEFORE updating the status message
    if not vectra_server or not api_key or not start_time or not end_time:
        messagebox.showerror("Input Error", "All fields are required!")
        return

    # Now that inputs are valid, disable the button and update the status message
    submit_button.config(state=tk.DISABLED)
    status_label.config(text="Processing request... Please wait.", fg="blue")
    root.update()

    try:
        # Convert user-provided date and time (GMT+8) to UTC
        local_tz = timezone("Asia/Kuala_Lumpur")
        start_time_utc = local_tz.localize(datetime.strptime(start_time, "%Y-%m-%d %H:%M")).astimezone(timezone("UTC")).strftime("%Y-%m-%dT%H%M")
        end_time_utc = local_tz.localize(datetime.strptime(end_time, "%Y-%m-%d %H:%M")).astimezone(timezone("UTC")).strftime("%Y-%m-%dT%H%M")

        # Build the URL and headers
        url = f"https://{vectra_server}/api/v2.5/search/detections/?page_size=5000&query_string=detection.first_timestamp%3A%5B{start_time_utc}%20TO%20{end_time_utc}%5D"
        headers = {"Authorization": f"Token {api_key}"}

        # Create a requests session using the SystemCertAdapter
        with requests.Session() as session:
            session.mount("https://", SystemCertAdapter())
            # Send the GET request
            response = session.get(url, headers=headers)
            response.raise_for_status()  # Raise an error for HTTP codes >= 400

        # Save the output to the Downloads folder with a unique filename
        downloads_folder = os.path.join(os.path.expanduser("~"), "Downloads")
        file_name = f"detections_{start_time}_{end_time}.json".replace(" ", "T").replace(":", "").replace("-", "")
        counter = 1
        output_path = os.path.join(downloads_folder, file_name)

        # Check if the file already exists, and increment the suffix if needed
        while os.path.exists(output_path):
            output_path = os.path.join(downloads_folder, f"{file_name.split('.')[0]}_{counter}.json")
            counter += 1

        # Store the output filename in the global variable
        stored_filename = output_path

        with open(output_path, "w") as output_file:
            output_file.write(response.text)

        # Notify the user of success
        messagebox.showinfo("Success", f"Data saved to: {output_path}")
        status_label.config(text=f"File saved: {output_path}", fg="green")

    except requests.exceptions.RequestException as e:
        messagebox.showerror("Request Error", f"Error during API request:\n{e}")
        status_label.config(text="Request failed.", fg="red")
    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred:\n{e}")
        status_label.config(text="An error occurred.", fg="red")
    finally:
        # Re-enable the submit button after the request is processed
        submit_button.config(state=tk.NORMAL)

# Flatten the JSON to Excel and add a new column based on tags
def flatten_json_to_excel():
    global stored_filename  # Access the global stored_filename variable
    try:
        if stored_filename is None:
            messagebox.showerror("Error", "No data file available. Please run the query first.")
            return

        # Read the stored JSON file
        with open(stored_filename, "r") as json_file:
            data = json.load(json_file)

        # Process the "results" array in JSON
        if "results" not in data or not isinstance(data["results"], list):
            messagebox.showerror("Error", "No 'results' array found in the JSON file.")
            return

        # Flatten the JSON data
        flattened_data = [flatten_json(item, flatten_keys) for item in data["results"]]

        # Convert to DataFrame
        df = pd.DataFrame(flattened_data)

        # Replace any remaining empty or missing values with "N/A"
        df.fillna("N/A", inplace=True)

        # --- Add a new column "Detection Status" based on tags ---
        # This function checks all columns that start with "tags" and returns
        # "False Positive" if any tag is exactly "False Positive", or "True Positive"
        # if any tag is exactly "True Positive". Otherwise, it returns an empty string.
        def get_detection_status(row):
            # Identify all columns created from the tags array.
            tag_columns = [col for col in row.index if col.startswith("tags")]
            # Collect tag values (ignoring "N/A")
            tags = [row[col] for col in tag_columns if row[col] != "N/A"]
            if "False Positive" in tags:
                return "False Positive"
            elif "True Positive" in tags:
                return "True Positive"
            else:
                return ""
        
        # Append the new column; it will appear at the end.
        df["Detection Status"] = df.apply(get_detection_status, axis=1)
        # -----------------------------------------------------------

        # Automatically generate the output file path for Excel
        output_file_path = stored_filename.replace(".json", ".xlsx")

        # Save to Excel
        df.to_excel(output_file_path, index=False)

        # Notify the user of success
        messagebox.showinfo("Success", f"Excel file created successfully at: {output_file_path}")
        status_label.config(text=f"Excel file saved: {output_file_path}", fg="green")

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while converting to Excel:\n{e}")

# Function to open the URL when clicking on the info label
def open_url(event=None):
    url = "https://github.com/alReaperz/KaizenKit/blob/main/Vectra/Vectra-Search-Detection-v2.py"
    webbrowser.open(url)

# GUI Setup
root = tk.Tk()
root.title("Vectra Detection Exporter API 2.5 V2 by alReaperz")

# Create a frame for the main content (inputs and buttons)
content_frame = tk.Frame(root)
content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

tk.Label(content_frame, text="Vectra Brain FQDN:").grid(row=0, column=0, sticky="w", padx=10, pady=5)
vectra_server_entry = tk.Entry(content_frame, width=50)
vectra_server_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(content_frame, text="API Token:").grid(row=1, column=0, sticky="w", padx=10, pady=5)
api_key_entry = tk.Entry(content_frame, show="*", width=50)
api_key_entry.grid(row=1, column=1, padx=10, pady=5)

tk.Label(content_frame, text="Start Time (YYYY-MM-DD HH:MM):").grid(row=2, column=0, sticky="w", padx=10, pady=5)
start_time_entry = tk.Entry(content_frame, width=50)
start_time_entry.grid(row=2, column=1, padx=10, pady=5)

tk.Label(content_frame, text="End Time (YYYY-MM-DD HH:MM):").grid(row=3, column=0, sticky="w", padx=10, pady=5)
end_time_entry = tk.Entry(content_frame, width=50)
end_time_entry.grid(row=3, column=1, padx=10, pady=5)

# Add submit button
submit_button = tk.Button(content_frame, text="Run Query", command=run_query)
submit_button.grid(row=4, column=0, columnspan=2, pady=10)

# Add a button for flattening the JSON to Excel
flatten_button = tk.Button(content_frame, text="Flatten to Excel", command=flatten_json_to_excel)
flatten_button.grid(row=5, column=0, columnspan=2, pady=10)

# Add a status label to display processing status
status_label = tk.Label(content_frame, text="Waiting for input...", fg="black")
status_label.grid(row=6, column=0, columnspan=2, pady=10)

# Create a clickable info label in the bottom-right corner of the window
info_label = tk.Label(root, text="?", fg="blue", cursor="hand2", font=("Arial", 12, "bold"))
info_label.place(relx=1.0, rely=1.0, anchor="se", x=-10, y=-10)
info_label.bind("<Button-1>", open_url)

# Start the GUI event loop
root.mainloop()
