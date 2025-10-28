from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import pandas as pd
import matplotlib.pyplot as plt

### UI HELPERS ###
def load_img(path, frame, max_size=(100, 100)):
    img = Image.open(path)
    img = img.resize(max_size, Image.LANCZOS)
    logo_img = ImageTk.PhotoImage(img)

    logo_label = Label(frame, image=logo_img, bg="#2C3E50")
    logo_label.image = logo_img
    return logo_label

def load_placeholder(frame):
    load_img("images/logo.png", frame).pack()
    Label(frame, text="Welcome to VitalSync Management!", font=("Helvetica", 18), bg="#2C3E50", fg="white", padx=10,
          pady=10).pack()
    Label(frame, text="Choose an option from the sidebar to continue.", font=("Helvetica", 14), bg="#2C3E50",
          fg="white", padx=10, pady=10).pack()
    Label(frame, text="24k-5541 Ayan Ahmed\n24k-5558 Khizr Ahmed\n24k-5589 Haider Husnain\n24k-5659 Ahmed Raza", font=("Helvetica", 14), bg="#2C3E50",
          fg="white", padx=10, pady=10).pack()

def btn(master, text, command=None):
    return Button(
        master,
        text=text,
        command=command,
        font=("Helvetica", 11, "bold"),
        bg="#2694cb",
        fg="white",
        activebackground="#2E66C0",
        activeforeground="white",
        relief="flat",
        padx=10,
        pady=5,
        cursor="hand2"
    )

def entry(master, show=None):
    return Entry(
        master,
        font=("Helvetica", 12),
        show=show,
        bd=0,
        relief="flat",
        highlightthickness=1,
        highlightbackground="#ccc",
        highlightcolor="#3A7FF6",
        bg="white"
    )

### AUTHENTICATION ###

current_user = {
    "user_id": None,
    "name": None,
    "patient_id": None
}

def login(user_type, user_entry, pass_entry, status_label, login_frame, sidebar_frame, content_frame, logout, root, error_label):
    username = user_entry.get()
    password = pass_entry.get()

    try:
        df = pd.read_csv("data/user_data.csv")
        user = df[
            (df["Username"] == username) &
            (df["Password"] == password) &
            (df["Role"].str.lower() == user_type.lower())
            ]

        if not user.empty:
            status = user.iloc[0]["Status"]
            user_id = user.iloc[0]["User ID"]
            name = user.iloc[0]["Name"]

            if status.lower() == "active":
                # Store current user information
                global current_user
                current_user["user_id"] = user_id
                current_user["name"] = name

                # If patient, get patient_id from patient.csv
                if user_type.lower() == "patient":
                    try:
                        patient_df = pd.read_csv("data/patient.csv")
                        patient = patient_df[patient_df["User ID"] == user_id]
                        if not patient.empty:
                            current_user["patient_id"] = patient.iloc[0]["Patient ID"]
                    except Exception as e:
                        messagebox.showwarning("Warning", f"Could not load patient data: {e}")

                login_frame.place_forget()
                sidebar_frame.place(relx=0, rely=0, relwidth=0.2, relheight=1)
                content_frame.place(relx=0.2, rely=0, relwidth=0.8, relheight=1)

                btn(sidebar_frame, text=f"Logged in as {user_id} {name}", command=logout).place(relx=0, rely=0.95,
                                                                                                relwidth=1,
                                                                                                relheight=0.05)

                if status_label:
                    status_label.config(text=f"Welcome to {user_type.capitalize()} Panel", fg="black")

                root.iconbitmap("images/vs.ico")

                # Load placeholder in content frame
                for widget in content_frame.winfo_children():
                    widget.destroy()
                load_placeholder(content_frame)

            else:
                inactive_label = Label(login_frame, text="Account is inactive.", font=("Helvetica", 12), fg="red")
                inactive_label.place(relx=0.3, rely=0.52)
                root.after(1500, lambda: inactive_label.place_forget())
        else:
            error_label.place(relx=0.3, rely=0.52)
            root.after(1000, lambda: error_label.place_forget())

    except Exception as e:
        if status_label:
            status_label.config(text=f"Error: {e}", fg="red")
        else:
            messagebox.showerror("Login Error", f"An unexpected error occurred: {e}")
    finally:
        user_entry.delete(0, END)
        pass_entry.delete(0, END)

def create_account(username_entry, password_entry, confirm_password_entry, signup_frame, selection_frame):
    username = username_entry.get()
    password = password_entry.get()
    confirm_password = confirm_password_entry.get()

    if not username or not password or not confirm_password:
        messagebox.showwarning("Warning", "Please fill out all fields.")
        return

    if password != confirm_password:
        messagebox.showerror("Error", "Passwords do not match.")
        return

    try:
        df = pd.read_csv('data/user_data.csv')

        if username in df['Username'].values:
            messagebox.showerror("Error", "Username already exists. Please choose another.")
            return

        existing_ids = df['User ID'].tolist()
        new_id_number = max([int(i[1:]) for i in existing_ids if i.startswith('U')], default=4000) + 1
        new_user_id = f"U{new_id_number}"

        new_user = {
            "User ID": new_user_id,
            "Username": username,
            "Role": "Patient",
            "Password": password,
            "Status": "Active",
            "Name": username.capitalize()
        }

        df = pd.concat([df, pd.DataFrame([new_user])], ignore_index=True)
        df.to_csv('data/user_data.csv', index=False)

        messagebox.showinfo("Success", f"Account created successfully for {username}!")

        username_entry.delete(0, END)
        password_entry.delete(0, END)
        confirm_password_entry.delete(0, END)
        signup_frame.place_forget()
        selection_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.3, relheight=0.3)

    except Exception as e:
        messagebox.showerror("Error", f"An error occurred while creating account: {e}")

### RECORD MANAGEMENT ###

def display_data(content_frame, title, csv_path):
    def refresh_data():
        for widget in content_frame.winfo_children():
            widget.destroy()
        try:
            nonlocal df
            df = pd.read_csv(csv_path)
        except Exception as e:
            Label(content_frame, text=f"Error loading data: {e}", fg="red", font=("Helvetica", 12), bg="#2C3E50").pack(
                pady=20)
            return

        Label(content_frame, text=title, font=("Helvetica", 18, "bold"), bg="#2C3E50", fg="white").pack(pady=10)

        table_frame = Frame(content_frame)
        table_frame.pack(pady=10, padx=20)

        column_width = 14

        for col_idx, col in enumerate(df.columns):
            Label(table_frame, text=col, font=("Helvetica", 10, "bold"),
                  borderwidth=1, relief="solid", padx=10, pady=5,
                  bg="#0d8b91", fg="white", width=column_width).grid(row=0, column=col_idx, sticky="nsew")

        Label(table_frame, text="Action", font=("Helvetica", 10, "bold"),
              borderwidth=1, relief="solid", padx=10, pady=5,
              bg="#0d8b91", fg="white", width=column_width).grid(row=0, column=len(df.columns), sticky="nsew")

        for row_idx, row in df.iterrows():
            for col_idx, value in enumerate(row):
                display_value = "●●●●●●" if df.columns[col_idx].strip().lower() == "password" else str(value)
                Label(table_frame, text=display_value, font=("Helvetica", 10),
                      borderwidth=1, relief="solid", padx=10, pady=7, width=column_width).grid(row=row_idx + 1,
                                                                                               column=col_idx,
                                                                                               sticky="nsew")

            action_frame = Frame(table_frame, borderwidth=1, relief="solid")
            action_frame.grid(row=row_idx + 1, column=len(df.columns), sticky="nsew")

            Button(action_frame, text="Edit", command=lambda idx=row_idx: edit_row(idx),
                   font=("Helvetica", 9, "bold"), bg="#3A7FF6", fg="white", relief="flat",
                   activebackground="#2E66C0", cursor="hand2", width=6).pack(side=LEFT, padx=2)

            Button(action_frame, text="Delete", command=lambda idx=row_idx: delete_row(idx),
                   font=("Helvetica", 9, "bold"), bg="#DC3545", fg="white", relief="flat",
                   activebackground="#91232d", cursor="hand2", width=6).pack(side=RIGHT, padx=2)

        btn(content_frame, text="Add", command=add_entry).pack(pady=10)

    def edit_row(row_idx):
        for widget in content_frame.winfo_children():
            widget.destroy()

        Label(content_frame, text="Edit Record", font=("Helvetica", 18, "bold"), bg="#2C3E50", fg="white").pack(pady=10)
        form_frame = Frame(content_frame, bg="#2C3E50")
        form_frame.pack(pady=10)

        fields = {}
        selected_row = df.iloc[row_idx]

        for i, (col, val) in enumerate(selected_row.items()):
            Label(form_frame, text=f"{col}:", font=("Helvetica", 11), anchor="w", width=20, bg="#2C3E50", fg="white").grid(row=i, column=0,
                                                                                                 sticky="w", pady=5,
                                                                                                 padx=5)

            entry_widget = Entry(form_frame, font=("Helvetica", 11), width=30)
            entry_widget.insert(0, "●●●●●●" if col.strip().lower() == "password" else str(val))

            if col.strip().lower() in ["user id", "patient id", "doctor id", "medicine id", "appointment id",
                                       "invoice id", "amount (pkr)", "role", "username", "password", "name"]:
                entry_widget.config(state="disabled", cursor="no")

            entry_widget.grid(row=i, column=1, pady=5, padx=5)
            fields[col] = entry_widget

        button_frame = Frame(content_frame, bg="#2C3E50")
        button_frame.pack(pady=10)

        btn(button_frame, "Save", lambda: save_changes(row_idx, fields)).pack(side=LEFT, padx=10)
        btn(button_frame, "Cancel", refresh_data).pack(side=LEFT, padx=10)

    def save_changes(row_idx, fields):
        for col, widget in fields.items():
            if widget["state"] != "disabled":
                df.at[row_idx, col] = widget.get()
        df.to_csv(csv_path, index=False)
        refresh_data()

    def delete_row(row_idx):
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this record?"):
            df.drop(index=row_idx, inplace=True)
            df.to_csv(csv_path, index=False)
            refresh_data()

    def add_entry():
        add_window = Toplevel(content_frame)
        add_window.title(f"Add New Entry - {title}")
        add_window.geometry("400x600")
        add_window.configure(bg="#2C3E50")
        entry_vars = {}

        Label(add_window, text=f"Add New {title[:-8]} Entry", font=("Helvetica", 14, "bold"), bg="#2C3E50", fg="white").pack(pady=10)
        form_frame = Frame(add_window, bg="#2C3E50")
        form_frame.pack(pady=10, padx=20, fill=BOTH, expand=True)

        for idx, column in enumerate(df.columns):
            Label(form_frame, text=f"{column}:", anchor="w", font=("Helvetica", 10), bg="#2C3E50", fg="white").grid(row=idx, column=0, sticky="w",
                                                                                          pady=5)
            var = StringVar()
            Entry(form_frame, textvariable=var, font=("Helvetica", 10), width=30).grid(row=idx, column=1, pady=5)
            entry_vars[column] = var

        def save_new_entry():
            new_data = {col: entry_vars[col].get() for col in df.columns}
            if all(val.strip() for val in new_data.values()):
                new_df = pd.concat([df, pd.DataFrame([new_data])], ignore_index=True)
                new_df.to_csv(csv_path, index=False)
                add_window.destroy()
                refresh_data()
            else:
                messagebox.showerror("Incomplete Data", "Please fill in all fields.")

        btn(add_window, "Save Entry", command=save_new_entry).pack(pady=10)

    df = None
    refresh_data()

### PATIENT PANEL FUNCTIONS ###

def display_patient_info(content_frame, title, csv_path, id_column, id_value):
    """Display and allow editing/creating of patient's info, appointments or billing"""
    for widget in content_frame.winfo_children():
        widget.destroy()

    try:
        # Load the data
        df = pd.read_csv(csv_path)

        # Get the patient specific data
        patient_data = df[df[id_column] == id_value]

        title_label = Label(content_frame, text=title, font=("Helvetica", 18, "bold"), bg="#2C3E50", fg="white")
        title_label.pack(pady=10)

        form_frame = Frame(content_frame, bg="#2C3E50")
        form_frame.pack(pady=20, padx=20, fill=BOTH)

        fields = {}

        # -------------------------
        # Section-specific settings
        # -------------------------
        if title == "Patient Information":
            columns = ["Patient ID", "Name", "Age", "Contact Number", "Illness/Disease", "Blood Group", "User ID", "Status"]
            id_prefix = "P"
            id_field = "Patient ID"
            auto_fields = {"User ID": current_user["user_id"], "Status": "Active"}

        elif title == "Appointment Information":
            columns = ["Appointment ID", "Patient ID", "Doctor Name", "Doctor ID", "Date", "Time Slot", "Status"]
            id_prefix = "A"
            id_field = "Appointment ID"
            auto_fields = {"Patient ID": current_user["patient_id"], "Status": "Pending"}

            # Load doctor list
            doctor_df = pd.read_csv("data/doctor.csv")
            doctor_list = doctor_df["Name"].tolist()
            doctor_id_map = dict(zip(doctor_df["Name"], doctor_df["Doctor ID"]))

        elif title == "Billing Information":
            columns = ["Invoice ID", "Patient ID", "Date", "Amount (PKR)", "Service", "Payment Status"]
            id_prefix = "INV"
            id_field = "Invoice ID"
            auto_fields = {"Patient ID": current_user["patient_id"], "Status": "Unpaid"}

        else:
            raise ValueError("Unknown section title")

        # --------------------------
        # Display existing or new form
        # --------------------------
        if not patient_data.empty:
            # Display existing data
            for i, (col, val) in enumerate(patient_data.iloc[0].items()):
                Label(form_frame, text=f"{col}:", font=("Helvetica", 12),
                      bg="#2C3E50", fg="white", anchor="e").grid(row=i, column=0,
                                                                 sticky="e", pady=10, padx=10)

                entry_widget = Entry(form_frame, font=("Helvetica", 12), width=40)
                entry_widget.insert(0, str(val))

                # Disable editing for ID fields
                non_editable = ["patient id", "appointment id", "invoice id", "user id", "doctor id"]
                if col.lower() in non_editable:
                    entry_widget.config(state="disabled")

                entry_widget.grid(row=i, column=1, pady=10, padx=10, sticky="w")
                fields[col] = entry_widget

            # Row index of the data for updating
            row_idx = patient_data.index[0]

        else:
            # New record form
            try:
                all_df = pd.read_csv(csv_path)
                existing_ids = all_df[id_field].tolist()
                prefix_len = len(id_prefix)

                # Only IDs that start with correct prefix and extract numeric part safely
                id_numbers = [int(i[prefix_len:]) for i in existing_ids if
                              i.startswith(id_prefix) and i[prefix_len:].isdigit()]
                new_id_number = max(id_numbers, default=1000) + 1
                new_unique_id = f"{id_prefix}{new_id_number}"

            except Exception:
                new_unique_id = f"{id_prefix}1000"

            for i, col in enumerate(columns):
                Label(form_frame, text=f"{col}:", font=("Helvetica", 12),
                      bg="#2C3E50", fg="white", anchor="e").grid(row=i, column=0,
                                                                 sticky="e", pady=10, padx=10)

                if title == "Appointment Information" and col == "Doctor Name":
                    var = StringVar()
                    doctor_dropdown = OptionMenu(form_frame, var, *doctor_list)
                    doctor_dropdown.config(font=("Helvetica", 12), width=37)
                    doctor_dropdown.grid(row=i, column=1, pady=10, padx=10, sticky="w")
                    fields[col] = var

                    def on_doctor_select(*args):
                        selected_name = var.get()
                        doctor_id = doctor_id_map.get(selected_name, "")
                        fields["Doctor ID"].config(state="normal")
                        fields["Doctor ID"].delete(0, END)
                        fields["Doctor ID"].insert(0, doctor_id)
                        fields["Doctor ID"].config(state="disabled")

                    var.trace("w", on_doctor_select)

                else:
                    entry_widget = Entry(form_frame, font=("Helvetica", 12), width=40)

                    if col == id_field:
                        entry_widget.insert(0, new_unique_id)
                        entry_widget.config(state="disabled")
                    elif col in auto_fields:
                        entry_widget.insert(0, auto_fields[col])
                        entry_widget.config(state="disabled" if col.endswith("ID") else "normal")

                    entry_widget.grid(row=i, column=1, pady=10, padx=10, sticky="w")
                    fields[col] = entry_widget

            row_idx = -1

        # ----------------------
        # Save Button
        # ----------------------
        button_frame = Frame(content_frame, bg="#2C3E50")
        button_frame.pack(pady=20)

        def save_patient_data():
            # Collect data from form
            new_data = {}
            for col, widget in fields.items():
                if isinstance(widget, StringVar):
                    new_data[col] = widget.get()
                else:
                    new_data[col] = widget.get()

            if row_idx == -1:
                df = pd.read_csv(csv_path)
                # New entry
                df = pd.concat([df, pd.DataFrame([new_data])], ignore_index=True)

                # If new patient info → update current_user patient_id
                if title == "Patient Information" and "Patient ID" in new_data:
                    current_user["patient_id"] = new_data["Patient ID"]

            else:
                # Update existing entry
                df = pd.read_csv(csv_path)
                for col, value in new_data.items():
                    df.at[row_idx, col] = value

            # Save to CSV
            df.to_csv(csv_path, index=False)
            messagebox.showinfo("Success", f"{title} saved successfully!")

            # Refresh the view
            display_patient_info(content_frame, title, csv_path, id_column, new_data[id_column])

        btn(button_frame, "Save", command=save_patient_data).pack(side=LEFT, padx=10)

    except Exception as e:
        Label(content_frame, text=f"Error: {e}", font=("Helvetica", 14),
              bg="#2C3E50", fg="red").pack(pady=20)

def show_patient_record(content_frame):
    """Show patient's personal information"""
    if current_user["patient_id"]:
        display_patient_info(content_frame, "Patient Information", "data/patient.csv", "Patient ID",
                             current_user["patient_id"])
    else:
        # No patient record exists yet, show form to create one
        display_patient_info(content_frame, "Patient Information", "data/patient.csv", "Patient ID", None)

def show_patient_appointments(content_frame):
    """Show patient's appointments"""
    if current_user["patient_id"]:
        display_patient_info(content_frame, "Appointment Information", "data/appointments.csv", "Patient ID",
                             current_user["patient_id"])
    else:
        messagebox.showwarning("Warning", "No patient record found. Please create your patient record first.")
        show_patient_record(content_frame)

def show_patient_bills(content_frame):
    """Show patient's billing information"""
    if current_user["patient_id"]:
        display_patient_info(content_frame, "Billing Information", "data/billings.csv", "Patient ID",
                             current_user["patient_id"])
    else:
        messagebox.showwarning("Warning", "No patient record found. Please create your patient record first.")
        show_patient_record(content_frame)

### SHORTCUTS FOR DIFFERENT TABLES ###

def show_patient_data(content_frame):
    display_data(content_frame, "Patient Records", "data/patient.csv")

def show_doctor_data(content_frame):
    display_data(content_frame, "Doctor Records", "data/doctor.csv")

def show_billing_data(content_frame):
    display_data(content_frame, "Billing Records", "data/billings.csv")

def show_appointments(content_frame):
    display_data(content_frame, "Appointment Records", "data/appointments.csv")

def show_pharmacy_data(content_frame):
    display_data(content_frame, "Pharmacy Records", "data/pharmacy.csv")

def show_user_data(content_frame):
    display_data(content_frame, "Users Records", "data/user_data.csv")

def show_bill_graph(content_frame):
    """Display a graph of Invoice ID vs Amount (PKR) from billing.csv"""

    # Clear content_frame
    for widget in content_frame.winfo_children():
        widget.destroy()

    try:
        # Load billing data
        df = pd.read_csv('data/billings.csv')

        # Check necessary columns
        if 'Invoice ID' not in df.columns or 'Amount (PKR)' not in df.columns:
            Label(content_frame, text="Required columns not found in billing.csv",
                  font=("Helvetica", 14), bg="#2C3E50", fg="red").pack(pady=20)
            return

        # Extract relevant data
        invoice_ids = df['Invoice ID'].astype(str)  # ensure strings for x-axis
        amounts = pd.to_numeric(df['Amount (PKR)'], errors='coerce').fillna(0)  # ensure numeric + handle NaNs

        # Title label
        Label(content_frame, text="Billing Summary (Invoice vs Amount)",
              font=("Helvetica", 18, "bold"), bg="#2C3E50", fg="white").pack(pady=10)

        # Create a frame to center the graph (like table)
        graph_frame = Frame(content_frame, bg="#2C3E50")
        graph_frame.pack(pady=10, padx=20)

        # Plotting
        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.bar(invoice_ids, amounts, color="#3A7FF6")

        ax.set_xlabel("Invoice ID", fontsize=12)
        ax.set_ylabel("Amount (PKR)", fontsize=12)
        ax.set_title("Invoice vs Bill Amount", fontsize=14, pad=15)
        ax.set_xticks(range(len(invoice_ids)))  # Set fixed tick locations
        ax.set_xticklabels(invoice_ids, rotation=45, ha="right")
        ax.bar_label(bars, fmt='%.0f', fontsize=9, padding=3)

        fig.tight_layout()

        # Embed matplotlib plot into Tkinter frame
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    except Exception as e:
        Label(content_frame, text=f"Error loading or plotting data: {e}",
              font=("Helvetica", 14), bg="#2C3E50", fg="red").pack(pady=20)

def show_user_graph(content_frame):
    """Display a graph of User Roles vs User Count from user_data.csv"""

    # Clear content_frame
    for widget in content_frame.winfo_children():
        widget.destroy()

    try:
        # Load user data
        df = pd.read_csv('data/user_data.csv')

        # Check necessary column
        if 'Role' not in df.columns:
            Label(content_frame, text="Required column 'Role' not found in user_data.csv",
                  font=("Helvetica", 14), bg="#2C3E50", fg="red").pack(pady=20)
            return

        # Count users by role (case-insensitive just in case)
        role_counts = df['Role'].str.strip().str.title().value_counts()

        roles = role_counts.index.tolist()  # e.g., ['Admin', 'Patient']
        counts = role_counts.values.tolist()  # e.g., [3, 10]

        # Title label
        Label(content_frame, text="User Roles vs User Count",
              font=("Helvetica", 18, "bold"), bg="#2C3E50", fg="white").pack(pady=10)

        # Create a frame to center the graph (like table)
        graph_frame = Frame(content_frame, bg="#2C3E50")
        graph_frame.pack(pady=10, padx=20)

        # Plotting
        fig, ax = plt.subplots(figsize=(8, 6))
        bars = ax.bar(range(len(roles)), counts, color="#3A7FF6")

        ax.set_xlabel("User Role", fontsize=12)
        ax.set_ylabel("User Count", fontsize=12)
        ax.set_title("User Roles vs User Count", fontsize=14, pad=15)

        ax.set_xticks(range(len(roles)))
        ax.set_xticklabels(roles, rotation=0, ha="center")
        ax.bar_label(bars, fmt='%.0f', fontsize=9, padding=3)

        fig.tight_layout()

        # Embed matplotlib plot into Tkinter frame
        canvas = FigureCanvasTkAgg(fig, master=graph_frame)
        canvas.draw()
        canvas.get_tk_widget().pack()

    except Exception as e:
        Label(content_frame, text=f"Error loading or plotting data: {e}",
              font=("Helvetica", 14), bg="#2C3E50", fg="red").pack(pady=20)
