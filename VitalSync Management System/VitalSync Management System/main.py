from tkinter import *
from tkinter import messagebox
from functions import *

root = Tk()
root.title("VitalSync Management System")
root.iconbitmap("images/favicon.ico")
root.geometry("1600x900")
root.configure(bg="white")


# ----------- Helper Functions -----------

def labeled_entry(parent, label_text, relx_label, rely, relx_entry, show=None):
    Label(parent, text=label_text, font=("Helvetica", 12), bg="white").place(relx=relx_label, rely=rely, anchor="e")
    entry_widget = entry(parent, show=show)
    entry_widget.place(relx=relx_entry, rely=rely, relwidth=0.5, relheight=0.07, anchor="w")
    return entry_widget


def patient_window():
    selection.place_forget()
    p_login_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.4, relheight=0.4)


def admin_window():
    selection.place_forget()
    login_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.4, relheight=0.4)


def patient_signup_window():
    selection.place_forget()
    patient_signup_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.4, relheight=0.5)


def logout():
    if messagebox.askokcancel("Confirm Logout", "Are you sure you want to logout?"):
        try:
            # Reset current user information
            global current_user
            current_user["user_id"] = None
            current_user["name"] = None
            current_user["patient_id"] = None

            # Hide frames
            f.place_forget()
            f1.place_forget()
            pat_f.place_forget()
            pat_f1.place_forget()
            login_frame.place_forget()
            p_login_frame.place_forget()
            selection.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.3, relheight=0.3)
            root.iconbitmap("images/favicon.ico")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred while logging out: {e}")

# ----------- Setup Frames -----------

def setup_selection_frame():
    global selection
    selection = Frame(root, bd=0, highlightthickness=0, relief="flat", bg="white")
    selection.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.3, relheight=0.3)

    Label(selection, text="Welcome to VitalSync", font=("Helvetica", 20, "bold"), bg="white").place(relx=0.5, rely=0.1,
                                                                                                    anchor="n")

    btn(selection, text="Login as a Patient", command=patient_window).place(relx=0.25, rely=0.4, anchor="center")
    btn(selection, text="Login as an Admin", command=admin_window).place(relx=0.75, rely=0.4, anchor="center")
    btn(selection, text="Sign Up as a Patient", command=patient_signup_window).place(relx=0.5, rely=0.7,
                                                                                     anchor="center")

def setup_admin_login_frame():
    global login_frame, username_entry, password_entry, unsuccessful_admin
    login_frame = Frame(root, bg="white")

    Label(login_frame, text="Welcome to VitalSync Admin Panel", font=("Helvetica", 20, "bold"), bg="white").place(
        relx=0.5, rely=0.1, anchor="n")
    unsuccessful_admin = Label(login_frame, text="Incorrect Username or Password", font=("Helvetica", 12), bg="white",
                               fg="red")

    username_entry = labeled_entry(login_frame, "Username:", 0.25, 0.3, 0.27)
    password_entry = labeled_entry(login_frame, "Password:", 0.25, 0.45, 0.27, show="*")

    btn(login_frame, text="Log In", command=lambda: login(
        "admin",
        username_entry,
        password_entry,
        None,
        login_frame,
        f,
        f1,
        logout,
        root,
        unsuccessful_admin
    )).place(relx=0.5, rely=0.7, anchor="center")


def setup_patient_login_frame():
    global p_login_frame, p_username_entry, p_password_entry, unsuccessful_pat
    p_login_frame = Frame(root, bg="white")

    Label(p_login_frame, text="Welcome to VitalSync Patient Panel", font=("Helvetica", 20, "bold"), bg="white").place(
        relx=0.5, rely=0.1, anchor="n")
    unsuccessful_pat = Label(p_login_frame, text="Incorrect Username or Password", font=("Helvetica", 12), bg="white",
                             fg="red")

    p_username_entry = labeled_entry(p_login_frame, "Username:", 0.25, 0.3, 0.27)
    p_password_entry = labeled_entry(p_login_frame, "Password:", 0.25, 0.45, 0.27, show="*")

    btn(p_login_frame, text="Log In", command=lambda: login(
        "patient",
        p_username_entry,
        p_password_entry,
        None,
        p_login_frame,
        pat_f,
        pat_f1,
        logout,
        root,
        unsuccessful_pat
    )).place(relx=0.5, rely=0.7, anchor="center")


def setup_patient_signup_frame():
    global patient_signup_frame, signup_username_entry, signup_password_entry, confirm_password_entry
    patient_signup_frame = Frame(root, bg="white")

    Label(patient_signup_frame, text="Patient Sign Up", font=("Helvetica", 20, "bold"), bg="white").place(relx=0.5,
                                                                                                          rely=0.1,
                                                                                                          anchor="n")

    signup_username_entry = labeled_entry(patient_signup_frame, "Username:", 0.25, 0.3, 0.27)
    signup_password_entry = labeled_entry(patient_signup_frame, "Password:", 0.25, 0.45, 0.27, show="*")
    confirm_password_entry = labeled_entry(patient_signup_frame, "Confirm Password:", 0.25, 0.6, 0.27, show="*")

    btn(patient_signup_frame, text="Create Account", command=lambda: create_account(
        signup_username_entry,
        signup_password_entry,
        confirm_password_entry,
        patient_signup_frame,
        selection
    )).place(relx=0.5, rely=0.8, anchor="center")

def crafted(frame):
    return Label(frame, text="Made with ♥ by Meditussy", font=("Helvetica", 12), bg="white", fg="green")

def setup_admin_main_interface():
    global f, f1
    f = LabelFrame(root, padx=10, pady=10, bg="white", bd=0)
    f1 = LabelFrame(root, padx=10, pady=10, bd=0, bg="#2C3E50")
    load_placeholder(f1)

    admin_buttons = [
        ("Patient Records", 0.00, show_patient_data),
        ("Doctor Records", 0.06, show_doctor_data),
        ("Appointment Records", 0.12, show_appointments),
        ("Billing Records", 0.18, show_billing_data),
        ("Pharmacy Records", 0.24, show_pharmacy_data),
        ("User Records", 0.30, show_user_data),
        ("Bill Graph", 0.36, show_bill_graph),
        ("User Roles Graph", 0.42, show_user_graph),
    ]

    for text, rel_y, command in admin_buttons:
        btn(f, text=text, command=lambda c=command: c(f1)).place(
            relx=0, rely=rel_y, relwidth=1, relheight=0.05
        )

    crafted(f).place(relx=0.17, rely=0.48, relheight=0.05)

def setup_patient_main_interface():
    global pat_f, pat_f1
    pat_f = LabelFrame(root, padx=10, pady=10, bg="white", bd=0)
    pat_f1 = LabelFrame(root, padx=10, pady=10, bd=0, bg="#2C3E50")
    load_placeholder(pat_f1)

    patient_buttons = [
        ("Patient Record", 0.00, show_patient_record),
        ("Appointment Management", 0.06, show_patient_appointments),
        ("Bill Management", 0.12, show_patient_bills)
    ]

    for text, rel_y, command in patient_buttons:
        btn(pat_f, text=text, command=lambda c=command: c(pat_f1)).place(
            relx=0, rely=rel_y, relwidth=1, relheight=0.05
        )

    crafted(pat_f).place(relx=0.17, rely=0.18, relheight=0.05)
# ----------- Initialize App -----------

setup_selection_frame()
setup_admin_login_frame()
setup_patient_login_frame()
setup_patient_signup_frame()
setup_admin_main_interface()
setup_patient_main_interface()

root.mainloop()
