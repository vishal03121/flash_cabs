# tkinter module for GUI
from tkinter import *
import tkinter as ttk
from tkinter import messagebox
# image library for displaying images
from PIL import ImageTk, Image
# for sending emails library
import smtplib
# for checking internet connection
import socket
# for date and time stamps
import time
from datetime import date
from datetime import datetime, timedelta
# others needed
import math, random
import re
import json

# global variables required
# global root variable for main window
global root
global left_frame
global right_frame
# used to clear widgets of a particular window
global welcome_screen_items
global login_screen_items
global sign_up_screen_items
global forgot_password_screen_items
global left_frame_items
global right_frame_items
# login variable to check login status
global login_status
global logged_in_user
# otp variables
global otp
otp_count = 0
# for strong user data
global car_id
global users

# colors to be used during the whole code
background_color = "#272822"
foreground_color = "#909090"
left_frame_background_color = "#3c3f41"


# checking internet connectivity
def check_internet_socket():
    try:
        socket.create_connection(('Google.com', 80))
        return True
    except OSError:
        return False


# reading data from files
def read_car_id():
    global car_id
    # reading json file
    with open('data_files/car_id.json') as infile:
        car_id = json.load(infile)


def read_users():
    global users
    # reading json file
    with open('data_files/users.json') as infile:
        users = json.load(infile)


# writing to file json file functions
def write_users():
    global users
    json_object = json.dumps(users, indent=4)
    # Writing to json file
    with open("data_files/users.json", "w") as outfile:
        outfile.write(json_object)


# validate functions
# checking username validity
def validate_username(username):
    # empty username condition
    if len(username) == 0:
        return "Please Enter Username", False
    # lengthy username condition
    if len(username) > 40:
        return 'Username Length must be less than 40 chars', False
    # special character condition
    special_char_search = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    if (special_char_search.search(username) != None):
        return "Username cannot contain special characters", False
    # valid username
    return "valid username", True


# check password validity for login screen
def validate_login_password(password):
    # empty password
    if len(password) == 0:
        return "Please enter Password", False
    # valid username
    return "valid password", True


# actual password validation
def validate_password(password, confirm_password):
    # empty password condition
    if len(password) <= 0:
        return "Please enter Password", False
    # password length must be 8 chars long
    if len(password) < 8:
        return "Password must be of 8 chars", False
    # special character condition, there must be one special char
    special_char_search = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    if (special_char_search.search(password) == None):
        return "Password must contain a special character", False
    # password not matching with confirm password
    if password != confirm_password:
        return "Confirm Password not matching with password", False
    # valid password
    return "valid password", True


# name validate function
def validate_name(name):
    # empty name condition
    if len(name) <= 0:
        return "Please enter Name", False
    # max length of name condition
    if len(name) > 40:
        return "Name must be less than 40 chars", False
    # no digit in name condition
    for s in name:
        if s.isdigit():
            return "Name must contain only chars", False
    # valid name
    return "valid name", True


# otp validation function:
def validate_otp(otp_original, otp_input):
    # otp empty condition
    if len(otp_input) <= 0:
        return "Please Enter OTP", False
    # otp not matching condition
    if otp_input != otp_original:
        return "Invalid OTP!", False
    # valid otp
    return "valid otp", True


# email validation
def validate_email(email):
    # empty email condition
    if len(email) <= 0:
        return "Please Enter Email", False
    # checking email via regular expression
    email_expression = '^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$'
    if re.search(email_expression, email) == None:
        return "Please Enter Valid Email Address", False
    # valid condition
    return "valid email", True


# validating current password
def validate_current_password(current_password):
    # checking user password entered matches with stored or not
    if current_password != users[logged_in_user]['password']:
        return "Incorrect Current Password", False
    # valid password
    return "valid current password", True


# pick up from validation
def validate_pick_up(pick_up):
    if len(pick_up) <= 0:
        return "Please Enter 'From' Location", False
    if len(pick_up) < 20:
        return "'From' Location must be 20 chars long!", False
    if len(pick_up) > 40:
        return "'From' Location must be less than 40 chars", False
    return "valid pick up", True


# drop to validation
def validate_drop_to(drop_to):
    if len(drop_to) <= 0:
        return "Please Enter 'To' Location", False
    if len(drop_to) < 20:
        return "'To' Location must be 20 chars long!", False
    if len(drop_to) > 40:
        return "'To Location must be less than 40 chars", False
    return "valid drop to", True


# validate Phone number
def validate_phone_number(phone_number):
    if len(phone_number) <= 0:
        return "Please Provide Phone Number.", False
    phone_number_expression = '^(?:(?:\+|0{0,2})91(\s*[\-]\s*)?|[0]?)?[789]\d{9}$'
    if re.search(phone_number_expression, phone_number) == None:
        return "Invalid Phone Number", False
    return "valid phone number", True


# pincode validation function
def validate_pincode(pincode, city):
    if len(pincode) == 0:
        return "Please enter Pincode", False
    if len(pincode) < 6 and len(pincode) > 6:
        return "Pincode must be 6 digit long", False
    pincodes = {}
    with open("data_files/pincode.json") as infile:
        pincodes = json.load(infile)
    if pincode not in pincodes[city]:
        return "Pincode Not matching with City", False
    del pincodes
    return "valid pincode", True


# generating otp function
def generate_otp():
    digits = "0123456789"
    OTP = ""
    # length of password can be changed by changing value in range(here 6 digit otp)
    for i in range(6):
        OTP += digits[math.floor(random.random() * 10)]
    return OTP


# action to perform if no internet connection detected
def no_internet(screen_items):
    root.geometry("400x205")
    # clearing screen widgets
    for item in screen_items:
        item.destroy()
    internet_image = ImageTk.PhotoImage(Image.open('images/internet_connection.png'))
    internet_label = Label(root, image=internet_image, bg=background_color)
    internet_label.image = internet_image
    internet_label.grid(row=0, column=0, columnspan=3)
    welcome_screen = Button(root, text='Go To Welcome Screen', bg=background_color, fg=foreground_color,
                            activebackground=left_frame_background_color, activeforeground=foreground_color,
                            relief=GROOVE)
    welcome_screen.config(command=lambda: welcome_screen_window([internet_label, welcome_screen]))
    welcome_screen.grid(row=1, column=0, columnspan=3)


# confirming changed password
def confirm_change_password():
    # getting vale from input fields
    current_password = right_frame_items[9].get()
    change_password = right_frame_items[11].get()
    confirm_password = right_frame_items[13].get()

    # validating password
    is_current_password_valid = validate_current_password(current_password)
    is_change_password_valid = validate_password(change_password, confirm_password)
    if is_current_password_valid[1]:
        if is_change_password_valid[1]:
            users[logged_in_user]["password"] = change_password
            write_users()
            user_profile_screen(right_frame_items)
        else:
            right_frame_items[15].config(text=is_change_password_valid[0])
            right_frame_items[15].grid(row=15, column=0, columnspan=6, sticky=W + E)
            right_frame_items[14].grid(row=14, column=0, columnspan=6, sticky=W + E, pady=61)
    else:
        right_frame_items[15].config(text=is_current_password_valid[0])
        right_frame_items[15].grid(row=15, column=0, columnspan=6, sticky=W + E)
        right_frame_items[14].grid(row=14, column=0, columnspan=6, sticky=W + E, pady=61)


# change user password function
def change_password():
    right_frame_items[8].grid(row=8, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    right_frame_items[9].grid(row=8, column=3, columnspan=3, rowspan=2, pady=10)
    right_frame_items[10].grid(row=10, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    right_frame_items[11].grid(row=10, column=3, columnspan=3, rowspan=2, pady=10)
    right_frame_items[12].grid(row=12, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    right_frame_items[13].grid(row=12, column=3, columnspan=3, rowspan=2, pady=10)
    right_frame_items[14].grid(row=14, column=0, columnspan=6, sticky=W + E, pady=69)
    right_frame_items[16].config(text="Cancel", command=lambda: user_profile_screen(right_frame_items))
    right_frame_items[17].config(command=confirm_change_password)


# deleting user and updating data
def delete_user_confirm_update():
    del users[logged_in_user]
    write_users()


# delete account final confirmation
def delete_user():
    current_password = right_frame_items[9].get()
    # validating password
    is_current_password_valid = validate_current_password(current_password)
    if is_current_password_valid[1]:
        if current_bookings() == 0:
            time.sleep(2)
            delete_user_confirm_update()
            welcome_screen_login([left_frame, right_frame])
        else:
            right_frame_items[15].config(text="Ride Pending, Can't delete")
            right_frame_items[15].grid(row=15, column=0, columnspan=6, sticky=W + E)
            right_frame_items[14].grid(row=14, column=0, columnspan=6, sticky=W + E, pady=104)
    else:
        right_frame_items[15].config(text=is_current_password_valid[0])
        right_frame_items[15].grid(row=15, column=0, columnspan=6, sticky=W + E)
        right_frame_items[14].grid(row=14, column=0, columnspan=6, sticky=W + E, pady=104)


# delete account function screen updation
def delete_user_screen():
    right_frame_items[8].grid(row=8, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    right_frame_items[9].grid(row=8, column=3, columnspan=3, rowspan=2, pady=10)
    right_frame_items[14].grid(row=14, column=0, columnspan=6, sticky=W + E, pady=112)
    right_frame_items[17].config(text="Cancel", command=lambda: user_profile_screen(right_frame_items))
    right_frame_items[16].config(command=delete_user)


# user profile screen
def user_profile_screen(screen_items):
    # clearing widgets on right frame
    for item in screen_items:
        item.destroy()
    # creating widgets of user profile screen
    global right_frame
    right_frame.grid_forget()
    right_frame = Frame(root, bg=background_color)
    right_frame.grid(row=0, column=1, sticky=W + E + N + S)
    page_label = Label(right_frame, text="USER PROFILE", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0, width=63)
    upper_space_label = Label(right_frame, bg=background_color, fg=foreground_color,
                              bd=0, highlightthickness=0)
    username_label = Label(right_frame, text="Username:", bg=background_color, fg=foreground_color,
                           bd=0, highlightthickness=0)
    username_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                           insertbackground=foreground_color, width=30)
    name_label = Label(right_frame, text="Name:", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0)
    name_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                       insertbackground=foreground_color, width=30)
    email_label = Label(right_frame, text="Email:", bg=background_color, fg=foreground_color,
                        bd=0, highlightthickness=0)
    email_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                        insertbackground=foreground_color, width=30)
    current_password_label = Label(right_frame, text="Current Password:", bg=background_color, fg=foreground_color,
                                   bd=0, highlightthickness=0)
    current_password_entry = Entry(right_frame, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                                   insertbackground=foreground_color, width=30)
    change_password_label = Label(right_frame, text="Change Password:", bg=background_color, fg=foreground_color,
                                  bd=0, highlightthickness=0)
    change_password_entry = Entry(right_frame, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                                  insertbackground=foreground_color, width=30)
    confirm_password_label = Label(right_frame, text="Confirm Password:", bg=background_color, fg=foreground_color,
                                   bd=0, highlightthickness=0)
    confirm_password_entry = Entry(right_frame, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                                   insertbackground=foreground_color, width=30)
    error_label = Label(right_frame, text="error message", bg=background_color, fg="red",
                        bd=0, highlightthickness=0)
    delete_account_button = Button(right_frame, text='Delete Account', bg=background_color, fg=foreground_color,
                                   activebackground=left_frame_background_color, activeforeground=foreground_color,
                                   relief=GROOVE)
    change_password_button = Button(right_frame, text='Change Password', bg=background_color, fg=foreground_color,
                                    activebackground=left_frame_background_color, activeforeground=foreground_color,
                                    relief=GROOVE)
    logout_button = Button(right_frame, text='Logout', bg=background_color, fg=foreground_color,
                           activebackground=left_frame_background_color, activeforeground=foreground_color,
                           relief=GROOVE)
    lower_space_label = Label(right_frame, bg=background_color, fg=foreground_color,
                              bd=0, highlightthickness=0)
    # placing widgets on screen
    page_label.grid(row=0, column=0, columnspan=6, sticky=W + E)
    upper_space_label.grid(row=1, column=0, columnspan=6, sticky=W + E, pady=11)
    username_label.grid(row=2, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    username_entry.grid(row=2, column=3, columnspan=3, rowspan=2, pady=10)
    name_label.grid(row=4, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    name_entry.grid(row=4, column=3, columnspan=3, rowspan=2, pady=10)
    email_label.grid(row=6, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    email_entry.grid(row=6, column=3, columnspan=3, rowspan=2, pady=10)

    # lower pace label pady=60 in change passowrd section
    lower_space_label.grid(row=14, column=0, columnspan=6, sticky=W + E, pady=134)

    delete_account_button.grid(row=16, column=0, columnspan=2, sticky=W + E + S)
    change_password_button.grid(row=16, column=2, columnspan=2, sticky=W + E + S)
    logout_button.grid(row=16, column=4, columnspan=2, sticky=W + E + S)

    # inserting values in entry boxes
    username_entry.insert(0, logged_in_user)
    name_entry.insert(0, users[logged_in_user]["name"])
    email_entry.insert(0, users[logged_in_user]["email"])
    # diabling the values in entry boxex
    username_entry.config(state=DISABLED, disabledbackground=background_color)
    name_entry.config(state=DISABLED, disabledbackground=background_color)
    email_entry.config(state=DISABLED, disabledbackground=background_color)
    global right_frame_items
    right_frame_items = [page_label,
                         upper_space_label,
                         username_label,
                         username_entry,
                         name_label,
                         name_entry,
                         email_label,
                         email_entry,
                         current_password_label,
                         current_password_entry,
                         change_password_label,
                         change_password_entry,
                         confirm_password_label,
                         confirm_password_entry,
                         lower_space_label,
                         error_label,
                         delete_account_button,
                         change_password_button,
                         logout_button]
    # adding onclick behaviour to buttons
    logout_button.config(command=lambda: welcome_screen_login([left_frame, right_frame]))
    change_password_button.config(command=change_password)
    delete_account_button.config(command=delete_user_screen)


class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)
        canvas = Canvas(self, width=449, height=498, bg=background_color, highlightthickness=0, bd=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas, bg=background_color)

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(
                scrollregion=canvas.bbox("all")
            )
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")

        canvas.configure(yscrollcommand=scrollbar.set, bg=background_color, highlightcolor=background_color,
                         highlightbackground=left_frame_background_color)

        canvas.grid(row=0, column=0, sticky="nwes")
        scrollbar.grid(row=0, column=0, sticky="nes")


# car rides available screen
def rides_available_screen(screen_items):
    for item in screen_items:
        item.destroy()
    global right_frame
    right_frame.grid_forget()
    right_frame = ScrollableFrame(root)
    right_frame.grid(row=0, column=1, sticky=W + E + N + S)
    car_background_colors = "#ab4d33"

    img101 = ImageTk.PhotoImage(Image.open('images/101.jpg').resize((120, 75)))
    img102 = ImageTk.PhotoImage(Image.open('images/102.jpg').resize((120, 75)))
    img103 = ImageTk.PhotoImage(Image.open('images/103.jpg').resize((120, 75)))
    img104 = ImageTk.PhotoImage(Image.open('images/104.jpg').resize((120, 75)))
    img105 = ImageTk.PhotoImage(Image.open('images/105.jpg').resize((120, 75)))
    img106 = ImageTk.PhotoImage(Image.open('images/106.jpg').resize((120, 75)))
    img107 = ImageTk.PhotoImage(Image.open('images/107.jpg').resize((120, 75)))
    img108 = ImageTk.PhotoImage(Image.open('images/108.jpg').resize((120, 75)))
    img109 = ImageTk.PhotoImage(Image.open('images/109.jpg').resize((120, 75)))

    img_lst = [img101, img102, img103, img104, img105, img106, img107, img108, img109]

    page_label = Label(right_frame.scrollable_frame, text="RIDES AVAILABLE", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0, width=63)
    # placing elements on screen
    page_label.grid(row=0, column=0, columnspan=6, sticky=W + E)
    i = 1
    for key in car_id:
        image_label = Label(right_frame.scrollable_frame, image=img_lst[i - 1], bg=car_background_colors, anchor=W)
        image_label.image = img_lst[i - 1]
        text_label = Label(right_frame.scrollable_frame, text="Brand: {}\nModel: {}\nBase Fare: {}".format(
            car_id[key]["car_brand"],
            car_id[key]["car_name"],
            car_id[key]["base_fare"]), bg=car_background_colors, fg="white", anchor=W, justify=LEFT)
        image_label.grid(row=i, column=2, sticky=W + E, pady=7)
        text_label.grid(row=i, column=3, sticky=W + E + N + S, pady=7)
        i = i + 1

    global right_frame_items
    right_frame_items = [right_frame.scrollable_frame]


# updating bookings in user
# evaluating bookings for booking history
def evaluate_booking_history():
    today = date.today()
    today_date = list(map(int, today.strftime("%d/%m/%Y").split("/")))

    now_time = datetime.now().time()
    today_time = list(map(int, now_time.strftime("%H:%M").split(":")))
    today = datetime(today_date[2], today_date[1], today_date[0], today_time[0], today_time[1])

    for key in users[logged_in_user]["booking"]:
        if users[logged_in_user]["booking"][key]["status"] == 1:
            booking_date = list(map(int, users[logged_in_user]["booking"][key]["date"].split("/")))
            booking_time = list(map(int, users[logged_in_user]["booking"][key]["time"].split(":")))
            booking = datetime(booking_date[2], booking_date[1], booking_date[0], booking_time[0],
                               booking_time[1]) + timedelta(minutes=30)
            if booking <= today:
                users[logged_in_user]["booking"][key]["status"] = 0
    write_users()
    read_users()


# booking history screen
def booking_history_screen(screen_items):
    for item in screen_items:
        item.destroy()
    evaluate_booking_history()
    global right_frame
    right_frame.grid_forget()
    right_frame = ScrollableFrame(root)
    right_frame.grid(row=0, column=1, sticky=W + E + N + S)
    card_background_colors = ["#470f0f", "#294d2f"]
    img_string = "images/{}.jpg"
    page_label = Label(right_frame.scrollable_frame, text="BOOKING HISTORY", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0, width=63)
    page_label.grid(row=0, column=0, columnspan=6, sticky=W + E)
    status = ["Ride Completed", "Pending"]
    i = 1
    text_string = "Booking ID: {}\nName: {}\nFrom: {},\n           {},{},{}\nTo: {},\n           {},{},{}\nPick Up Date: {}\nPick Up Time: {}\nCar Name: {} {}\nBase Fare: {}\nPhone Number: {}\nStatus: {}"
    if len(users[logged_in_user]["booking"].keys()) != 0:
        for key in sorted(users[logged_in_user]["booking"].keys(),
                          key=lambda e: (users[logged_in_user]["booking"][e]["status"], e), reverse=True):
            img = ImageTk.PhotoImage(
                Image.open(img_string.format(users[logged_in_user]["booking"][key]["car_id"])).resize((120, 75)))
            image_label = Label(right_frame.scrollable_frame, image=img,
                                bg=card_background_colors[users[logged_in_user]["booking"][key]["status"]],
                                anchor=N + W)
            image_label.image = img
            text_label = Label(right_frame.scrollable_frame, text=text_string.format(
                key,
                users[logged_in_user]["booking"][key]["name"],
                users[logged_in_user]["booking"][key]["from"],
                users[logged_in_user]["booking"][key]["city"],
                users[logged_in_user]["booking"][key]["pincode"],
                users[logged_in_user]["booking"][key]["country"],
                users[logged_in_user]["booking"][key]["to"],
                users[logged_in_user]["booking"][key]["city"],
                users[logged_in_user]["booking"][key]["pincode"],
                users[logged_in_user]["booking"][key]["country"],
                users[logged_in_user]["booking"][key]["date"],
                users[logged_in_user]["booking"][key]["time"],
                car_id[users[logged_in_user]["booking"][key]["car_id"]]["car_brand"],
                car_id[users[logged_in_user]["booking"][key]["car_id"]]["car_name"],
                car_id[users[logged_in_user]["booking"][key]["car_id"]]["base_fare"],
                users[logged_in_user]["booking"][key]["phone_number"],
                status[users[logged_in_user]["booking"][key]["status"]]),
                               bg=card_background_colors[users[logged_in_user]["booking"][key]["status"]], fg="white",
                               anchor=W, justify=LEFT)
            image_label.grid(row=i, column=2, sticky=W + E + N + S, pady=7)
            text_label.grid(row=i, column=3, sticky=W + E + N + S, pady=7)
            i = i + 1
    else:
        no_booking_label = Label(right_frame.scrollable_frame, text="NO BOOKING HISTORY TO VIEW", bg=background_color,
                                 fg=foreground_color,
                                 bd=0, highlightthickness=0, width=63)
        no_booking_label.grid(row=i, column=0, columnspan=6, pady=100)
    global right_frame_items
    right_frame_items = [right_frame.scrollable_frame]


def validate_booking_id(booking_id):
    # checking booking id in users table
    if booking_id not in users[logged_in_user]["booking"]:
        return "Invalid Booking ID", False
    else:
        if users[logged_in_user]["booking"][booking_id]["status"] == 0:
            return "Ride Already Completed!", False
        return "valid booking id", True


# check ride canceling availability
def can_cancel_booking(booking_id):
    today = date.today()
    today_date = list(map(int, today.strftime("%d/%m/%Y").split("/")))

    now_time = datetime.now().time()
    today_time = list(map(int, now_time.strftime("%H:%M").split(":")))
    today = datetime(today_date[2], today_date[1], today_date[0], today_time[0], today_time[1])

    booking_date = list(map(int, users[logged_in_user]["booking"][booking_id]["date"].split("/")))
    booking_time = list(map(int, users[logged_in_user]["booking"][booking_id]["time"].split(":")))
    booking = datetime(booking_date[2], booking_date[1], booking_date[0], booking_time[0],
                       booking_time[1]) + timedelta(minutes=10)

    return booking > today


# canelling confirm booking
def confirm_cancel_booking():
    booking_id = right_frame_items[1].get()
    is_valid_booking_id = validate_booking_id(booking_id)

    if is_valid_booking_id[1]:
        if can_cancel_booking(booking_id):
            del users[logged_in_user]["booking"][booking_id]
            write_users()
            read_users()
            cancel_booking(right_frame_items)
        else:
            messagebox.showinfo('Information', "Times Up!\nYou can not cancel after 10 minutes of booking")
            cancel_booking(right_frame_items)
    else:
        right_frame_items[0].config(text=is_valid_booking_id[0])


# cancel booking main screen
def cancel_booking(screen_items):
    for item in screen_items:
        item.destroy()
    global right_frame
    right_frame.grid_forget()
    right_frame = ScrollableFrame(root)
    right_frame.grid(row=0, column=1, sticky=W + E + N + S)
    card_background_colors = ["#470f0f", "#294d2f"]
    img_string = "images/{}.jpg"
    page_label = Label(right_frame.scrollable_frame, text="CANCEL RIDE", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0, width=63)
    page_label.grid(row=0, column=0, columnspan=6, sticky=W + E)
    text_string = "Booking ID: {}\nName: {}\nFrom: {},\n           {},{},{}\nTo: {},\n           {},{},{}\nPick Up Date: {}\nPick Up Time: {}\nCar Name: {} {}\nBase Fare: {}\nPhone Number: {}"
    booking_id_label = Label(right_frame.scrollable_frame, text="Booking ID:", bg=background_color, fg=foreground_color,
                             bd=0, highlightthickness=0)
    booking_id_entry = Entry(right_frame.scrollable_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                             insertbackground=foreground_color, width=20)
    confirm_button = Button(right_frame.scrollable_frame, text='Confirm', bg=background_color, fg=foreground_color,
                            width=15,
                            activebackground=left_frame_background_color, activeforeground=foreground_color,
                            relief=GROOVE)
    error_label = Label(right_frame.scrollable_frame, text="", bg=background_color, fg="red",
                        bd=0, highlightthickness=0)
    instructions = """INSTRUCTIONS:
1. Fill in the Booking ID From the Given Below List.
2. You can cancel a ride with in 10 minutes of booking only."""
    instructions_label = Label(right_frame.scrollable_frame, text=instructions, bg=background_color,
                               fg=foreground_color,
                               bd=0, highlightthickness=0, anchor=W, justify=LEFT)

    booking_id_label.grid(row=1, column=0, rowspan=2, padx=10, sticky=W)
    booking_id_entry.grid(row=1, column=1, columnspan=3, rowspan=2, pady=10, padx=10, sticky=E)
    confirm_button.grid(row=1, column=5, pady=10)
    error_label.grid(row=4, column=0, columnspan=6)
    instructions_label.grid(row=5, column=0, columnspan=6, padx=20, pady=10, sticky=W)

    bookings_label = Label(right_frame.scrollable_frame, text="BOOKINGS:", bg=background_color, fg=foreground_color,
                           bd=0, highlightthickness=0)
    bookings_label.grid(row=6, column=0, columnspan=6, sticky=W, padx=10)

    today = date.today()
    today_date = list(map(int, today.strftime("%d/%m/%Y").split("/")))

    now_time = datetime.now().time()
    today_time = list(map(int, now_time.strftime("%H:%M").split(":")))
    today = datetime(today_date[2], today_date[1], today_date[0], today_time[0], today_time[1])
    card_background_colors = "#294d2f"
    img_string = "images/{}.jpg"
    i = 7
    for key in sorted(users[logged_in_user]["booking"].keys(), reverse=True):
        if users[logged_in_user]["booking"][key]["status"] == 1:
            booking_date = list(map(int, users[logged_in_user]["booking"][key]["date"].split("/")))
            booking_time = list(map(int, users[logged_in_user]["booking"][key]["time"].split(":")))
            booking = datetime(booking_date[2], booking_date[1], booking_date[0], booking_time[0],
                               booking_time[1]) + timedelta(minutes=10)
            if booking > today:
                img = ImageTk.PhotoImage(
                    Image.open(img_string.format(users[logged_in_user]["booking"][key]["car_id"])).resize((120, 75)))
                image_label = Label(right_frame.scrollable_frame, image=img,
                                    bg=card_background_colors, anchor=N + W)
                image_label.image = img
                text_label = Label(right_frame.scrollable_frame, text=text_string.format(
                    key,
                    users[logged_in_user]["booking"][key]["name"],
                    users[logged_in_user]["booking"][key]["from"],
                    users[logged_in_user]["booking"][key]["city"],
                    users[logged_in_user]["booking"][key]["pincode"],
                    users[logged_in_user]["booking"][key]["country"],
                    users[logged_in_user]["booking"][key]["to"],
                    users[logged_in_user]["booking"][key]["city"],
                    users[logged_in_user]["booking"][key]["pincode"],
                    users[logged_in_user]["booking"][key]["country"],
                    users[logged_in_user]["booking"][key]["date"],
                    users[logged_in_user]["booking"][key]["time"],
                    car_id[users[logged_in_user]["booking"][key]["car_id"]]["car_brand"],
                    car_id[users[logged_in_user]["booking"][key]["car_id"]]["car_name"],
                    car_id[users[logged_in_user]["booking"][key]["car_id"]]["base_fare"],
                    users[logged_in_user]["booking"][key]["phone_number"]), bg=card_background_colors, fg="white",
                                   anchor=W, justify=LEFT)
                image_label.grid(row=i, column=0, sticky=W + E + N + S, pady=7)
                text_label.grid(row=i, column=1, sticky=W + E + N + S, pady=7, columnspan=5)
                i = i + 1

    global right_frame_items
    right_frame_items = [error_label, booking_id_entry, right_frame.scrollable_frame]
    confirm_button.config(command=confirm_cancel_booking)


# generate booking id
def generate_booking_id():
    booking_id = 100
    if len(users[logged_in_user]["booking"].keys()) != 0:
        booking_id = int(sorted(users[logged_in_user]["booking"].keys(), reverse=True)[0])
    return str(booking_id + 1)


# return current bookings
def current_bookings():
    count = 0
    evaluate_booking_history()
    for key in users[logged_in_user]["booking"]:
        if users[logged_in_user]["booking"][key]["status"] == 1:
            count += 1
    return count


# confirming booking
def confirm_booking(city_options, car_options):
    name = right_frame_items[2].get()
    pincode = right_frame_items[4].get()
    city = city_options.get()
    country = right_frame_items[8].get()
    pick_up_from = right_frame_items[10].get()
    drop_to = right_frame_items[12].get()
    phone_number = right_frame_items[23].get()
    car_ride = car_options.get().split()[0]

    is_name_valid = validate_name(name)
    is_pincode_valid = validate_pincode(pincode, city)
    is_pick_up_from_valid = validate_pick_up(pick_up_from)
    is_drop_to_valid = validate_drop_to(drop_to)
    is_phone_number_valid = validate_phone_number(phone_number)

    if is_name_valid[1]:
        if is_pincode_valid[1]:
            if is_pick_up_from_valid[1]:
                if is_drop_to_valid[1]:
                    if is_phone_number_valid[1]:
                        if current_bookings() < 3:

                            today = date.today()
                            today_date = today.strftime("%d/%m/%Y")

                            now_time = datetime.now().time()
                            today_time = now_time.strftime("%H:%M")
                            booking_id = generate_booking_id()
                            global users
                            users[logged_in_user]["booking"][booking_id] = {
                                "booking_id": booking_id,
                                "name": name,
                                "from": pick_up_from,
                                "to": drop_to,
                                "country": country,
                                "city": city,
                                "pincode": pincode,
                                "date": today_date,
                                "time": today_time,
                                "car_id": car_ride,
                                "phone_number": phone_number,
                                "status": 1
                            }
                            write_users()
                            read_users()
                            booking_history_screen(right_frame_items)
                        else:
                            right_frame_items[19].config(text="Booking Limit exceeded!")
                    else:
                        right_frame_items[19].config(text=is_phone_number_valid[0])
                else:
                    right_frame_items[19].config(text=is_drop_to_valid[0])
            else:
                right_frame_items[19].config(text=is_pick_up_from_valid[0])
        else:
            right_frame_items[19].config(text=is_pincode_valid[0])
    else:
        right_frame_items[19].config(text=is_name_valid[0])


# car booking screen
def book_now_screen(screen_items):
    for item in screen_items:
        item.destroy()

    global right_frame
    right_frame.grid_forget()
    right_frame = Frame(root, bg=background_color)
    right_frame.grid(row=0, column=1, sticky=W + E + N + S)
    # defining widgets
    page_label = Label(right_frame, text="BOOK NOW", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0, width=63)
    name_label = Label(right_frame, text="Name:", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0)
    name_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                       insertbackground=foreground_color, width=30)
    pincode_label = Label(right_frame, text="Pincode:", bg=background_color, fg=foreground_color,
                          bd=0, highlightthickness=0)
    pincode_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                          insertbackground=foreground_color, width=30)
    city_label = Label(right_frame, text="City:", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0)
    city_options = ["Bangalore", "Mumbai", "Pune", "Hyderabad"]
    variable_city_options = StringVar()
    variable_city_options.set(city_options[0])
    city_entry = OptionMenu(right_frame, variable_city_options, *city_options)
    city_entry.config(width=15, bg=background_color, fg=foreground_color, activebackground=background_color,
                      activeforeground=foreground_color, bd=0, relief=SUNKEN)
    country_label = Label(right_frame, text="Country:", bg=background_color, fg=foreground_color,
                          bd=0, highlightthickness=0)
    country_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                          insertbackground=foreground_color, width=20)
    from_label = Label(right_frame, text="From:", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0)
    from_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                       insertbackground=foreground_color, width=30)
    to_label = Label(right_frame, text="To:", bg=background_color, fg=foreground_color,
                     bd=0, highlightthickness=0)
    to_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                     insertbackground=foreground_color, width=30)
    when_label = Label(right_frame, text="When:", bg=background_color, fg=foreground_color,
                       bd=0, highlightthickness=0)
    when_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                       insertbackground=foreground_color, width=30)
    mobile_label = Label(right_frame, text="Phone Number:", bg=background_color, fg=foreground_color,
                         bd=0, highlightthickness=0)
    mobile_entry = Entry(right_frame, borderwidth=3, bg=background_color, fg=foreground_color,
                         insertbackground=foreground_color, width=30)
    select_ride_label = Label(right_frame, text="Select Ride:", bg=background_color, fg=foreground_color,
                              bd=0, highlightthickness=0)

    car_options = ["{} {} {}".format(x, car_id[x]["car_brand"], car_id[x]["car_name"]) for x in car_id]
    variable = StringVar()
    variable.set(car_options[0])
    select_ride_combobox = OptionMenu(right_frame, variable, *car_options)
    select_ride_combobox.config(width=24, bg=background_color, fg=foreground_color, activebackground=background_color,
                                activeforeground=foreground_color, bd=0, relief=SUNKEN)
    cost_label = Label(right_frame, text="Base Cost {} + 15 per Kilometer".format(car_id["101"]["base_fare"]),
                       bg=background_color, fg="yellow",
                       bd=0, highlightthickness=0)
    instructions = """INSTRUCTIONS
1. Base Fare depends upon ride chosen.
2. Cancelling is available within 10 minutes of booking.
3. You can view your rides in BOOKING HISTORY."""
    instructions_label = Label(right_frame, text=instructions, bg=background_color, fg=foreground_color,
                               bd=0, highlightthickness=0, anchor=W, justify=LEFT)
    error_label = Label(right_frame, bg=background_color, fg="red",
                        bd=0, highlightthickness=0)
    cancel_button = Button(right_frame, text='Cancel', bg=background_color, fg=foreground_color, width=20,
                           activebackground=left_frame_background_color, activeforeground=foreground_color,
                           relief=GROOVE)
    confirm_button = Button(right_frame, text='Confirm', bg=background_color, fg=foreground_color, width=20,
                            activebackground=left_frame_background_color, activeforeground=foreground_color,
                            relief=GROOVE)
    global right_frame_items
    right_frame_items = [page_label, name_label, name_entry, pincode_label, pincode_entry,
                         city_label, city_entry, country_label, country_entry,
                         from_label, from_entry, to_label, to_entry, when_label, when_entry,
                         select_ride_label, select_ride_combobox, cost_label, instructions_label, error_label,
                         cancel_button, confirm_button, mobile_label, mobile_entry]

    def callback(*args):
        id = variable.get().split()[0]
        right_frame_items[17].configure(text="Base Cost {} + 15 per Kilometer".format(car_id[id]["base_fare"]))

    variable.trace("w", callback)
    page_label.grid(row=0, column=0, columnspan=6, sticky=W + E)
    name_label.grid(row=1, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    name_entry.grid(row=1, column=3, columnspan=3, rowspan=2, pady=10)
    pincode_label.grid(row=3, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    pincode_entry.grid(row=3, column=3, columnspan=3, rowspan=2, pady=10)
    city_label.grid(row=5, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    city_entry.grid(row=5, column=0, columnspan=3, rowspan=2, pady=10, padx=15, sticky=E)
    country_label.grid(row=5, column=3, columnspan=3, rowspan=2, padx=10, sticky=W)
    country_entry.grid(row=5, column=3, columnspan=3, rowspan=2, pady=10, padx=15, sticky=E)
    from_label.grid(row=7, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    from_entry.grid(row=7, column=3, columnspan=3, rowspan=2, pady=10)
    to_label.grid(row=9, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    to_entry.grid(row=9, column=3, columnspan=3, rowspan=2, pady=10)
    when_label.grid(row=11, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    when_entry.grid(row=11, column=3, columnspan=3, rowspan=2, pady=10)
    select_ride_label.grid(row=13, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    select_ride_combobox.grid(row=13, column=3, columnspan=3, rowspan=2, pady=10)
    mobile_label.grid(row=15, column=0, columnspan=3, rowspan=2, padx=10, sticky=W)
    mobile_entry.grid(row=15, column=3, columnspan=3, rowspan=2, pady=10)
    cost_label.grid(row=17, column=0, columnspan=6)
    instructions_label.grid(row=18, column=0, columnspan=6, pady=3, sticky=W, padx=10)
    error_label.grid(row=19, column=0, columnspan=6)
    cancel_button.grid(row=20, column=0, columnspan=3, sticky=S)
    confirm_button.grid(row=20, column=3, columnspan=3, sticky=S)
    # placing widgets on screen

    country_entry.insert(0, "INDIA")
    when_entry.insert(0, "NOW")
    # disabling the values in entry boxes
    country_entry.config(state=DISABLED, disabledbackground=background_color)
    when_entry.config(state=DISABLED, disabledbackground=background_color)

    cancel_button.config(command=lambda: book_now_screen(right_frame_items))
    confirm_button.config(command=lambda: confirm_booking(variable_city_options, variable))


# defining frames in window
def windows_frames():
    # dividing screen into two frames
    global left_frame
    global right_frame
    left_frame = LabelFrame(root, bg=left_frame_background_color, highlightbackground=background_color,
                            highlightthickness=0, bd=0)
    right_frame = Frame(root, bg=background_color)

    # positioning frames
    left_frame.grid(row=0, column=0, sticky=W)
    right_frame.grid(row=0, column=1, sticky=W + E + N + S)

    logo_image = ImageTk.PhotoImage(Image.open('images/left_frame_logo.jpg'))
    logo_label = Label(left_frame, image=logo_image, bg=left_frame_background_color, fg=foreground_color, bd=0,
                       highlightthickness=0)
    logo_label.image = logo_image
    profile_button = Button(left_frame, text='{}\n(view profile)'.format(logged_in_user),
                            bg=left_frame_background_color,
                            fg=foreground_color, height=2,
                            activebackground=background_color, activeforeground=foreground_color, relief=GROOVE)
    book_now_button = Button(left_frame, text='BOOK NOW', bg=left_frame_background_color, fg=foreground_color, height=2,
                             activebackground=background_color, activeforeground=foreground_color, relief=GROOVE)
    cancel_ride_button = Button(left_frame, text='CANCEL RIDE', bg=left_frame_background_color, fg=foreground_color,
                                height=2,
                                activebackground=background_color, activeforeground=foreground_color, relief=GROOVE)
    booking_history_button = Button(left_frame, text='BOOKING HISTORY', bg=left_frame_background_color,
                                    fg=foreground_color, height=2,
                                    activebackground=background_color, activeforeground=foreground_color, relief=GROOVE)
    rides_available_button = Button(left_frame, text='RIDES AVAILABLE', bg=left_frame_background_color,
                                    fg=foreground_color, height=2,
                                    activebackground=background_color, activeforeground=foreground_color, relief=GROOVE)

    info_image = ImageTk.PhotoImage(Image.open('images/left_frame_info.jpg'))
    info_label = Label(left_frame, image=info_image, bg=left_frame_background_color, fg=foreground_color,
                       highlightbackground=background_color, highlightthickness=0, bd=0)
    info_label.image = info_image
    # placing buttons left screen
    logo_label.grid(row=0, column=0)
    profile_button.grid(row=1, column=0, sticky=W + E)
    book_now_button.grid(row=2, column=0, sticky=W + E)
    cancel_ride_button.grid(row=3, column=0, sticky=W + E)
    booking_history_button.grid(row=4, column=0, sticky=W + E)
    rides_available_button.grid(row=5, column=0, sticky=W + E)

    info_label.grid(row=6, column=0)

    # assign on click action on buttons
    profile_button.config(command=lambda: user_profile_screen(right_frame_items))
    rides_available_button.config(command=lambda: rides_available_screen(right_frame_items))
    book_now_button.config(command=lambda: book_now_screen(right_frame_items))
    booking_history_button.config(command=lambda: booking_history_screen(right_frame_items))
    cancel_ride_button.config(command=lambda: cancel_booking(right_frame_items))
    book_now_screen([])


# after login screen
def after_login_screen(screen_items):
    # clearing screen items
    for item in screen_items:
        item.destroy()
    root.geometry("600x500")
    read_users()
    read_car_id()
    windows_frames()


# canel warning for forget password screen
def cancel_warning_forgot_password():
    confirm_cancel = messagebox.askquestion('Confirmation', 'Are you sure you want to cancel',
                                            icon='info')
    # go to login screen if yes
    if confirm_cancel == 'yes':
        welcome_screen_login(forgot_password_screen_items)


# sending otp in vai mail function
def send_otp(original_otp, receiver_mail, mail_option):
    # atarting server connection
    server = smtplib.SMTP_SSL("smtp.gmail.com", 465)
    server.ehlo()
    server.login("pythoncabproject@gmail.com", "Code@1234")
    # message options depending upon which email to sent
    msg_options = ["account generation", "Password Recovery", "Booking Cab", "Cancelling Cab"]
    mail_message = """Your OTP for {} is {}""".format(msg_options[mail_option], original_otp)
    mail_message = 'Subject: {}\n\n{}'.format("OTP", mail_message)
    # sending mail
    server.sendmail("pythoncabproject@gmail.com", receiver_mail, mail_message)
    server.quit()


# for checking otp enter is correct or not for sign up screen
def confirm_otp(original_otp, otp_input):
    global otp_count
    is_otp_valid = validate_otp(original_otp, otp_input)
    # only three attempts are allowed
    if otp_count < 3:
        # otp is correct
        if is_otp_valid[1]:
            messagebox.showinfo('Information', """Authentication Confirmed! 
You'll be redirected to Log In""")
            otp_count = 0
            # write data to file
            global users
            users[sign_up_screen_items[6].get()] = {
                "username": sign_up_screen_items[6].get(),
                "name": sign_up_screen_items[7].get(),
                "email": sign_up_screen_items[8].get(),
                "password": sign_up_screen_items[9].get(),
                "booking": {}
            }
            write_users()
            # redirecting to login screen
            welcome_screen_login(sign_up_screen_items)

        else:
            # checking count will increases only if invalid otp is entered
            if is_otp_valid[0] == "Invalid OTP!":
                otp_count += 1
            sign_up_screen_items[13].config(text=is_otp_valid[0])
    # otp count exceeded
    else:
        messagebox.showinfo('Information', "Too many attempts. You'll be redirected to Log In")
        otp_count = 0
        # redirecting to login screen
        welcome_screen_login(sign_up_screen_items)


# confirm forgot password otp
def confirm_otp_forgot_password(original_otp, otp_input):
    global otp_count
    is_otp_valid = validate_otp(original_otp, otp_input)
    # only three attempts are allowed
    if otp_count < 3:
        # otp is correct
        if is_otp_valid[1]:
            messagebox.showinfo('Information', """Authentication Confirmed! 
You'll be redirected to Log In""")
            otp_count = 0
            # updating and writing data to file
            global users
            users[forgot_password_screen_items[4].get()]['password'] = forgot_password_screen_items[5].get()
            write_users()
            # redirecting to login screen
            welcome_screen_login(forgot_password_screen_items)

        else:
            # checking count will increases only if invalid otp is entered
            if is_otp_valid[0] == "Invalid OTP!":
                otp_count += 1
            forgot_password_screen_items[7].config(text=is_otp_valid[0])
    # otp count exceeded
    else:
        messagebox.showinfo('Information', "Too many attempts. You'll be redirected to Log In")
        otp_count = 0
        # redirecting to login screen
        welcome_screen_login(forgot_password_screen_items)


# forgot password checker
def forgot_password_confirm():
    # checking internet connection
    if not check_internet_socket():
        messagebox.showinfo('Information', """Please Connect To Internet!""")
        no_internet(forgot_password_screen_items)
    else:
        # obataing values
        username = forgot_password_screen_items[4].get()
        password = forgot_password_screen_items[5].get()
        confirm_password = forgot_password_screen_items[6].get()
        # validating values
        is_valid_username = validate_username(username)
        is_valid_password = validate_password(password, confirm_password)
        if is_valid_username[1]:
            if username in users:
                if is_valid_password[1]:
                    # resizing window
                    root.geometry("300x245")
                    # disabling all other options
                    forgot_password_screen_items[4].config(state=DISABLED, disabledbackground=background_color)
                    forgot_password_screen_items[5].config(state=DISABLED, disabledbackground=background_color)
                    forgot_password_screen_items[6].config(state=DISABLED, disabledbackground=background_color)
                    # enabling otp widgets
                    otp_label = Label(root, text='Enter OTP:', bg=background_color, fg=foreground_color)
                    otp_entry = Entry(root, borderwidth=3, bg=background_color, fg=foreground_color,
                                      insertbackground=foreground_color, width=25)
                    otp_label.grid(row=7, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
                    otp_entry.grid(row=7, column=2, columnspan=2, rowspan=2, pady=10)
                    # append widgets created on forgot screen
                    forgot_password_screen_items.append(otp_label)
                    forgot_password_screen_items.append(otp_entry)
                    forgot_password_screen_items[7].config(text="An OTP is sent to your respective mail")
                    forgot_password_screen_items[7].grid(row=9, column=0, columnspan=4)
                    # otp confirmation
                    global otp
                    otp = generate_otp()
                    forgot_password_screen_items[9].config(command=lambda: confirm_otp_forgot_password(otp,
                                                                                                       otp_entry.get()))
                    send_otp(otp, users[username]['email'], 1)
                else:
                    root.geometry("300x205")
                    forgot_password_screen_items[7].config(text=is_valid_password[0])
                    forgot_password_screen_items[7].grid(row=9, column=0, columnspan=4)
            else:
                root.geometry("300x205")
                forgot_password_screen_items[7].config(text="Username does not exists")
                forgot_password_screen_items[7].grid(row=9, column=0, columnspan=4)
        else:
            root.geometry("300x205")
            forgot_password_screen_items[7].config(text=is_valid_username[0])
            forgot_password_screen_items[7].grid(row=9, column=0, columnspan=4)


# main forgot password screen function
def forgot_password():
    # intializing forget screen widgets
    page_label = Label(root, text='Forget Password', bg=background_color, fg=foreground_color)
    username_label = Label(root, text='Username:', bg=background_color, fg=foreground_color)
    password_label = Label(root, text='New Password:', bg=background_color, fg=foreground_color)
    confirm_password_label = Label(root, text='Confirm Password:', bg=background_color, fg=foreground_color)
    username_entry = Entry(root, borderwidth=3, bg=background_color, fg=foreground_color,
                           insertbackground=foreground_color, width=25)
    password_entry = Entry(root, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                           insertbackground=foreground_color, width=25)
    confirm_password_entry = Entry(root, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                                   insertbackground=foreground_color, width=25)
    error_label = Label(root, text='Error Message', bg=background_color, fg="#FF0000")
    cancel_button = Button(root, text='Cancel', bg=background_color, fg=foreground_color, width=10,
                           activebackground=left_frame_background_color, activeforeground=foreground_color,
                           relief=GROOVE)
    confirm_button = Button(root, text='Confirm', bg=background_color, fg=foreground_color, width=10,
                            activebackground=left_frame_background_color, activeforeground=foreground_color,
                            relief=GROOVE)

    global forgot_password_screen_items
    forgot_password_screen_items = [page_label, username_label, password_label,
                                    confirm_password_label, username_entry,
                                    password_entry, confirm_password_entry, error_label,
                                    cancel_button, confirm_button]
    # placing elements on screen
    page_label.grid(row=0, column=0, columnspan=4)
    username_label.grid(row=1, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    username_entry.grid(row=1, column=2, columnspan=2, rowspan=2, pady=10)
    password_label.grid(row=3, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    password_entry.grid(row=3, column=2, columnspan=2, rowspan=2, pady=10)
    confirm_password_label.grid(row=5, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    confirm_password_entry.grid(row=5, column=2, columnspan=2, rowspan=2, pady=10)
    # by default invisible so as a comment
    # error_label.grid(row=9, column=0, columnspan=4)

    cancel_button.grid(row=14, column=0, padx=6, columnspan=3)
    confirm_button.grid(row=14, column=3, padx=6)

    # creating on click event on buttons
    cancel_button.config(command=lambda: welcome_screen_login(forgot_password_screen_items))
    confirm_button.config(command=forgot_password_confirm)


# forgot password screen function
def forgot_password_screen():
    # clearing objects of previous screen
    root.geometry("300x185")
    for item in login_screen_items:
        item.destroy()
    forgot_password()


# canel warning for sign up screen
def cancel_warning_sign_up():
    confirm_cancel = messagebox.askquestion('Confirmation', 'Are you sure you want to cancel Sign Up process',
                                            icon='info')
    if confirm_cancel == 'yes':
        # redirecting to login screen
        welcome_screen_login(sign_up_screen_items)


# login click function
def login_to_id():
    global login_status
    global logged_in_user
    # checking internet connection
    # getting input field values
    username = login_screen_items[3].get()
    password = login_screen_items[4].get()

    # validating input field values
    is_username_valid = validate_username(username)
    is_password_valid = validate_login_password(password)
    if (is_username_valid[1]):
        # check username in database and validate
        if (is_password_valid[1]):
            # check username in database and validate
            if username in users:
                if users[username]["password"] == password:
                    login_status = True
                    logged_in_user = username
                    evaluate_booking_history()
                    after_login_screen(login_screen_items)
                else:
                    root.geometry("300x165")
                    login_screen_items[8].config(text="Incorrect Password")
                    login_screen_items[8].grid(row=5, column=0, columnspan=4)
            else:
                root.geometry("300x165")
                login_screen_items[8].config(text="Username does not exists")
                login_screen_items[8].grid(row=5, column=0, columnspan=4)
        else:
            root.geometry("300x165")
            login_screen_items[8].config(text=is_password_valid[0])
            login_screen_items[8].grid(row=5, column=0, columnspan=4)
    else:
        root.geometry("300x165")
        login_screen_items[8].config(text=is_username_valid[0])
        login_screen_items[8].grid(row=5, column=0, columnspan=4)


# sign to id function
def sign_up_to_id():
    # checking internet connection
    if not check_internet_socket():
        messagebox.showinfo('Information', """Please Connect To Internet!""")
        no_internet(sign_up_screen_items)
    else:
        # getting input field values
        username = sign_up_screen_items[6].get()
        name = sign_up_screen_items[7].get()
        email = sign_up_screen_items[8].get()
        password = sign_up_screen_items[9].get()
        confirm_password = sign_up_screen_items[10].get()

        # validating input filed values
        is_username_valid = validate_username(username)
        is_name_valid = validate_name(name)
        is_email_valid = validate_email(email)
        is_password_valid = validate_password(password, confirm_password)

        if is_username_valid[1]:
            # check if user already exists or not
            if username not in users:
                if is_name_valid[1]:
                    if is_email_valid[1]:
                        # check if email already exists or not
                        user_mails = [users[x]['email'] for x in users]
                        if email not in user_mails:
                            if is_password_valid[1]:
                                root.geometry("300x330")
                                # here we call otp valid and if that return true than append data to list
                                # diabling all other widgets
                                sign_up_screen_items[6].config(state=DISABLED, disabledbackground=background_color)
                                sign_up_screen_items[7].config(state=DISABLED, disabledbackground=background_color)
                                sign_up_screen_items[8].config(state=DISABLED, disabledbackground=background_color)
                                sign_up_screen_items[9].config(state=DISABLED, disabledbackground=background_color)
                                sign_up_screen_items[10].config(state=DISABLED, disabledbackground=background_color)
                                sign_up_screen_items[13].config(text="An OTP is sent to your respective mail")
                                # making otp widgets
                                otp_label = Label(root, text='Enter OTP:', bg=background_color, fg=foreground_color)
                                otp_entry = Entry(root, borderwidth=3, bg=background_color, fg=foreground_color,
                                                  insertbackground=foreground_color, width=25)
                                sign_up_screen_items.append(otp_label)
                                sign_up_screen_items.append(otp_entry)
                                # placing otp widgets
                                global otp
                                otp = generate_otp()
                                otp_label.grid(row=11, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
                                otp_entry.grid(row=11, column=2, columnspan=2, rowspan=2, pady=10)
                                sign_up_screen_items[13].grid(row=13, column=0, columnspan=4)
                                sign_up_screen_items[12].config(text="Confirm",
                                                                command=lambda: confirm_otp(otp, otp_entry.get()))
                                sign_up_screen_items[11].config(text="Cancel", command=cancel_warning_sign_up)

                                send_otp(otp, email, 0)

                            else:
                                root.geometry("300x290")
                                sign_up_screen_items[13].config(text=is_password_valid[0])
                                sign_up_screen_items[13].grid(row=13, column=0, columnspan=4)
                        else:
                            root.geometry("300x290")
                            sign_up_screen_items[13].config(text="Account already exists with given email")
                            sign_up_screen_items[13].grid(row=13, column=0, columnspan=4)
                    else:
                        root.geometry("300x290")
                        sign_up_screen_items[13].config(text=is_email_valid[0])
                        sign_up_screen_items[13].grid(row=13, column=0, columnspan=4)
                else:
                    root.geometry("300x290")
                    sign_up_screen_items[13].config(text=is_name_valid[0])
                    sign_up_screen_items[13].grid(row=13, column=0, columnspan=4)
            else:
                root.geometry("300x290")
                sign_up_screen_items[13].config(text="Username already Exists! Try Different Username")
                sign_up_screen_items[13].grid(row=13, column=0, columnspan=4)
        else:
            root.geometry("300x290")
            sign_up_screen_items[13].config(text=is_username_valid[0])
            sign_up_screen_items[13].grid(row=13, column=0, columnspan=4)


# login function
def login():
    read_users()
    write_users()
    # creating widgets of loginScreen
    page_label = Label(root, text='Log In', bg=background_color, fg=foreground_color)
    username_label = Label(root, text='Username:', bg=background_color, fg=foreground_color)
    password_label = Label(root, text='Password:', bg=background_color, fg=foreground_color)
    username_entry = Entry(root, borderwidth=3, bg=background_color, fg=foreground_color,
                           insertbackground=foreground_color, width=25)
    password_entry = Entry(root, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                           insertbackground=foreground_color, width=25)
    forgot_password_button = Button(root, text='Forgot Password', bg=background_color, fg=foreground_color,
                                    activebackground=left_frame_background_color,
                                    activeforeground=foreground_color, relief=GROOVE)
    login_button = Button(root, text='Log In', bg=background_color, fg=foreground_color, width=10,
                          activebackground=left_frame_background_color, activeforeground=foreground_color,
                          relief=GROOVE)
    sign_up_button = Button(root, text='Sign Up', bg=background_color, fg=foreground_color, width=10,
                            activebackground=left_frame_background_color, activeforeground=foreground_color,
                            relief=GROOVE)
    error_label = Label(root, text='Error Message', bg=background_color, fg="#FF0000")

    global login_screen_items
    login_screen_items = [page_label, username_label, password_label,
                          username_entry, password_entry, forgot_password_button,
                          login_button, sign_up_button, error_label]
    # placing elements on login screen
    page_label.grid(row=0, column=0, columnspan=4)
    username_label.grid(row=1, column=0, columnspan=2, rowspan=2, padx=10)
    username_entry.grid(row=1, column=2, columnspan=2, rowspan=2, pady=10)
    password_label.grid(row=3, column=0, columnspan=2, rowspan=2, padx=10)
    password_entry.grid(row=3, column=2, columnspan=2, rowspan=2, pady=10)
    # by default invisible so as a comment
    # error_label.grid(row=5, column=0, columnspan=4)
    forgot_password_button.grid(row=6, column=0, columnspan=2, padx=6, pady=7)
    login_button.grid(row=6, column=2, padx=6)
    sign_up_button.grid(row=6, column=3, padx=6)

    # adding on click event to function
    login_button.config(command=login_to_id)
    sign_up_button.config(command=lambda: welcome_screen_sign_up(login_screen_items))
    forgot_password_button.config(command=forgot_password_screen)


# sign up function
def sign_up():
    # creating widgets of loginScreen
    page_label = Label(root, text='Sign Up', bg=background_color, fg=foreground_color)
    username_label = Label(root, text='Username:', bg=background_color, fg=foreground_color)
    name_label = Label(root, text='Name:', bg=background_color, fg=foreground_color)
    email_label = Label(root, text='Email:', bg=background_color, fg=foreground_color)
    password_label = Label(root, text='Password:', bg=background_color, fg=foreground_color)
    confirm_password_label = Label(root, text='Confirm Password:', bg=background_color, fg=foreground_color)
    username_entry = Entry(root, borderwidth=3, bg=background_color, fg=foreground_color,
                           insertbackground=foreground_color, width=25)
    name_entry = Entry(root, borderwidth=3, bg=background_color, fg=foreground_color,
                       insertbackground=foreground_color, width=25)
    email_entry = Entry(root, borderwidth=3, bg=background_color, fg=foreground_color,
                        insertbackground=foreground_color, width=25)
    password_entry = Entry(root, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                           insertbackground=foreground_color, width=25)
    confirm_password_entry = Entry(root, show="*", borderwidth=3, bg=background_color, fg=foreground_color,
                                   insertbackground=foreground_color, width=25)
    login_button = Button(root, text='Log In', bg=background_color, fg=foreground_color, width=10,
                          activebackground=left_frame_background_color, activeforeground=foreground_color,
                          relief=GROOVE)
    sign_up_button = Button(root, text='Sign Up', bg=background_color, fg=foreground_color, width=10,
                            activebackground=left_frame_background_color, activeforeground=foreground_color,
                            relief=GROOVE)
    error_label = Label(root, text='Error Message', bg=background_color, fg="#FF0000")

    global sign_up_screen_items
    sign_up_screen_items = [page_label, username_label, name_label, email_label,
                            password_label, confirm_password_label, username_entry,
                            name_entry, email_entry, password_entry, confirm_password_entry,
                            login_button, sign_up_button, error_label]

    # placing elements on login screen
    page_label.grid(row=0, column=0, columnspan=4)
    username_label.grid(row=1, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    username_entry.grid(row=1, column=2, columnspan=2, rowspan=2, pady=10)
    name_label.grid(row=3, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    name_entry.grid(row=3, column=2, columnspan=2, rowspan=2, pady=10)
    email_label.grid(row=5, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    email_entry.grid(row=5, column=2, columnspan=2, rowspan=2, pady=10)
    password_label.grid(row=7, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    password_entry.grid(row=7, column=2, columnspan=2, rowspan=2, pady=10)
    confirm_password_label.grid(row=9, column=0, columnspan=2, rowspan=2, padx=10, sticky=W)
    confirm_password_entry.grid(row=9, column=2, columnspan=2, rowspan=2, pady=10)
    # by default invisible so as a comment
    # error_label.grid(row=11, column=0, columnspan=4)

    login_button.grid(row=14, column=0, padx=6, columnspan=3)
    sign_up_button.grid(row=14, column=3, padx=6)

    # adding on click event to function
    login_button.config(command=lambda: welcome_screen_login(sign_up_screen_items))
    sign_up_button.config(command=sign_up_to_id)


# login function screen
def welcome_screen_login(screen_items):
    # clearing widgets of previous screen
    root.geometry("300x155")
    for item in screen_items:
        item.destroy()
    login()


# signup screen function
def welcome_screen_sign_up(screen_items):
    # clearing widgets of previous screen
    root.geometry("300x270")
    for item in screen_items:
        item.destroy()
    sign_up()


# welcome screen function
def welcome_screen_window(screen_items):
    for item in screen_items:
        item.destroy()

    # setting the main window size to fix size
    root.geometry("400x205")

    # top label with all text and logo
    welcome_image = ImageTk.PhotoImage(Image.open('images/welcome_screen_image.png'))

    # creating widgets to be placed on main screen
    welcome_label = Label(root, image=welcome_image, bg=background_color)
    welcome_label.image = welcome_image
    welcome_login_button = Button(root, text='Log In', bg=background_color, fg=foreground_color, width=10,
                                  activebackground=left_frame_background_color,
                                  activeforeground=foreground_color, relief=GROOVE)
    welcome_sign_up_button = Button(root, text='Sign Up', bg=background_color, fg=foreground_color, width=10,
                                    activebackground=left_frame_background_color, activeforeground=foreground_color,
                                    relief=GROOVE)

    # list to be used later on to clear widgets
    global welcome_screen_items
    welcome_screen_items = [welcome_label, welcome_login_button, welcome_sign_up_button]

    # adding on click event to buttons
    welcome_login_button.config(command=lambda: welcome_screen_login(welcome_screen_items))
    welcome_sign_up_button.config(command=lambda: welcome_screen_sign_up(welcome_screen_items))

    # placing widgets on main screen
    welcome_label.grid(row=0, column=0, columnspan=3)
    welcome_login_button.grid(row=1, column=0, columnspan=3, padx=100, sticky=W)
    welcome_sign_up_button.grid(row=1, column=0, columnspan=3, padx=100, sticky=E)


# execution will start from here
if __name__ == "__main__":
    # reading data files
    read_car_id()
    read_users()

    # setting login status to false in start
    login_status = False

    # creating main window
    root = Tk()
    root.title("Flash Cabs")
    root.configure(bg=background_color)

    # restricting resize of window
    root.resizable(0, 0)
    root.iconbitmap('images/logo.ico')

    # calling welcome screen function
    welcome_screen_window([])

    root.mainloop()
