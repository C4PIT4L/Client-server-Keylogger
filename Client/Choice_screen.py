import logging
import socket
import ssl
import threading
import tkinter
from tkinter import *
from PIL import Image, ImageTk
from speed_writing_test import Speed_writing_test
from Project.Client.avrage_statistics import AverageStatisticsWindow
from Keylogger import Keylogger_SCREEN
from KeyloggerHistory import KeystrokesHistory



class HomeScreen(tkinter.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.handle_thread_socket()
        self.parent = parent
        self.geometry("1920x1080")
        self.canvas = Canvas(self, width=self.winfo_screenwidth(), height=self.winfo_screenheight())
        self.resizable(width=False, height=False)
        self.protocol("WM_DELETE_WINDOW", self.close_window)
        self.canvas.pack(fill='both', expand=True)
        self.title('Home')
        self.wm_iconbitmap('Photos/bug.ico')
        self.create_gui()

    def create_gui(self):
        text_font='Comic Sans MS'
        # Set background image
        self.bg_image = ImageTk.PhotoImage(Image.open("Photos/background.jpg"))
        self.bg_item = self.canvas.create_image(0, 0, image=self.bg_image, anchor='nw')
        self.canvas.tag_lower(self.bg_item)

        # Create welcome label
        self.user_name_label = Label(self, text="Welcome", font=("Future Z", 35), bg="#FFD4D4")
        self.user_name_label.place(relx=0.485, rely=0.1, anchor='n')

        # Create arrow images
        self.image_arrow = PhotoImage(file='Photos/arrow_pointing_down-removebg-preview.png')
        self.canvas.create_image(1150, 700, image=self.image_arrow)
        self.image_arrow_2 = PhotoImage(file='Photos/arrow_pointing_down-removebg-preview.png')
        self.canvas.create_image(770, 700, image=self.image_arrow_2)

        # Create question label
        self.question = self.canvas.create_text(950, 500, text="choose your destiny", font=(text_font, 30),fill="#000000")

        # Create close button
        self.close_button = Button(self, text='Log in as someone else', command=self.close, font=(text_font, 15))
        self.close_button.place(relx=0.5, rely=0.9, anchor='s')

        # Create buttons for different functions
        self.image = PhotoImage(file='Photos/NewLogo.png')
        self.open_test = Button(self, text='Speed writing test', command=self.open_speed_writing_test,font=(text_font, 15))
        self.open_test.place(relx=0.6, rely=0.578, anchor='s')
        self.open_statistics = Button(self, text='statistics', command=self.open_avrage_statistics,font=(text_font, 15))
        self.open_statistics.place(relx=0.6, rely=0.79, anchor='s')
        self.open_keylogger = Button(self, text='Key logger', command=self.open_key_logger, font=(text_font, 15))
        self.open_keylogger.place(relx=0.4, rely=0.578, anchor='s')
        self.open_history = Button(self, text='History', command=self.open_keylogger_history,font=(text_font, 15))
        self.open_history.place(relx=0.4, rely=0.79, anchor='s')

        # Create logo.png image
        self.canvas.create_image(950, 330, image=self.image)

        # Update user name label
        self.update_user_name()

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

    @staticmethod
    def receive_message(client_socket):
        try:
            message_length_header = client_socket.recv(4)
        except socket.error as e:
            print("Socket error occurred while receiving message length header:", e)
            return ''

        if not message_length_header:
            return ''
        try:
            message_length = int.from_bytes(message_length_header, 'big')
        except ValueError:
            print(f"Error: Received invalid message length header: '{message_length_header}'")
            return ''
        message = b''
        bytes_received = 0
        while bytes_received < message_length:
            bytes_to_receive = min(1024, message_length - bytes_received)
            chunk = client_socket.recv(bytes_to_receive)
            if not chunk:
                break
            message += chunk
            bytes_received += len(chunk)
        return message.decode('utf-8')

    def update_user_name(self):
        self.send_message(self.client_socket, "get_username")
        display_username = self.receive_message(self.client_socket)
        if display_username:
            self.user_name_label.config(text=f"Welcome {display_username}!")
        else:
            self.user_name_label.config(text="Welcome User!")

    def create_socket(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            self.client_socket = context.wrap_socket(self.client_socket)
            self.client_socket.connect(('10.100.102.18', 8042))
            try:
                data = self.receive_message(self.client_socket)
                print(data)
            except Exception as e:
                print("Error receiving initial message from server:", e)
            print("hi", self.client_socket)
        except ConnectionRefusedError:
            print("Error: Could not connect to the server")
            logging.warning('A client without a server is not a good combination')
        except ssl.SSLError as e:
            print("SSL error occurred:", e)
        except socket.error as e:
            print("Socket error occurred:", e)
        except Exception as e:
            print("An unexpected error occurred:", e)

    def handle_thread_socket(self):
        client_handler = threading.Thread(target=self.create_socket, args=())
        client_handler.daemon = True
        client_handler.start()

    def open_speed_writing_test(self):
        current_user_id = self.get_current_user_id_from_server()
        window = Speed_writing_test(self, current_user_id)
        window.grab_set()
        self.withdraw()

    def open_keylogger_history(self):
        current_user_id = self.get_current_user_id_from_server()
        log_file_path = '../Logs/keystrokes.log'
        window = KeystrokesHistory(self, current_user_id, log_file_path)
        window.grab_set()
        self.withdraw()

    def open_key_logger(self):
        current_user_id = self.get_current_user_id_from_server()
        window = Keylogger_SCREEN(self, current_user_id)
        window.grab_set()
        self.withdraw()

    def open_avrage_statistics(self):
        current_user_id = self.get_current_user_id_from_server()
        window = AverageStatisticsWindow(self, current_user_id)
        window.grab_set()
        self.withdraw()

    def get_current_user_id_from_server(self):
        self.send_message(self.parent.client_socket, "get_current_user_id")
        user_id = self.receive_message(self.parent.client_socket)
        return user_id

    def close(self):
        self.parent.deiconify()
        self.destroy()

    def close_window(self):
        try:
            self.client_socket.close()
        except AttributeError:
            pass
        finally:
            try:
                self.parent.destroy()
                self.destroy()
            except tkinter.TclError:
                pass
