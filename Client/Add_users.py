import ssl
import threading
import tkinter
from tkinter import *
from PIL import Image, ImageTk


class Register(tkinter.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.geometry('400x400+500+200')
        self.canvas = Canvas(self, width=self.winfo_screenwidth(), height=self.winfo_screenheight())
        self.resizable(width=False, height=False)
        self.canvas.pack(fill='both', expand=True)
        self.title('Register')
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.wm_iconbitmap('Photos/bug.ico')
        self.button_presses = 0
        self.create_gui()


    def create_gui(self):
        text_font='Comic Sans MS'
        #Background(canvas)
        self.bg_image = ImageTk.PhotoImage(Image.open("Photos/background.jpg"))
        self.bg_item = self.canvas.create_image(0, 0, image=self.bg_image, anchor='nw')
        self.canvas.tag_lower(self.bg_item)

        #Buttons
        self.close_button = Button(self, text='Close', command=self.close, font=(text_font, 14))
        self.close_button.place(relx=0.12, rely=0.98, anchor='s')
        self.btn_register = Button(self, text='Register', font=(text_font, 14), command=self.handle_add_user)
        self.btn_register.place(relx=0.68, rely=0.8, anchor='center')

        #Labales
        self.lbl_email = self.canvas.create_text(121, 80, text="Email: ", font=(text_font, 17), fill="white")
        self.lbl_password = self.canvas.create_text(107, 155, text="Password: ", font=(text_font, 17), fill="white")
        self.lbl_firstname = self.canvas.create_text(102, 230, text="First name: ", font=(text_font, 17), fill="white")

        #Entries
        self.email = Entry(self, width=30)
        self.email.place(x=185, y=73)
        self.password = Entry(self, width=30)
        self.password.place(x=185, y=148)
        self.firstname = Entry(self, width=30)
        self.firstname.place(x=185, y=223)

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
        except ConnectionResetError:
            print("Connection was reset by the remote host.")
            return None
        except OSError as e:
            print(f"OS error occurred: {e}")
            return None

    def check_email_exists(self, email):
        self.send_message(self.parent.client_socket, f"check_email_exists,{email}")
        email_exists = self.receive_message(self.parent.client_socket)
        return email_exists == "True"

    def handle_add_user(self):
        self.button_presses += 1
        if self.button_presses >= 10:
            self.btn_register.config(state=DISABLED)
        self.canvas.delete("error_message")
        error_messages = []

        if len(self.email.get()) == 0:
            error_messages.append(("Missing email.", 117))
        elif self.email.get().find(",") != -1:
            error_messages.append(("Email cannot contain a comma", 117))
        elif len(self.email.get()) > 50:
            error_messages.append(("Email too long", 117))
        elif self.check_email_exists(self.email.get()):
            error_messages.append(("Email already in use.", 117))

        if len(self.password.get()) == 0:
            error_messages.append(("Missing password.", 191))
        elif self.password.get().find(",") != -1:
            error_messages.append(("Password cannot contain a comma", 191))
        elif len(self.password.get()) > 50:
            error_messages.append(("Password too long", 191))

        if len(self.firstname.get()) == 0:
            error_messages.append(("Missing firstname.", 262))
        elif self.firstname.get().find(",") != -1:
            error_messages.append(("First name cannot contain a comma", 262))
        elif len(self.firstname.get()) > 27:
            error_messages.append(("Name too long", 262))

        if error_messages:
            for error, y in error_messages:
                self.canvas.create_text(250, y, text=error, fill="red", tags="error_message")
        else:
            self.client_handler = threading.Thread(target=self.register_user, args=())
            self.client_handler.daemon = True
            self.client_handler.start()

    def register_user(self):
        print("register")
        arr = ["register", self.email.get(), self.password.get(), self.firstname.get()]
        str_insert = ",".join(arr)
        self.send_message(self.parent.client_socket, str_insert)
        data = self.receive_message(self.parent.client_socket)
        print(data)
        if data == "success register":
            self.canvas.create_text(268, 273, text="Success registration", fill="#50C878", font=("Comic Sans MS", 16),
                                    tags="success_message")
            self.after(3000, self.hide_text)

    def hide_text(self):
        self.canvas.delete("success_message")

    def close(self):
        try:
            self.parent.deiconify()
            self.destroy()
        except AttributeError:
            pass
