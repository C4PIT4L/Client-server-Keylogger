import re
import ssl
import threading
import tkinter
from tkinter import *
import socket
from PIL import Image, ImageTk
from Project.Client.Add_users import Register
from Project.Client.Choice_screen import HomeScreen
from the_creator import Creator
import logging
from Minigame import minigame



class Login_register(tkinter.Tk):
    def __init__(self):
        super().__init__()
        self.handle_thread_socket()
        self.geometry("700x700+500+100")
        self.canvas = Canvas(self, width=self.winfo_screenwidth(), height=self.winfo_screenheight())
        self.resizable(width=False, height=False)
        self.canvas.pack(fill='both', expand=True)
        self.title('Login')
        self.wm_iconbitmap('Photos/bug.ico')
        self.home_screen = None
        self.ip_attempts = {}
        self.protocol("WM_DELETE_WINDOW", self.close_window)
        self.create_gui()
        self.reset_time = 3000
        logging.basicConfig(filename='../Logs/login_system.log', level=logging.INFO, format='%(asctime)s:%(levelname)s:%(message)s')

    def create_gui(self):
        text_font='Comic Sans MS'

        # Background image
        self.bg_image = ImageTk.PhotoImage(Image.open("Photos/background.jpg"))
        self.bg_item = self.canvas.create_image(0, 0, image=self.bg_image, anchor='nw')
        self.canvas.tag_lower(self.bg_item)

        # Register,creator and minigame buttons
        self.btn_register = Button(self, text='Register',font=(text_font, 15), command=self.open_register)
        self.btn_register.place(relx=0.25, rely=0.93, anchor='center')
        self.btn_creator = Button(self, text="About", font=(text_font, 15), command=self.open_creator)
        self.btn_creator.place(relx=0.82, rely=0.93, anchor='center')
        self.btn_minigame = Button(self, text="Mini Game", font=(text_font, 15), command=self.open_minigame)
        self.btn_minigame.place(relx=0.52, rely=0.93, anchor='center')

        # Email label and entry
        self.email_label = self.canvas.create_text(166, 385, text="Email: ", font=(text_font, 20), fill="#270042")
        self.entry_email = Entry(self, font=(text_font, 17))
        self.entry_email.place(relx=0.52, rely=0.55, anchor='center')

        # Password label and entry
        self.password_label = self.canvas.create_text(150, 453, text="Password: ", font=(text_font, 20),fill="#270042")
        self.entry_password = Entry(self, font=(text_font, 17), show="*")
        self.entry_password.place(relx=0.52, rely=0.65, anchor='center')

        # Login button
        self.textvar = StringVar(self, "Log in")
        self.btn_login = Button(self, textvariable=self.textvar, font=(text_font, 15), command=self.login_user)
        self.btn_login.place(relx=0.52, rely=0.76, anchor='center')

        # Logo image
        self.image = PhotoImage(file='Photos/NewLogo.png')
        self.canvas.create_image(364, 174, image=self.image)

        # Update canvas
        self.canvas.update()

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

    def open_register(self):
        window = Register(self)
        window.grab_set()
        self.withdraw()

    def open_creator(self):
        window = Creator(self)
        window.grab_set()
        self.withdraw()

    def open_minigame(self):
        window = minigame(self)
        window.grab_set()
        self.withdraw()

    def open_home_screen(self):
        self.home_screen = HomeScreen(self)
        self.home_screen.update_user_name()
        self.withdraw()
        self.home_screen.grab_set()

    @staticmethod
    def sanitize_input(input_str):
        input_str = re.sub(r'[^\w\s.@-]', '', input_str)
        return input_str.strip()

    def login_user(self):
        try:
            email = self.sanitize_input(self.entry_email.get())
            password = self.sanitize_input(self.entry_password.get())
            if len(email) > 50 or len(password) > 50:
                self.textvar.set("Email or password too long.")
                self.after(self.reset_time, self.reset_login_text)
                return
            self.create_socket()
            arr = ["login", email, password]
            str_login = ",".join(arr)
            self.send_message(self.client_socket, str_login)
            response = self.receive_message(self.client_socket)
            client_ip = str(self.client_socket.getsockname()[0])

            if client_ip in self.ip_attempts:
                self.ip_attempts[client_ip] += 1
                if self.ip_attempts[client_ip] > 10:
                    logging.critical('Blocked IP=%s for excessive login attempts', client_ip)
                    self.textvar.set("Too many login attempts.")
                    self.entry_password.config(state=DISABLED)
                    self.btn_login.config(state=DISABLED)
                    return

            if response == "True":
                self.textvar.set("Login Successful!")
                logging.info('Successful login: username=%s, IP=%s', email, client_ip)
                self.open_home_screen()
                self.textvar.set("Please login")
                self.entry_email.delete(0, END)
                self.entry_password.delete(0, END)
            elif response == "User is already logged in":
                self.textvar.set("User is already logged in")
                self.after(self.reset_time, self.reset_login_text)

            elif response == "False":
                self.textvar.set("Username or password incorrect")
                logging.warning('Failed login: username=%s, IP=%s', email, client_ip)
                if client_ip not in self.ip_attempts:
                    self.ip_attempts[client_ip] = 1
                self.after(self.reset_time, self.reset_login_text)
        except:
            self.btn_login.config(state=DISABLED)
            self.textvar.set("Error connecting to server.")


    def reset_login_text(self):
        self.textvar.set("Log in")

    def handle_thread_socket(self):
        client_handler = threading.Thread(target=self.create_socket, args=())
        client_handler.daemon = True
        client_handler.start()

    def close_window(self):
        try:
            self.client_socket.close()
        except AttributeError:
            pass
        finally:
            self.destroy()


if __name__ == "__main__":
    app = Login_register()
    try:
        app.mainloop()
    except KeyboardInterrupt:
        pass
