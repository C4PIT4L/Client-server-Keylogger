import ssl
import tkinter.messagebox
import tkinter
from tkinter import *


class minigame(tkinter.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.geometry('500x500+600+200')
        self.canvas = Canvas(self, width=self.winfo_screenwidth(), height=self.winfo_screenheight())
        self.resizable(width=False, height=False)
        self.canvas.pack(fill='both', expand=True)
        self.title('Mini Game')
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.wm_iconbitmap('Photos/bug.ico')
        self.create_gui()

    def create_gui(self):
        text_font='Comic Sans MS'

        self.close_button = Button(self, text='Close', command=self.close, font=(text_font, 14),bg="#DF2D2F", fg="#F1F1F1")
        self.close_button.place(relx=0.12, rely=0.98, anchor='s')

        self.game_button = Button(self, text='Play', command=self.play_game, font=(text_font, 18),bg="#DF2D2F", fg="#F1F1F1")
        self.game_button.place(relx=0.5, rely=0.55, anchor='center')

        self.canvas.create_text(250, 80,text='cipher 3', font=("Retro", 90), fill='#DF2D2F',anchor='center')

        self.canvas.configure(bg="#292929")

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

    def play_game(self):
        text_font='Comic Sans MS'

        if hasattr(self, 'play_again_button'):
            self.play_again_button.destroy()
        self.game_button.destroy()

        arr = ["play_game"]
        str_insert = ",".join(arr)
        self.send_message(self.parent.client_socket, str_insert)
        self.encrypted_sentence = self.receive_message(self.parent.client_socket)

        self.canvas.delete('all')
        self.canvas.create_text(250, 160,text='Decrypt the following sentence:', font=(text_font, 22), fill='#F1F1F1',anchor='center')
        self.canvas.create_text(250, 250,text=self.encrypted_sentence, font=(text_font, 18), fill='#F1F1F1', anchor='center')
        self.canvas.create_text(250, 80,text='cipher 3', font=("Retro", 90), fill='#DF2D2F',anchor='center')

        self.input_box = Entry(self, font=("Comic Sans MS", 14))
        self.input_box.place(relx=0.5, rely=0.70, anchor='center')

        self.submit_button = Button(self, text='Submit', command=self.check_answer, font=(text_font, 14),bg="#DF2D2F", fg="#F1F1F1")
        self.submit_button.place(relx=0.5, rely=0.85, anchor='center')
        if self.encrypted_sentence is None:
            print("The game can't be played due to connection issues.")
            self.submit_button['state'] = 'disabled'

    def check_answer(self):
        user_input = self.input_box.get().strip()
        if len(user_input) > 100:
            tkinter.messagebox.showinfo("Error", "Input is too long.")
            return
        if self.encrypted_sentence is None:
            tkinter.messagebox.showinfo("Error", "Connection lost. Please try again.")
            return
        arr = ["check_answer", user_input, self.encrypted_sentence]
        str_insert = ",".join(arr)
        self.send_message(self.parent.client_socket, str_insert)
        result = self.receive_message(self.parent.client_socket)

        if result == "successfully decrypted":
            self.canvas.delete('all')
            self.canvas.create_text(250, 200,text='successfully\n decrypted!\n Respect   99',font=("Pricedown II", 55), fill='green', anchor='center')
            self.canvas.create_text(335, 295,text='+',font=("ariel", 55), fill='green', anchor='center')
        else:
            self.canvas.delete('all')
            self.canvas.create_text(250, 200,text='Game\n Over', font=("Hannover Messe Serif", 120),fill='#DF2D2F', anchor='center')
        self.input_box.destroy()
        self.submit_button.destroy()

        self.play_again_button = Button(self, text='Play Again', command=self.play_game, font=("Comic Sans MS", 14),bg="#DF2D2F", fg="#F1F1F1")
        self.play_again_button.place(relx=0.5, rely=0.9, anchor='center')

    def close(self):
        try:
            self.parent.deiconify()
            self.destroy()
        except AttributeError:
            pass