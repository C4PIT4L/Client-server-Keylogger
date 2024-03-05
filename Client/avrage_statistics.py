import socket
import ssl
from tkinter import *
import tkinter
import tkinter.ttk as ttk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import NavigationToolbar2Tk


class AverageStatisticsWindow(tkinter.Toplevel):
    def __init__(self, parent, user_id):
        super().__init__(parent)
        self.parent = parent
        self.send_message(self.parent.client_socket, f"get_statistics,{user_id}")
        try:
            server_data = self.receive_message(self.parent.client_socket)
        except socket.error as e:
            print("Socket error occurred while receiving server data:", e)
            server_data = None
        if server_data is not None:
            unpacked_data = eval(server_data)
            if isinstance(unpacked_data, tuple) and len(unpacked_data) == 4:
                avg_statistics, self.user_number_of_games, self.user_wpm_history, self.user_accuracy_history = unpacked_data
            else:
                print("Unexpected server data structure:", unpacked_data)
                avg_statistics, self.user_number_of_games, self.user_wpm_history, self.user_accuracy_history = (0, 0, [], [])
        else:
            avg_statistics, self.user_number_of_games, self.user_wpm_history, self.user_accuracy_history = (0, 0, [], [])

        if avg_statistics is None or isinstance(avg_statistics, bool) or not isinstance(avg_statistics, (tuple, list)) or len(avg_statistics) != 4:
            self.avg_wpm, self.avg_total_words, self.avg_wrong_words, self.avg_accuracy = (0, 0, 0, 0)
        else:
            self.avg_wpm, self.avg_total_words, self.avg_wrong_words, self.avg_accuracy = avg_statistics
        self.geometry("1920x1080")
        self.canvas = Canvas(self, width=self.winfo_screenwidth(), height=self.winfo_screenheight())
        self.resizable(width=False, height=False)
        self.canvas.pack(fill='both', expand=True)
        self.title('Statistics')
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.wm_iconbitmap('Photos/bug.ico')
        self.user_id = user_id
        self.create_gui()

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


    def create_gui(self):
        # Define colors
        bg_color = "#292929"
        text_color = "#F1F1F1"
        button_color = "#FF028D"
        button_text_color = "#F1F1F1"
        text_font='Comic Sans MS'
        progress_bar_style='green.Horizontal.TProgressbar'

        # Plot graphs
        self.plot_wpm_over_tries()
        self.plot_Accuracy_over_tries()


        # Create labels to display statistics
        self.wpm_label = self.canvas.create_text(1400, 600, text=" Your Average WPM: {}".format(self.avg_wpm),font=(text_font, 30), fill=text_color)
        self.total_words_label = self.canvas.create_text(1400, 800,text=" Your Average Total words: {}".format(self.avg_total_words),font=(text_font, 30), fill=text_color)
        self.wrong_words_label = self.canvas.create_text(500, 800,text=" Your Average Wrong words: {}".format(self.avg_wrong_words),font=(text_font, 30), fill=text_color)
        self.accuracy_label = self.canvas.create_text(500, 600,text=" Your Average Accuracy: {}%".format(self.avg_accuracy),font=(text_font, 30), fill=text_color)

        # Create a custom style for progress bar
        style = ttk.Style()
        style.theme_use('default')
        style.configure("red.Horizontal.TProgressbar", foreground='#af4c4c', background='#af4c4c', thickness=28,
                        borderwidth=0, troughcolor='#e6c8c8', relief='flat')

        style = ttk.Style()
        style.theme_use('default')
        style.configure(progress_bar_style, foreground='#4CAF50', background='#4CAF50', thickness=28,
                        borderwidth=0, troughcolor='#C8E6C9', relief='flat')

        # Create progress bars to show user's progress
        self.wpm_progress = ttk.Progressbar(self.canvas, orient="horizontal", length=300, mode="determinate",style=progress_bar_style)
        self.wpm_progress.place(relx=0.75, rely=0.64, anchor='center')
        self.wpm_progress["value"] = self.avg_wpm
        self.wpm_progress["maximum"] = 100

        self.total_words_progress = ttk.Progressbar(self.canvas, orient="horizontal", length=300, mode="determinate",style=progress_bar_style)
        self.total_words_progress.place(relx=0.75, rely=0.84, anchor='center')
        self.total_words_progress["value"] = self.avg_total_words
        self.total_words_progress["maximum"] = 100

        self.accuracy_progress = ttk.Progressbar(self.canvas, orient="horizontal", length=300, mode="determinate",style=progress_bar_style)
        self.accuracy_progress.place(relx=0.25, rely=0.64, anchor='center')
        self.accuracy_progress["value"] = self.avg_accuracy
        self.accuracy_progress["maximum"] = 100

        self.wrong_words_progress = ttk.Progressbar(self.canvas, orient="horizontal", length=300, mode="determinate",style="red.Horizontal.TProgressbar")
        self.wrong_words_progress.place(relx=0.25, rely=0.84, anchor='center')
        self.wrong_words_progress["value"] = self.avg_wrong_words
        self.wrong_words_progress["maximum"] = 100

        # Create button to return to main menu
        self.close_button = Button(self, text='Return', command=self.close, font=("Comic Sans MS", 20),bg=button_color, fg=button_text_color)
        self.close_button.place(relx=0.5, rely=0.95, anchor='s')

        # Set background color of the canvas
        self.canvas.configure(bg=bg_color)

    def plot_wpm_over_tries(self):
        fig, ax = plt.subplots(figsize=(7, 5), dpi=100, facecolor='#F1F1F1')
        x = list(range(1, self.user_number_of_games + 1))
        y = self.user_wpm_history
        ax.plot(x, y, color='#FF028D', linewidth=2, linestyle='--', marker='o', markersize=8)
        ax.set_xlabel('Attempts', fontsize=14)
        ax.set_ylabel('WPM (Words per minute)', fontsize=14)
        ax.set_title('WPM Over Attempts', fontsize=16, fontweight='bold', pad=15)
        ax.grid(True, linestyle='--', alpha=0.7)
        ax.legend(['WPM Over Attempts'], fontsize=12, loc='best')
        ax.tick_params(axis='both', which='major', labelsize=12, pad=8)
        ax.set_facecolor('#F9F9F9')
        ax.spines['bottom'].set_color('white')
        ax.spines['top'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.spines['left'].set_color('white')
        canvas = FigureCanvasTkAgg(fig, master=self.canvas)
        canvas.draw()
        canvas.get_tk_widget().place(relx=0.72, rely=0.27, anchor='center')

        toolbar = NavigationToolbar2Tk(canvas, self.canvas)
        toolbar.update()
        toolbar.place(relx=0.72, rely=0.44, anchor='center')

    def plot_Accuracy_over_tries(self):
        fig, ax = plt.subplots(figsize=(7, 5), dpi=100, facecolor='#F1F1F1')
        x = list(range(1, self.user_number_of_games + 1))
        y = self.user_accuracy_history
        ax.plot(x, y, color='#FF028D', linewidth=2, linestyle='--', marker='o', markersize=8)
        ax.set_xlabel('Attempts', fontsize=14)
        ax.set_ylabel('Accuracy(%)', fontsize=14)
        ax.set_title('Accuracy Over Attempts', fontsize=16, fontweight='bold', pad=15)
        ax.grid(True, linestyle='--', alpha=0.7)
        ax.legend(['Accuracy Over Attempts'], fontsize=12, loc='best')
        ax.tick_params(axis='both', which='major', labelsize=12, pad=8)
        ax.set_facecolor('#F9F9F9')
        ax.spines['bottom'].set_color('white')
        ax.spines['top'].set_color('white')
        ax.spines['right'].set_color('white')
        ax.spines['left'].set_color('white')
        canvas = FigureCanvasTkAgg(fig, master=self.canvas)
        canvas.draw()
        canvas.get_tk_widget().place(relx=0.27, rely=0.27, anchor='center')

        toolbar = NavigationToolbar2Tk(canvas, self.canvas)
        toolbar.update()
        toolbar.place(relx=0.27, rely=0.44, anchor='center')

    def close(self):
        try:
            self.parent.deiconify()
            self.destroy()
        except AttributeError:
            pass
