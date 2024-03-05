import tkinter
from tkinter import *



class Creator(tkinter.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.geometry("1000x700+400+100")
        self.canvas = Canvas(self, width=self.winfo_screenwidth(), height=self.winfo_screenheight())
        self.resizable(width=False, height=False)
        self.canvas.pack(fill='both', expand=True)
        self.title('"About"')
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.wm_iconbitmap('Photos/bug.ico')
        self.create_gui()

    def create_gui(self):
        bg_color= "#FCF8EC"
        self.project_name = self.canvas.create_text(500, 80, text='"Key Logger"', font=('Futura', 60, 'bold'),fill='#1F906A')
        self.image = PhotoImage(file='Photos/About-qr.png')
        self.canvas.create_image(500, 390, image=self.image)
        close_btn = Button(self, text='"Close"', font=('Futura', 20, 'bold'), bg='#FCF8EC', fg='#1F906A', bd=0,
                           activebackground='#FCF8EC', activeforeground='#1F906A', command=self.close)
        close_btn.place(x=15, y=640)

        self.canvas.configure(bg=bg_color)
        self.canvas.update()

    def close(self):
        try:
            self.parent.deiconify()
            self.destroy()
        except AttributeError:
            pass