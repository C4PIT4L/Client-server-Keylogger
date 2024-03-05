import ssl
import threading
import tkinter
from tkinter import *
from tkinter import ttk
import random
from time import sleep

class Speed_writing_test(tkinter.Toplevel):
    def __init__(self, parent,user_id):
        super().__init__(parent)
        self.parent = parent
        self.title('Speed writing test')
        self.wm_iconbitmap('Photos/bug.ico')
        self.geometry("940x735+420+100")
        self.resizable(width=False, height=False)
        self.mainframe = Frame(self, bd=4, bg='pink')
        self.mainframe.grid()
        self.configure(bg='pink')
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.is_running = True
        self.totaltime = 60
        self.time = 0
        self.wrongwords = 0
        self.elapsedtimeinminutes = 0
        self.user_id = user_id
        self.create_gui()


    def create_gui(self):
        self.titleframe = Frame(self.mainframe, bg="pink")
        self.titleframe.grid()

        self.titleLabel = Label(self.titleframe, text='speed writing test', font=('algerian', 28, 'bold'), bg='pink', fg='white'
                           , width=38, bd=10)
        self.titleLabel.grid(row=0, column=0, columnspan=2, pady=5, sticky='nsew')

        self.paragraph_frame = Frame(self.mainframe, bg='pink')
        self.paragraph_frame.grid(row=1, column=0, columnspan=2)



        paragraph_list = [
            'OK, first rule of Wall Street. Nobody and I dont care if youre Warren Buffet or Jimmy Buffet, nobody knows if a stocks going up, down or fucking sideways, least of all stock brokers. But we have to pretend we know. Make sure you stay relaxed. Nobody wants to buy something from someone who sounds like they havent gotten laid in a month. Take breaks when you feel stressed, jerk off if you can. You like jerking off, right? -MARK HANNA (The wolf of wall street) ',

            'Theres a passage I got memorized, seems appropriate for this situation "The path of the righteous man is beset on all sides by the inequities of the selfish and the tyranny of evil men. Blessed is he who, in the name of charity and good will, shepherds the weak through the valley of darkness, for he is truly his brothers keeper and the finder of lost children. And I will strike down upon thee with great vengeance and furious anger those who attempt to poison and destroy my brothers. And you will know my name is the Lord when I lay my vengeance upon you."- JULES (Pulp Fiction)',

            'I went to this girl’s party the week after she beat the shit out of my friend. While everyone was getting trashed, I went around putting tuna inside all the curtain rods and so like weeks went by and they couldn’t figure out why the house smelled like festering death. They caught me through this video where these guys at the party were singing Beyonce while I was in the background with a can of tuna.This is what happened in this short funny story if you like.',

            'One time way back in sixth grade math class I had to fart really bad. Me being the idiot that I am decided that it would be silent. Big surprise it wasn’t. The only person talking was the teacher and she was interrupted by freaking cannon fire farts. She said she was disappointed I couldn’t hold it in and proceeded to tell a story of how she taught a famous athlete who did nearly the same thing.I felt ashamed then everyone laughed and at the end I also laughed.',

            'So a couple weeks ago, me and my friends were sitting on this cement kind of pedestal (as we called it) It’s basically the steps up to the portable. (classroom that no one uses) and this weird supply French teacher comes up to us and says: you shouldn’t be sitting on this ground, it’s too cold and it’s bad for your ovaries. I asked her how or why and she said that if children sit on cold ground their ovaries will freeze and that we won’t be able to have kids.',
            'One of the most valuable possession of human life is its health. With good health, one can attain everything in life. In order to perform an important work effectively, one has to be in sound health. Nowadays, everyone is suffering from some sort of mental, health, chronic or physical illness, which however deprives them. Often bad habits such as smoking have brought upon diseases and weakness upon a person which he is not aware of and are of no value to their family and society.',
            'Alcohol is taken in almost all cool and cold climates, and to a very much less extent in hot ones. It is taken by people who live in the Himalaya Mountains, but not nearly so much by those who live in the plains of India. Alcohol is not necessary in any way to anybody. The regular use of alcohol, even in small quantities, tends to cause mischief in many ways to various organs of the body. It affects the liver, it weakens the mental powers, and lessens the energy of the body.',

            'The Computer is an automatic device that performs mathematical calculations and logical operations. They are being put to use in widely divergent fields such as book-keeping, spaceflight controls, passenger reservation service, language translation etc. There are two categories: analog and digital. The former represents numbers by some physical quantity such as length, angular relation or electric current whereas the latter represent numbers by separate devices for each digit.'
            ]

        random.shuffle(paragraph_list)

        self.label_paragraph = Label(self.paragraph_frame, text=paragraph_list[0], wraplength=912, justify=LEFT,
                                font=('arial', 14, 'bold'),bg='pink')
        self.label_paragraph.grid(row=0, column=0)

        self.textarea_frame = Frame(self.mainframe, bg='pink')
        self.textarea_frame.grid(row=2, column=0)

        self.textarea = Text(self.textarea_frame, font=('arial', 12, 'bold'), width=100, height=7, bd=4, relief=GROOVE,wrap='word', state=DISABLED)
        self.textarea.grid()
        self.textarea.bind("<Control-c>", lambda e: "break")
        self.textarea.bind("<Control-v>", lambda e: "break")

        self.frame_output = Frame(self.mainframe, bg='pink')
        self.frame_output.grid(row=3, column=0)

        self.elapsed_time_label = Label(self.frame_output, text='Elapsed Time', font=('Tahoma', 12, 'bold'), fg='black',bg='pink')
        self.elapsed_time_label.grid(row=0, column=0, padx=5)

        self.elapsed_timer_label = Label(self.frame_output, text='0', font=('Tahoma', 12, 'bold'),bg='pink')
        self.elapsed_timer_label.grid(row=0, column=1, padx=5)

        self.remaining_time_label = Label(self.frame_output, text='Remaining Time', font=('Tahoma', 12, 'bold'), fg='black',bg='pink')
        self.remaining_time_label.grid(row=0, column=2, padx=5)

        self.remaining_timer_label = Label(self.frame_output, text='60', font=('Tahoma', 12, 'bold'),bg='pink')
        self.remaining_timer_label.grid(row=0, column=3, padx=5)

        self.wpm_label = Label(self.frame_output, text='WPM', font=('Tahoma', 12, 'bold'), fg='black',bg='pink')
        self.wpm_label.grid(row=0, column=4, padx=5)

        self.wpm_count_label = Label(self.frame_output, text='0', font=('Tahoma', 12, 'bold'),bg='pink')
        self.wpm_count_label.grid(row=0, column=5, padx=5)

        self.totalwords_label = Label(self.frame_output, text='Total character', font=('Tahoma', 12, 'bold'), fg='black',bg='pink')
        self.totalwords_label.grid(row=0, column=6, padx=5)

        self.totalwords_count_label = Label(self.frame_output, text='0', font=('Tahoma', 12, 'bold'),bg='pink')
        self.totalwords_count_label.grid(row=0, column=7, padx=5)

        self.wrongwords_label = Label(self.frame_output, text='Wrong Words', font=('Tahoma', 12, 'bold'), fg='black',bg='pink')
        self.wrongwords_label.grid(row=0, column=8, padx=5)

        self.wrongwords_count_label = Label(self.frame_output, text='0', font=('Tahoma', 12, 'bold'),bg='pink')
        self.wrongwords_count_label.grid(row=0, column=9, padx=5)

        self.accuracy_label = Label(self.frame_output, text='Accuracy', font=('Tahoma', 12, 'bold'), fg='black',bg='pink')
        self.accuracy_label.grid(row=0, column=10, padx=5)

        self.accuracy_percent_label = Label(self.frame_output, text='0', font=('Tahoma', 12, 'bold'),bg='pink')
        self.accuracy_percent_label.grid(row=0, column=11, padx=5)
        self.buttons_Frame = Frame(self.mainframe, bg='pink')
        self.buttons_Frame.grid(row=4, column=0)


        self.startButton = ttk.Button(self.buttons_Frame, text='Start', command=self.start)
        self.startButton.grid(row=0, column=0, padx=10)

        self.resetButton = ttk.Button(self.buttons_Frame, text='Reset', state=DISABLED, command=self.reset)
        self.resetButton.grid(row=0, column=1, padx=10)

        self.exitButton = ttk.Button(self.buttons_Frame, text='Exit', command=self.close)
        self.exitButton.grid(row=0, column=2, padx=10)

        self.keyboard_frame = Frame(self.mainframe, bg="pink")
        self.keyboard_frame.grid(row=5, column=0)

        self.frame1to0 = Frame(self.keyboard_frame, bg='pink')
        self.frame1to0.grid(row=0, column=0, pady=3)
        self.label1 = Label(self.frame1to0, text='1', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                            bd=10, relief=GROOVE)
        self.label2 = Label(self.frame1to0, text='2', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label3 = Label(self.frame1to0, text='3', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label4 = Label(self.frame1to0, text='4', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label5 = Label(self.frame1to0, text='5', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label6 = Label(self.frame1to0, text='6', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label7 = Label(self.frame1to0, text='7', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label8 = Label(self.frame1to0, text='8', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label9 = Label(self.frame1to0, text='9', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label0 = Label(self.frame1to0, text='0', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.label1.grid(row=0, column=0, padx=5)
        self.label2.grid(row=0, column=1, padx=5)
        self.label3.grid(row=0, column=2, padx=5)
        self.label4.grid(row=0, column=3, padx=5)
        self.label5.grid(row=0, column=4, padx=5)
        self.label6.grid(row=0, column=5, padx=5)
        self.label7.grid(row=0, column=6, padx=5)
        self.label8.grid(row=0, column=7, padx=5)
        self.label9.grid(row=0, column=8, padx=5)
        self.label0.grid(row=0, column=9, padx=5)
        self.frameqtop = Frame(self.keyboard_frame, bg='pink')
        self.frameqtop.grid(row=1, column=0, pady=3)
        self.labelQ = Label(self.frameqtop, text='Q', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelW = Label(self.frameqtop, text='W', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelE = Label(self.frameqtop, text='E', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelR = Label(self.frameqtop, text='R', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelT = Label(self.frameqtop, text='T', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelY = Label(self.frameqtop, text='Y', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelU = Label(self.frameqtop, text='U', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelI = Label(self.frameqtop, text='I', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelO = Label(self.frameqtop, text='O', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelP = Label(self.frameqtop, text='P', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelQ.grid(row=0, column=0, padx=5)
        self.labelW.grid(row=0, column=1, padx=5)
        self.labelE.grid(row=0, column=2, padx=5)
        self.labelR.grid(row=0, column=3, padx=5)
        self.labelT.grid(row=0, column=4, padx=5)
        self.labelY.grid(row=0, column=5, padx=5)
        self.labelU.grid(row=0, column=6, padx=5)
        self.labelI.grid(row=0, column=7, padx=5)
        self.labelO.grid(row=0, column=8, padx=5)
        self.labelP.grid(row=0, column=9, padx=5)
        self.frameatol = Frame(self.keyboard_frame, bg='pink')
        self.frameatol.grid(row=2, column=0, pady=3)
        self.labelA = Label(self.frameatol, text='A', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelS = Label(self.frameatol, text='S', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelD = Label(self.frameatol, text='D', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelF = Label(self.frameatol, text='F', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelG = Label(self.frameatol, text='G', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelH = Label(self.frameatol, text='H', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelJ = Label(self.frameatol, text='J', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelK = Label(self.frameatol, text='K', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelL = Label(self.frameatol, text='L', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelA.grid(row=0, column=0, padx=5)
        self.labelS.grid(row=0, column=1, padx=5)
        self.labelD.grid(row=0, column=2, padx=5)
        self.labelF.grid(row=0, column=3, padx=5)
        self.labelG.grid(row=0, column=4, padx=5)
        self.labelH.grid(row=0, column=5, padx=5)
        self.labelJ.grid(row=0, column=6, padx=5)
        self.labelK.grid(row=0, column=7, padx=5)
        self.labelL.grid(row=0, column=8, padx=5)
        self.frameztom = Frame(self.keyboard_frame, bg='pink')
        self.frameztom.grid(row=3, column=0, pady=3)
        self.labelZ = Label(self.frameztom, text='Z', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelX = Label(self.frameztom, text='X', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelC = Label(self.frameztom, text='C', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelV = Label(self.frameztom, text='V', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelB = Label(self.frameztom, text='B', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelN = Label(self.frameztom, text='N', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelM = Label(self.frameztom, text='M', bg='black', fg='white', font=('arial', 10, 'bold'), width=5, height=2,
                       bd=10, relief=GROOVE)
        self.labelZ.grid(row=0, column=0, padx=5)
        self.labelX.grid(row=0, column=1, padx=5)
        self.labelC.grid(row=0, column=2, padx=5)
        self.labelV.grid(row=0, column=3, padx=5)
        self.labelB.grid(row=0, column=4, padx=5)
        self.labelN.grid(row=0, column=5, padx=5)
        self.labelM.grid(row=0, column=6, padx=5)

        self.spaceFrame = Frame(self.keyboard_frame, bg='pink')
        self.spaceFrame.grid(row=4, column=0, pady=3)

        self.labelSpace = Label(self.spaceFrame, bg='black', fg='white', font=('arial', 10, 'bold'), width=40, height=2, bd=10,
                           relief=GROOVE)
        self.labelSpace.grid(row=0, column=0)



        def changeBG(event, widget, correct_letter):
            if event.char == correct_letter:
                widget.config(bg='green')
                widget.after(100, lambda: widget.config(bg='black'))
            else:
                widget.config(bg='red')
                widget.after(100, lambda: widget.config(bg='black'))

        label_numbers = [self.label1, self.label2, self.label3, self.label4, self.label5, self.label6, self.label7,
                         self.label8, self.label9, self.label0]

        label_alphabets = [self.labelA, self.labelB, self.labelC, self.labelD, self.labelE, self.labelF, self.labelG,
                           self.labelH, self.labelI, self.labelJ, self.labelK,
                           self.labelL, self.labelM, self.labelN,
                           self.labelO, self.labelP, self.labelQ, self.labelR, self.labelS, self.labelT, self.labelU,
                           self.labelV, self.labelW, self.labelX, self.labelY,
                           self.labelZ]

        space_label = [self.labelSpace]

        binding_numbers = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0']

        binding_capital_alphabets = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                     'Q', 'R', 'S', 'T',
                                     'U', 'V', 'W', 'X', 'Y', 'Z']

        binding_small_alphabets = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q',
                                   'r', 's', 't',
                                   'u', 'v', 'w', 'x', 'y', 'z']

        for numbers in range(len(binding_numbers)):
            self.bind(binding_numbers[numbers], lambda event, label=label_numbers[numbers], correct_letter=binding_numbers[numbers]: changeBG(event,label, correct_letter))

        for capital_alphabets in range(len(binding_capital_alphabets)):
            self.bind(binding_capital_alphabets[capital_alphabets], lambda event, label=label_alphabets[capital_alphabets], correct_letter=binding_capital_alphabets[capital_alphabets]: changeBG(event,label, correct_letter))

        for small_alphabets in range(len(binding_small_alphabets)):
            self.bind(binding_small_alphabets[small_alphabets], lambda event, label=label_alphabets[small_alphabets], correct_letter=binding_small_alphabets[small_alphabets]: changeBG(event,label, correct_letter))


        self.bind('<space>', lambda event: changeBG(event, space_label[0], event.char))

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

    def start_timer(self):
        self.startButton.config(state=DISABLED)
        self.textarea.config(state=NORMAL)
        self.textarea.focus()

        for self.time in range(1, 61):
            if not self.is_running:
                return
            try:
                self.elapsed_timer_label.config(text=self.time)
                self.remainingtime = self.totaltime - self.time
                self.remaining_timer_label.config(text=self.remainingtime)
            except TclError:
                return
            sleep(1)
            self.update()

        self.textarea.config(state=DISABLED)
        self.resetButton.config(state=NORMAL)
        statistics_data = "add_statistics," + str(self.user_id) + "," + str(self.wpm) + "," + str(
            self.totalwords) + "," + str(self.wrongwords) + "," + str(self.accuracy)
        self.send_message(self.parent.client_socket, statistics_data)

    def count(self):
        while self.time != self.totaltime and self.is_running:  # Add this condition
            try:
                self.entered_paragraph = self.textarea.get(1.0, END).split()
            except TclError:
                return
            self.totalcharacter = len("".join(self.entered_paragraph))
            self.totalwords = len(self.entered_paragraph)
        self.totalwords_count_label.config(text=self.totalcharacter)
        self.para_word_list = self.label_paragraph['text'].split()


        for pair in list(zip(self.para_word_list, self.entered_paragraph)):
            if pair[0] != pair[1]:
                self.wrongwords += 1

        self.wrongwords_count_label.config(text=self.wrongwords)

        self.elapsedtimeinminutes = self.time / 60
        self.wpm = (self.totalcharacter/5) / self.elapsedtimeinminutes
        self.wpm_count_label.config(text=self.wpm)
        self.gross_wpm = self.totalcharacter / self.elapsedtimeinminutes
        self.accuracy = (self.totalwords - self.wrongwords) / self.totalwords * 100
        self.accuracy = round(self.accuracy)
        self.accuracy_percent_label.config(text=str(self.accuracy) + '%')

    def start(self):
        self.t1 = threading.Thread(target=self.start_timer)
        self.t1.start()

        self.t2 = threading.Thread(target=self.count)
        self.t2.start()

    def reset(self):
        self.time = 0
        self.elapsedtimeinminutes = 0
        self.startButton.config(state=NORMAL)
        self.resetButton.config(state=DISABLED)
        self.textarea.config(state=NORMAL)
        self.textarea.delete(1.0, END)
        self.textarea.config(state=DISABLED)
        self.elapsed_timer_label.config(text='0')
        self.remaining_timer_label.config(text='0')
        self.wpm_count_label.config(text='0')
        self.accuracy_percent_label.config(text='0')
        self.totalwords_count_label.config(text='0')
        self.wrongwords_count_label.config(text='0')

    def close(self):
        try:
            self.is_running = False
            self.parent.deiconify()
            self.destroy()
        except AttributeError:
            pass
