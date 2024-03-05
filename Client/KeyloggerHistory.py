import os
import tkinter as tk
from tkinter import messagebox, filedialog
from tkinter.font import Font
from tkinter import ttk
import pandas as pd


class KeystrokesHistory(tk.Toplevel):
    def __init__(self, parent, user_id, log_file_path):
        super().__init__(parent)
        self.geometry("1000x800+420+100")
        self.resizable(width=False, height=False)
        self.parent = parent
        self.user_id = user_id
        self.log_file_path = log_file_path
        self.configure(bg='#f0f0f0')
        self.wm_iconbitmap('Photos/bug.ico')
        self.title(f"Keystrokes History - User {user_id}")
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.line_counter = 0
        self.load_more_lines = 1000
        self.create_gui()


    def create_gui(self):
        # create text widget
        self.text = tk.Text(self, wrap='word')
        self.text.pack(side='left', fill='both', expand=True)
        font = Font(family='Helvetica', size=12)
        self.text.configure(font=font)
        self.text.pack(padx=10, pady=10, fill='both', expand=True)

        self.load_more_button = tk.Button(self, text='Load More', font=('Helvetica', 16, 'bold'),command=self.load_more_history, foreground='#000000')
        self.load_more_button.pack(side='bottom', pady=45)
        # create scrollbar for text widget
        scrollbar = tk.Scrollbar(self, width=30, troughcolor='#f0f0f0', borderwidth=0)
        scrollbar.pack(side='right', fill='y')
        self.text.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.text.yview)

        # create button to show search dialog
        self.search_button = tk.Button(self, text='Search', font=('Helvetica', 16, 'bold'), command=self.show_search_dialog, foreground='#000000')
        self.search_button.pack(side='bottom', pady=45)

        # create button to save history
        self.save_button = tk.Button(self, text='Save History', font=('Helvetica', 16, 'bold'),command=self.save_history, foreground='#000000')
        self.save_button.pack(side='bottom', pady=45)

        # create button to export chat history to Excel
        self.export_button = tk.Button(self, text='Exel', font=('Helvetica', 16, 'bold'), command=self.Export_to_exel, foreground='#000000')
        self.export_button.pack(side='bottom', pady=45)



        # create button to change font size
        self.size_button = tk.Button(self, text='Text size', font=('Helvetica', 16, 'bold'), command=self.change_font_size, foreground='#000000')
        self.size_button.pack(side='bottom', pady=45)

        # create button to close chat history window
        self.close_button = tk.Button(self, text='Exit History', font=('Helvetica', 16, 'bold'), command=self.close, foreground='#000000')
        self.close_button.pack(side='bottom', pady=45)

        # load chat history
        self.load_history(self.user_id, self.log_file_path)

    def load_history(self, user_id, log_file_path):
        try:
            if os.path.exists(log_file_path):
                with open(log_file_path, 'r', encoding='utf-8') as f:
                    contents = f.read()
                    if contents:
                        entries = contents.split('\n')
                        user_entries = self.filter_entries_for_user(entries, user_id)
                        if user_entries:
                            self.display_entries(user_entries[:self.load_more_lines])
                            self.line_counter += self.load_more_lines
                        else:
                            messagebox.showinfo('No History Found', f"No keystrokes history found for user {user_id}.")
                    else:
                        messagebox.showinfo('Empty Log', 'The keystrokes log is empty.')
            else:
                messagebox.showerror('Log Not Found', 'The keystrokes log file was not found.')
        except Exception as e:
            messagebox.showerror('Error', f'An error occurred while loading the keystrokes history:\n{str(e)}')

    def load_more_history(self):
        try:
            with open(self.log_file_path, 'r', encoding='utf-8') as f:
                contents = f.read()
                if contents:
                    entries = contents.split('\n')
                    user_entries = self.filter_entries_for_user(entries, self.user_id)
                    if user_entries:
                        more_entries = user_entries[self.line_counter:self.line_counter + self.load_more_lines]
                        if more_entries:
                            self.display_entries(more_entries)
                            self.line_counter += self.load_more_lines
                        else:
                            messagebox.showinfo('No More History',
                                                f"No more keystrokes history for user {self.user_id}.")
                    else:
                        messagebox.showinfo('Empty Log', 'The keystrokes log is empty.')
        except Exception as e:
            messagebox.showerror('Error', f'An error occurred while loading more keystrokes history:\n{str(e)}')

    def display_entries(self, entries):
        display_string = '\n'.join(entries)
        self.text.configure(state='normal')
        if self.text.get('1.0', 'end-1c'):
            self.text.insert('end', '\n')
        self.text.insert('end', display_string)
        self.text.configure(state='disabled')
        self.text.tag_configure('search', background='yellow')

    def change_font_size(self):
        font = Font(family='Helvetica', size=15)
        self.text.configure(font=font)
        self.geometry("1200x800")

    def save_history(self):
        try:
            filename = filedialog.asksaveasfilename(defaultextension='.txt', filetypes=[('Text Files', '*.txt')])
            if not filename:
                return
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(self.text.get('1.0', 'end-1c'))

            messagebox.showinfo('Saved', f'Keystrokes history saved to {filename}.')
        except Exception as e:
            messagebox.showerror('Error', f'An error occurred while saving the keystrokes history:\n{str(e)}')


    def Export_to_exel(self):
        try:
            filename = filedialog.asksaveasfilename(defaultextension='.xlsx', filetypes=[('Excel Files', '*.xlsx')])
            if not filename:
                return
            lines = self.text.get('1.0', 'end').split('\n')
            data = []
            for line in lines:
                items = line.split(' | ')
                if len(items) != 3:
                    continue
                timestamp, key, title = items
                data.append([timestamp, key, title])
            df = pd.DataFrame(data, columns=['Timestamp', 'Key', 'Window Title'])
            df.to_excel(filename, index=False)
            messagebox.showinfo('Saved', f'Keystrokes history saved to {filename}.')
        except Exception as e:
            messagebox.showerror('Error', f'An error occurred while saving the keystrokes history:\n{str(e)}')

    def show_search_dialog(self):
        search_dialog = tk.Toplevel(self)
        search_dialog.geometry("400x100")
        search_dialog.title("Search")
        search_dialog.wm_iconbitmap('bug.ico')
        search_dialog.transient(self)
        search_dialog.grab_set()

        label = ttk.Label(search_dialog, text="Enter search term:")
        label.pack(side='left', padx=10, pady=10)

        search_var = tk.StringVar()
        search_entry = ttk.Entry(search_dialog, textvariable=search_var)
        search_entry.pack(side='left', padx=10, pady=10, fill='x', expand=True)
        search_entry.focus_set()

        search_button = ttk.Button(search_dialog, text='Search',command=lambda: self.search_entries(search_var.get(), search_dialog),style='My.TButton')
        search_button.pack(side='left', padx=10, pady=10)

    def search_entries(self, search_term, search_dialog):
        self.text.tag_remove('search', '1.0', 'end')
        found_match = False
        if search_term:
            search_term = search_term.lower()
            _buffer = []
            for i in range(1, int(self.text.index('end').split('.')[0])):
                line = self.text.get(f"{i}.0", f"{i}.end")
                if line:
                    parts = line.split(' | ')
                    if len(parts) == 3:
                        _buffer.append(parts[1].lower())
                        if len(_buffer) > len(search_term):
                            _buffer.pop(0)
                        if "".join(_buffer) == search_term:
                            found_match = True
                            start_pos = f"{i - len(search_term) + 1}.0"
                            end_pos = f"{i + 1}.0"
                            self.text.tag_add('search', start_pos, end_pos)
        if found_match:
            print(f"Found {len(self.text.tag_ranges('search')) // 2} matches")
            self.text.see('search.first')
            search_dialog.destroy()
        else:
            messagebox.showinfo('No Results', f"No results found for search term '{search_term}'.")

    @staticmethod
    def filter_entries_for_user(entries, user_id):
        user_entries = []
        for entry in entries:
            if entry.endswith(f"|{user_id}"):
                user_entries.append(entry)
        return user_entries

    def close(self):
        try:
            self.parent.deiconify()
            self.destroy()
        except AttributeError:
            pass