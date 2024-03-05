import sqlite3
import hashlib
import os

class User(object):
    def __init__(self, tablename="Users", Id="Id", email="email", password="password", username="username", salt="salt"):
        self.__tablename = tablename
        self.__Id = Id
        self.__email = email
        self.__password = password
        self.__username = username
        self.__salt = salt
        self.__current_user = None
        self.__current_user_id = None

        conn = sqlite3.connect('users_new.db')
        print("Opened database successfully")
        _str = f"CREATE TABLE IF NOT EXISTS {self.__tablename}({self.__Id} INTEGER PRIMARY KEY AUTOINCREMENT, {self.__email} TEXT NOT NULL, {self.__password} TEXT NOT NULL, {self.__username} TEXT NOT NULL, {self.__salt} BLOB NOT NULL)"
        conn.execute(_str)
        print("Table created successfully")
        conn.commit()
        conn.close()

    def get_table_name(self):
        return self.__tablename

    def set_current_user(self, user):
        if isinstance(user, int):
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute("SELECT * from " + self.__tablename + " where " + self.__Id + "= ? ", (user,))
            row = cursor.fetchone()
            if row:
                self.__current_user = row[1]
                self.__current_user_id = row[0]
        elif isinstance(user, str):
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute("SELECT * from " + self.__tablename + " where " + self.__email + "= ? ", (user,))
            row = cursor.fetchone()
            if row:
                self.__current_user = user
                self.__current_user_id = row[0]

    def get_current_user(self):
        if self.__current_user is not None:
            return self.__current_user
        else:
            return None

    def get_user_id_by_email(self, email):
        conn = sqlite3.connect('users_new.db')
        cursor = conn.execute(
            "SELECT " + self.__Id + " from " + self.__tablename + " where " + self.__email + "= ? ", (email,))
        row = cursor.fetchone()
        if row:
            user_id = row[0]
            return user_id
        else:
            return None

    def get_current_user_id(self):
        if self.__current_user_id is not None:
            return self.__current_user_id
        elif self.__current_user is not None:
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute("SELECT " + self.__Id + " from " + self.__tablename + " where " + self.__username + "= ? ", (self.__current_user,))
            row = cursor.fetchone()
            if row:
                user_id = row[0]
                self.__current_user_id = user_id
                return user_id
            else:
                return None
        else:
            return None


    def is_exist_by_id(self, Id):
        conn = sqlite3.connect('users_new.db')
        cursor = conn.execute("SELECT * from " + self.__tablename + " where " + self.__Id + "= ? ", (str(Id),))
        row = cursor.fetchone()
        if row:
            return True
        else:
            return False

    def is_exist_by_email(self, email):
        conn = sqlite3.connect('users_new.db')
        cursor = conn.execute("SELECT * from " + self.__tablename + " where " + self.__email + "= ? ", (str(email),))
        row = cursor.fetchone()
        if row:
            return True
        else:
            return False

    def get_user_id_by_username(self, username):
        conn = sqlite3.connect('users_new.db')
        cursor = conn.execute(
            "SELECT " + self.__Id + " from " + self.__tablename + " where " + self.__username + "= ? ", (username,))
        row = cursor.fetchone()
        if row:
            user_id = row[0]
            return user_id
        else:
            return None

    def insert_user(self, email, password, username):
        salt = os.urandom(16)
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        try:
            conn = sqlite3.connect('users_new.db')
            query = "INSERT INTO " + self.__tablename + " (" + self.__email + "," + self.__password + "," + self.__username + "," + self.__salt + ") VALUES (?, ?, ?, ?);"
            data = (email, hashed_password, username, salt)
            conn.execute(query, data)
            conn.commit()
            conn.close()
            print("Record created successfully")
            return True
        except:
            print("Failed to insert user")
            return False

    def delete_by_email(self, email):
        try:
            conn = sqlite3.connect('users_new.db')
            str_delete = f"DELETE  from {self.__tablename} where {self.__email} = ?"
            conn.execute(str_delete, (email,))
            conn.commit()
            conn.close()
            print("Record deleted successfully")
            return "Success"
        except:
            return "Failed to delete user"

    def is_exist(self, email, password):
        conn = sqlite3.connect('users_new.db')
        cursor = conn.execute("SELECT * from " + self.__tablename + " where " + self.__email + "= ? ", (email,))
        row = cursor.fetchone()
        if row:
            salt = row[4]
            hashed_password = hashlib.md5(password.encode() + salt).hexdigest()
            if row[2] == hashed_password:
                print("Exist")
                return "Exist"
            else:
                print("password not correct")
                return "password not correct"
        else:
            print("Not exist")
            return "Not exist"

    def login(self, email, password):
        conn = sqlite3.connect('users_new.db')
        try:
            password = hashlib.md5(password.encode()).hexdigest()
            strsql = f"SELECT * from {self.__tablename} where {self.__email} = ? and {self.__password} = ?"
            cursor = conn.execute(strsql, (email, password))
            row = cursor.fetchone()
            if row:
                username = row[3]
                self.__current_user = username
                print(username)
                conn.commit()
                return True
            else:
                print("Failed to find user")
                conn.commit()
                return False
        except sqlite3.Error as e:
            print("An error occurred:", e.args[0])
            return False
        finally:
            conn.close()

    def __str__(self):
        return "table  name is ", self.__tablename


u = User()
