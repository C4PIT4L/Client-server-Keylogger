import sqlite3
from users import User

class Statistics(object):
    def __init__(self, tablename="statistics", WPM="WPM", Total_Words="Total_Words", Wrong_Words="Wrong_Words", Accuracy="Accuracy", statistics_user_id="statistics_user_id"):
        self.__tablename = tablename
        self.__WPM = WPM
        self.__Total_Words = Total_Words
        self.__Wrong_Words = Wrong_Words
        self.__Accuracy = Accuracy
        self.__statistics_user_id = statistics_user_id

    def create_table(self):
        conn = sqlite3.connect('users_new.db')
        conn.execute("PRAGMA foreign_keys = 1")
        _str = "CREATE TABLE IF NOT EXISTS " + self.__tablename + "(" + self.__WPM + " FLOAT NOT NULL, "
        _str += " " + self.__Total_Words + " INTEGER NOT NULL, "
        _str += " " + self.__Wrong_Words + " INTEGER NOT NULL, "
        _str += " " + self.__Accuracy + " FLOAT NOT NULL, "
        _str += " " + self.__statistics_user_id + " INTEGER NOT NULL, FOREIGN KEY (" + self.__statistics_user_id + ") REFERENCES Users(Id) ON DELETE CASCADE)"
        conn.execute(_str)
        conn.commit()
        conn.close()

    @staticmethod
    def add_statistics(statistics_user_id, WPM, Total_Words, Wrong_Words, Accuracy):
        conn = sqlite3.connect('users_new.db')
        try:
            if not statistics_user_id:
                print("Invalid user ID")
                return False

            user = User()
            user_exists = user.is_exist_by_id(statistics_user_id)
            if user_exists:
                query = "INSERT INTO statistics (statistics_user_id, WPM, Total_Words, Wrong_Words,Accuracy) VALUES(?, ?, ?, ?, ?)"
                data = (statistics_user_id, WPM, Total_Words, Wrong_Words, Accuracy)
                conn.execute(query, data)
                conn.commit()
                print("Record created successfully")
                return True
            else:
                print("User with Id {} does not exist in the Users table".format(statistics_user_id))
                return False
        except Exception as e:
            print(f"Failed to insert statistics, error: {e}")
            return False
        finally:
            conn.close()

    @staticmethod
    def get_statistics_by_user(statistics_user_id):
        conn = sqlite3.connect('users_new.db')
        cursor = conn.execute("SELECT * FROM statistics WHERE statistics_user_id = ?", (statistics_user_id,))
        statistics = cursor.fetchall()
        conn.close()
        return statistics

    @staticmethod
    def get_user_number_of_games(statistics_user_id):
        try:
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute(
                "SELECT COUNT(*) FROM statistics WHERE statistics_user_id = ?",
                (statistics_user_id,))
            number_of_games = cursor.fetchone()[0]
            conn.close()
            return number_of_games
        except Exception as e:
            print("Failed to get user number of games:", e)
            return None

    @staticmethod
    def get_user_latest_wpm(statistics_user_id):
        try:
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute(
                "SELECT WPM FROM statistics WHERE statistics_user_id = ? ORDER BY rowid DESC LIMIT 1",
                (statistics_user_id,))
            wpm = cursor.fetchone()
            conn.close()
            return wpm[0] if wpm else None
        except Exception as e:
            print("Failed to get user latest WPM:", e)
            return None

    @staticmethod
    def update_statistics(statistics_user_id, WPM, Total_Words, Wrong_Words, Accuracy):
        try:
            conn = sqlite3.connect('users_new.db')
            query ="UPDATE statistics SET WPM = ?, Total_Words = ?, Wrong_Words = ?, Accuracy = ? WHERE statistics_user_id = ?"
            data = (WPM, Total_Words, Wrong_Words, Accuracy, statistics_user_id,)
            conn.execute(query, data)
            conn.commit()
            conn.close()
            print("Record updated successfully")
            return True
        except:
            print("Failed to update statistics")
        return False

    @staticmethod
    def get_average_statistics(statistics_user_id):
        try:
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute(
                "SELECT AVG(WPM), AVG(Total_Words), AVG(Wrong_Words), AVG(Accuracy) FROM statistics WHERE statistics_user_id = ?",
                (statistics_user_id,))
            avg_statistics = cursor.fetchone()
            conn.close()
            return tuple(round(x, 2) for x in avg_statistics)
        except:
            print("Failed to get average statistics")
            return False



    @staticmethod
    def delete_statistics(statistics_user_id):
        try:
            conn = sqlite3.connect('users_new.db')
            query ="DELETE FROM statistics WHERE statistics_user_id = ?"
            data = (statistics_user_id,)
            conn.execute(query, data)
            conn.commit()
            conn.close()
            print("Record deleted successfully")
            return True
        except:
            print("Failed to delete statistics")
            return False

    @staticmethod
    def get_user_wpm_history(statistics_user_id):
        try:
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute(
                "SELECT WPM FROM statistics WHERE statistics_user_id = ?",
                (statistics_user_id,))
            wpm_history = [row[0] for row in cursor.fetchall()]
            conn.close()
            return wpm_history
        except Exception as e:
            print("Failed to get user WPM history:", e)
            return None



    @staticmethod
    def get_user_Accuracy_history(statistics_user_id):
        try:
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute(
                "SELECT Accuracy FROM statistics WHERE statistics_user_id = ?",
                (statistics_user_id,))
            Accuracy_history = [row[0] for row in cursor.fetchall()]
            conn.close()
            return Accuracy_history
        except Exception as e:
            print("Failed to get user Accuracy history:", e)
            return None


    @staticmethod
    def get_all_statistics():
        try:
            conn = sqlite3.connect('users_new.db')
            cursor = conn.execute("SELECT * FROM statistics")
            statistics = cursor.fetchall()
            conn.close()
            return statistics
        except:
            print("Failed to get all statistics")
            return False

s=Statistics()
