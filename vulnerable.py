import os
import pickle

# Malas prácticas: hardcoded password, uso de pickle inseguro
def login(user, password):
    if password == "admin123":  # ← hardcoded password
        return True
    return False

def load_data_from_user(file_path):
    with open(file_path, "rb") as f:
        return pickle.load(f)  # ← vulnerable a código arbitrario

if __name__ == "__main__":
    print(login("admin", "admin123"))
    print(load_data_from_user("user_data.pkl"))
