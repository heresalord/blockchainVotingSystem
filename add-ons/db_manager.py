import os
import sqlite3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Classe pour gérer la base de données des votants
class VoterDatabase:
    def __init__(self, database_file='add-ons/database/VoterDatabase.sql', key_file='add-ons/encryption_key.key'):
        self.database_file = database_file
        self.key_file = key_file
        self.key = self.load_or_generate_key()
        self.create_table()

    # Charger ou générer une clé de chiffrement
    def load_or_generate_key(self):
        if os.path.exists(self.key_file):
            with open(self.key_file, 'rb') as key_file:
                key = key_file.read()
        else:
            key = os.urandom(32)  # Générer une clé AES-256 (256 bits)
            with open(self.key_file, 'wb') as key_file:
                key_file.write(key)
        return key

    # Chiffrer un texte
    def encrypt(self, plaintext):
        iv = os.urandom(16)  # Vecteur d'initialisation
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext.encode()) + padder.finalize()
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        return urlsafe_b64encode(iv + ciphertext).decode('utf-8')

    # Déchiffrer un texte
    def decrypt(self, encrypted_text):
        encrypted_data = urlsafe_b64decode(encrypted_text.encode('utf-8'))
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_data) + unpadder.finalize()
        return plaintext.decode('utf-8')

    # Créer la table des votants dans la base de données
    def create_table(self):
        with sqlite3.connect(self.database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS voters (
                    npi TEXT PRIMARY KEY,
                    full_name TEXT,
                    password TEXT,
                    role TEXT
                )
            ''')
            conn.commit()

    # Ajouter un votant dans la base de données
    def add_voter(self, npi, full_name, password, role):
        encrypted_full_name = self.encrypt(full_name)
        encrypted_password = self.encrypt(password)
        encrypted_role = self.encrypt(role)
        try:
            with sqlite3.connect(self.database_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO voters (npi, full_name, password, role)
                    VALUES (?, ?, ?, ?)
                ''', (npi, encrypted_full_name, encrypted_password, encrypted_role))
                conn.commit()
                print("Voter added successfully.")
        except sqlite3.IntegrityError:
            print("Voter with this NPI already exists.")

    # Supprimer un votant de la base de données
    def delete_voter(self, npi):
        with sqlite3.connect(self.database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM voters WHERE npi = ?
            ''', (npi,))
            conn.commit()
            if cursor.rowcount > 0:
                print("Voter deleted successfully.")
            else:
                print("Voter with this NPI does not exist.")

    # Réinitialiser la base de données
    def reset_database(self):
        confirm = input("Are you sure you want to reset the database? (yes/no): ")
        if confirm.lower() == 'yes':
            with sqlite3.connect(self.database_file) as conn:
                cursor = conn.cursor()
                cursor.execute('''DROP TABLE IF EXISTS voters''')
                conn.commit()
                self.create_table()
                print("Database has been reset.")

    # Afficher les votants dans la base de données
    def view_database(self):
        with sqlite3.connect(self.database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT * FROM voters''')
            rows = cursor.fetchall()
            if rows:
                print("NPI\t\tFull Name\t\tPassword\t\tRole")
                print("---------------------------------------------------------------")
                for row in rows:
                    decrypted_full_name = self.decrypt(row[1])
                    decrypted_password = self.decrypt(row[2])
                    decrypted_role = self.decrypt(row[3])
                    print(f"{row[0]}\t{decrypted_full_name}\t{decrypted_password}\t{decrypted_role}")
            else:
                print("Database is empty.")

# Classe pour gérer l'authentification de l'administrateur
class Admin:
    def __init__(self, npi, password):
        self.npi = npi
        self.password = password
        self.authenticated = False

    # Authentifier l'administrateur
    def authenticate(self):
        print("\nLoggin with the Admin credentials to continue\n\n")
        npi_input = input("Enter your NPI: ")
        password_input = input("Enter your password: ")
        if npi_input == self.npi and password_input == self.password:
            print("\nWelcome, Admin!")
            self.authenticated = True
        else:
            print("\nIncorrect NPI or password.")

    # Déconnexion de l'administrateur
    def logout(self):
        self.authenticated = False
        print("\nLogged out.")

# Classe pour gérer la base de données des administrateurs
class AdminDatabase:
    def __init__(self, database_file='add-ons/database/AdminDatabase.sql'):
        self.database_file = database_file
        self.create_table()

    # Créer la table des administrateurs dans la base de données
    def create_table(self):
        with sqlite3.connect(self.database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS admins (
                    npi TEXT PRIMARY KEY,
                    password TEXT
                )
            ''')
            conn.commit()

    # Ajouter un administrateur dans la base de données
    def add_admin(self, npi, password):
        with sqlite3.connect(self.database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO admins (npi, password)
                VALUES (?, ?)
            ''', (npi, password))
            conn.commit()

    # Charger l'administrateur depuis la base de données
    def load_admin(self):
        with sqlite3.connect(self.database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT * FROM admins''')
            row = cursor.fetchone()
            if row:
                return Admin(row[0], row[1])
            else:
                return None

    # Afficher les administrateurs dans la base de données
    def view_database(self):
        with sqlite3.connect(self.database_file) as conn:
            cursor = conn.cursor()
            cursor.execute('''SELECT * FROM admins''')
            rows = cursor.fetchall()
            if rows:
                print("NPI\t\tPassword")
                print("-------------------------")
                for row in rows:
                    print(f"{row[0]}\t{row[1]}")
            else:
                print("Admin database is empty.")

# Créer et initialiser la base de données des administrateurs
def create_admin_database():
    admin_db = AdminDatabase()
    print("\nCreate the Admin credentials to continue\n\n")
    npi = input("Enter admin NPI: ")
    password = input("Enter admin password: ")
    admin_db.add_admin(npi, password)
    print("\nAdmin added successfully.")
    return Admin(npi, password)

# Fonction principale pour exécuter le programme
def main():
    if not os.path.exists("add-ons"):
        os.makedirs("add-ons")

    admin_db = AdminDatabase()
    admin = admin_db.load_admin()
    if not admin:
        admin = create_admin_database()
    else:
        admin.authenticate()
        if not admin.authenticated:
            print("\nAuthentication failed. Exiting.")
            return

    voter_db = VoterDatabase()

    while True:
        if not admin.authenticated:
            admin.authenticate()
            if not admin.authenticated:
                continue

        print("\nOptions:")
        print("1. Add new voter")
        print("2. Delete voter")
        print("3. Reset voter database")
        print("4. View voter database")
        print("5. Add new admin")
        print("6. View admin database")
        print("7. Logout")
        print("8. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            npi = input("Enter NPI: ").strip()
            full_name = input("Enter full name: ").strip()
            password = input("Enter password: ").strip()
            print("Select role:")
            print("1. Admin")
            print("2. Voter")
            role_choice = input("Enter role (1 or 2): ").strip()
            role = 'Admin' if role_choice == '1' else 'Voter'
            if npi and full_name and password and role:
                voter_db.add_voter(npi, full_name, password, role)
            else:
                print("\nAll fields are required.")
        elif choice == '2':
            npi = input("\nEnter NPI of the voter you want to delete: ").strip()
            if npi:
                voter_db.delete_voter(npi)
            else:
                print("NPI is required.")
        elif choice == '3':
            voter_db.reset_database()
        elif choice == '4':
            voter_db.view_database()
        elif choice == '5':
            npi = input("Enter admin NPI: ").strip()
            password = input("Enter admin password: ").strip()
            if npi and password:
                admin_db.add_admin(npi, password)
                print("\nAdmin added successfully.")
            else:
                print("\nAll fields are required.")
        elif choice == '6':
            admin_db.view_database()
        elif choice == '7':
            admin.logout()
        elif choice == '8':
            print("\nExiting...")
            break
        else:
            print("\nInvalid choice. Please enter a valid option.")

# Point d'entrée du script
if __name__ == "__main__":
    main()
