import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import os
import base64
import secrets
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend

class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Gestionnaire de Mots de Passe")
        self.root.geometry("800x500")
        self.root.resizable(False, False)
        
        self.password_file = "passwords.encrypted"
        self.key_file = "key.salt"
        self.master_password = None
        self.fernet = None
        self.passwords = {}
        
        self.setup_ui()
        
        # Vérifier si des fichiers de données existent déjà
        if os.path.exists(self.key_file) and os.path.exists(self.password_file):
            self.login()
        else:
            self.create_master_password()
    
    def setup_ui(self):
        # Frame principal
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Cadre supérieur pour les boutons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=10)
        
        # Boutons
        ttk.Button(button_frame, text="Ajouter", command=self.add_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Modifier", command=self.edit_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Supprimer", command=self.delete_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Copier", command=self.copy_password).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Générer Mot de Passe", command=self.generate_password).pack(side=tk.LEFT, padx=5)
        
        # Barre de recherche
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_frame, text="Rechercher:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.search_passwords())
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Tableau des mots de passe
        columns = ("site", "username", "password")
        self.password_tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        
        # Définition des en-têtes
        self.password_tree.heading("site", text="Site")
        self.password_tree.heading("username", text="Nom d'utilisateur")
        self.password_tree.heading("password", text="Mot de passe")
        
        # Configuration des colonnes
        self.password_tree.column("site", width=250)
        self.password_tree.column("username", width=250)
        self.password_tree.column("password", width=250)
        
        # Ajout d'une barre de défilement
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        self.password_tree.configure(yscroll=scrollbar.set)
        
        # Empaquetage du tableau et de la barre de défilement
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Liaison du double-clic pour voir le mot de passe
        self.password_tree.bind("<Double-1>", lambda event: self.view_password())
        
        # Style
        style = ttk.Style()
        style.configure("Treeview", font=('Arial', 10))
        style.configure("Treeview.Heading", font=('Arial', 10, 'bold'))
    
    def create_master_password(self):
        # Demande à l'utilisateur de créer un mot de passe maître
        password = simpledialog.askstring("Configuration", "Créez un mot de passe maître:", show='*')
        if not password:
            messagebox.showerror("Erreur", "Un mot de passe maître est requis")
            self.root.destroy()
            return
        
        confirm_password = simpledialog.askstring("Configuration", "Confirmez le mot de passe maître:", show='*')
        if password != confirm_password:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
            self.create_master_password()
            return
        
        # Générer un sel aléatoire
        salt = secrets.token_bytes(16)
        
        # Dériver une clé à partir du mot de passe maître
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Sauvegarder le sel
        with open(self.key_file, "wb") as f:
            f.write(salt)
        
        # Initialiser Fernet avec la clé
        self.fernet = Fernet(key)
        self.master_password = password
        
        # Créer un fichier de mot de passe vide et chiffré
        self.passwords = {}
        self.save_passwords()
        
        messagebox.showinfo("Configuration", "Mot de passe maître créé avec succès!")
    
    def login(self):
        # Demande à l'utilisateur son mot de passe maître
        password = simpledialog.askstring("Connexion", "Entrez votre mot de passe maître:", show='*')
        if not password:
            messagebox.showerror("Erreur", "Mot de passe requis")
            self.root.destroy()
            return
        
        try:
            # Charger le sel
            with open(self.key_file, "rb") as f:
                salt = f.read()
            
            # Dériver la clé à partir du mot de passe et du sel
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            
            # Initialiser Fernet avec la clé
            self.fernet = Fernet(key)
            
            # Tester le déchiffrement
            self.load_passwords()
            
            self.master_password = password
            messagebox.showinfo("Connexion", "Connexion réussie!")
            
        except Exception as e:
            messagebox.showerror("Erreur", "Mot de passe incorrect ou fichier corrompu")
            self.login()
    
    def load_passwords(self):
        # Charger et déchiffrer les mots de passe
        try:
            with open(self.password_file, "rb") as f:
                encrypted_data = f.read()
            
            decrypted_data = self.fernet.decrypt(encrypted_data)
            self.passwords = json.loads(decrypted_data)
            
            # Mettre à jour l'affichage
            self.update_password_list()
            
        except FileNotFoundError:
            self.passwords = {}
        except Exception as e:
            raise e
    
    def save_passwords(self):
        # Chiffrer et sauvegarder les mots de passe
        encrypted_data = self.fernet.encrypt(json.dumps(self.passwords).encode())
        
        with open(self.password_file, "wb") as f:
            f.write(encrypted_data)
    
    def update_password_list(self):
        # Effacer la liste actuelle
        for item in self.password_tree.get_children():
            self.password_tree.delete(item)
        
        # Ajouter les entrées filtrées
        search_term = self.search_var.get().lower()
        for site, info in self.passwords.items():
            if search_term in site.lower() or search_term in info["username"].lower():
                # Masquer le mot de passe
                masked_password = "●" * len(info["password"])
                self.password_tree.insert("", tk.END, values=(site, info["username"], masked_password))
    
    def search_passwords(self):
        self.update_password_list()
    
    def add_password(self):
        # Créer une fenêtre de dialogue pour ajouter un mot de passe
        add_window = tk.Toplevel(self.root)
        add_window.title("Ajouter un mot de passe")
        add_window.geometry("400x200")
        add_window.resizable(False, False)
        
        ttk.Label(add_window, text="Site:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        site_var = tk.StringVar()
        ttk.Entry(add_window, textvariable=site_var, width=30).grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(add_window, text="Nom d'utilisateur:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(add_window, textvariable=username_var, width=30).grid(row=1, column=1, padx=10, pady=10)
        
        ttk.Label(add_window, text="Mot de passe:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(add_window, textvariable=password_var, width=30, show='*')
        password_entry.grid(row=2, column=1, padx=10, pady=10)
        
        # Bouton pour générer un mot de passe
        def generate():
            password_var.set(self.generate_random_password())
        
        ttk.Button(add_window, text="Générer", command=generate).grid(row=2, column=2, padx=5, pady=10)
        
        # Bouton pour afficher/masquer le mot de passe
        def toggle_password():
            if password_entry['show'] == '*':
                password_entry['show'] = ''
                show_button['text'] = "Masquer"
            else:
                password_entry['show'] = '*'
                show_button['text'] = "Afficher"
        
        show_button = ttk.Button(add_window, text="Afficher", command=toggle_password)
        show_button.grid(row=2, column=3, padx=5, pady=10)
        
        # Fonction pour sauvegarder l'entrée
        def save():
            site = site_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()
            
            if not site or not username or not password:
                messagebox.showerror("Erreur", "Tous les champs sont requis", parent=add_window)
                return
            
            if site in self.passwords:
                confirm = messagebox.askyesno("Attention", 
                    f"Une entrée pour {site} existe déjà. Voulez-vous la remplacer?", 
                    parent=add_window)
                if not confirm:
                    return
            
            self.passwords[site] = {
                "username": username,
                "password": password
            }
            
            self.save_passwords()
            self.update_password_list()
            add_window.destroy()
        
        ttk.Button(add_window, text="Sauvegarder", command=save).grid(row=3, column=0, columnspan=4, pady=20)
        
        # Centrer la fenêtre
        add_window.update_idletasks()
        width = add_window.winfo_width()
        height = add_window.winfo_height()
        x = (add_window.winfo_screenwidth() // 2) - (width // 2)
        y = (add_window.winfo_screenheight() // 2) - (height // 2)
        add_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        add_window.transient(self.root)
        add_window.grab_set()
    
    def edit_password(self):
        # Obtenir l'élément sélectionné
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showinfo("Information", "Veuillez sélectionner une entrée à modifier")
            return
        
        # Obtenir les informations de l'entrée sélectionnée
        item = self.password_tree.item(selected[0])
        site = item['values'][0]
        
        # Créer une fenêtre de dialogue pour éditer le mot de passe
        edit_window = tk.Toplevel(self.root)
        edit_window.title(f"Modifier {site}")
        edit_window.geometry("400x200")
        edit_window.resizable(False, False)
        
        ttk.Label(edit_window, text="Site:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        site_var = tk.StringVar(value=site)
        site_entry = ttk.Entry(edit_window, textvariable=site_var, width=30)
        site_entry.grid(row=0, column=1, padx=10, pady=10)
        site_entry.configure(state="readonly")  # Le site ne peut pas être modifié
        
        ttk.Label(edit_window, text="Nom d'utilisateur:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        username_var = tk.StringVar(value=self.passwords[site]["username"])
        ttk.Entry(edit_window, textvariable=username_var, width=30).grid(row=1, column=1, padx=10, pady=10)
        
        ttk.Label(edit_window, text="Mot de passe:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        password_var = tk.StringVar(value=self.passwords[site]["password"])
        password_entry = ttk.Entry(edit_window, textvariable=password_var, width=30, show='*')
        password_entry.grid(row=2, column=1, padx=10, pady=10)
        
        # Bouton pour générer un mot de passe
        def generate():
            password_var.set(self.generate_random_password())
        
        ttk.Button(edit_window, text="Générer", command=generate).grid(row=2, column=2, padx=5, pady=10)
        
        # Bouton pour afficher/masquer le mot de passe
        def toggle_password():
            if password_entry['show'] == '*':
                password_entry['show'] = ''
                show_button['text'] = "Masquer"
            else:
                password_entry['show'] = '*'
                show_button['text'] = "Afficher"
        
        show_button = ttk.Button(edit_window, text="Afficher", command=toggle_password)
        show_button.grid(row=2, column=3, padx=5, pady=10)
        
        # Fonction pour sauvegarder les modifications
        def save():
            username = username_var.get().strip()
            password = password_var.get()
            
            if not username or not password:
                messagebox.showerror("Erreur", "Tous les champs sont requis", parent=edit_window)
                return
            
            self.passwords[site] = {
                "username": username,
                "password": password
            }
            
            self.save_passwords()
            self.update_password_list()
            edit_window.destroy()
        
        ttk.Button(edit_window, text="Sauvegarder", command=save).grid(row=3, column=0, columnspan=4, pady=20)
        
        # Centrer la fenêtre
        edit_window.update_idletasks()
        width = edit_window.winfo_width()
        height = edit_window.winfo_height()
        x = (edit_window.winfo_screenwidth() // 2) - (width // 2)
        y = (edit_window.winfo_screenheight() // 2) - (height // 2)
        edit_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        edit_window.transient(self.root)
        edit_window.grab_set()
    
    def delete_password(self):
        # Obtenir l'élément sélectionné
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showinfo("Information", "Veuillez sélectionner une entrée à supprimer")
            return
        
        # Obtenir les informations de l'entrée sélectionnée
        item = self.password_tree.item(selected[0])
        site = item['values'][0]
        
        # Demander confirmation
        confirm = messagebox.askyesno("Confirmation", f"Êtes-vous sûr de vouloir supprimer l'entrée pour {site}?")
        if not confirm:
            return
        
        # Supprimer l'entrée
        del self.passwords[site]
        self.save_passwords()
        self.update_password_list()
    
    def copy_password(self):
        # Obtenir l'élément sélectionné
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showinfo("Information", "Veuillez sélectionner une entrée à copier")
            return
        
        # Obtenir les informations de l'entrée sélectionnée
        item = self.password_tree.item(selected[0])
        site = item['values'][0]
        
        # Copier le mot de passe dans le presse-papiers
        self.root.clipboard_clear()
        self.root.clipboard_append(self.passwords[site]["password"])
        
        messagebox.showinfo("Information", "Mot de passe copié dans le presse-papiers")
    
    def view_password(self):
        # Obtenir l'élément sélectionné
        selected = self.password_tree.selection()
        if not selected:
            return
        
        # Obtenir les informations de l'entrée sélectionnée
        item = self.password_tree.item(selected[0])
        site = item['values'][0]
        
        # Afficher le mot de passe
        messagebox.showinfo("Mot de passe", f"Site: {site}\nUtilisateur: {self.passwords[site]['username']}\nMot de passe: {self.passwords[site]['password']}")
    
    def generate_password(self):
        # Obtenir l'élément sélectionné
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showinfo("Information", "Veuillez sélectionner une entrée pour générer un mot de passe")
            return
        
        # Générer un mot de passe
        password = self.generate_random_password()
        
        # Demander confirmation
        confirm = messagebox.askyesno("Confirmation", f"Nouveau mot de passe généré:\n\n{password}\n\nVoulez-vous l'utiliser?")
        if not confirm:
            return
        
        # Obtenir les informations de l'entrée sélectionnée
        item = self.password_tree.item(selected[0])
        site = item['values'][0]
        
        # Mettre à jour le mot de passe
        self.passwords[site]["password"] = password
        self.save_passwords()
        self.update_password_list()
        
        # Copier le mot de passe dans le presse-papiers
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        
        messagebox.showinfo("Information", "Nouveau mot de passe généré et copié dans le presse-papiers")
    
    def generate_random_password(self, length=16):
        # Caractères pour le mot de passe
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        # Générer un mot de passe aléatoire
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        return password

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
