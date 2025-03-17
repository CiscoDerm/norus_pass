import tkinter as tk
from tkinter import ttk, messagebox, simpledialog, filedialog
import json
import os
import base64
import secrets
import datetime
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
        self.current_theme = "light"
        
        # Catégories par défaut
        self.categories = ["Email", "Réseaux sociaux", "Finance", "Travail", "Personnel", "Divers"]
        self.selected_category = "Tous"
        
        self.style = ttk.Style()
        self.setup_ui()
        self.create_menu()
        
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
        
        # Barre de recherche et sélection de catégorie
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=10)
        
        ttk.Label(search_frame, text="Catégorie:").pack(side=tk.LEFT, padx=5)
        self.category_var = tk.StringVar(value="Tous")
        category_menu = ttk.Combobox(search_frame, textvariable=self.category_var, 
                                    values=["Tous"] + self.categories, width=15, state="readonly")
        category_menu.pack(side=tk.LEFT, padx=5)
        category_menu.bind("<<ComboboxSelected>>", lambda e: self.filter_by_category())
        
        ttk.Label(search_frame, text="Rechercher:").pack(side=tk.LEFT, padx=5)
        self.search_var = tk.StringVar()
        self.search_var.trace("w", lambda name, index, mode: self.search_passwords())
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=30)
        search_entry.pack(side=tk.LEFT, padx=5)
        
        # Tableau des mots de passe avec catégories
        columns = ("category", "site", "username", "password")
        self.password_tree = ttk.Treeview(main_frame, columns=columns, show="headings")
        
        # Définition des en-têtes
        self.password_tree.heading("category", text="Catégorie")
        self.password_tree.heading("site", text="Site")
        self.password_tree.heading("username", text="Nom d'utilisateur")
        self.password_tree.heading("password", text="Mot de passe")
        
        # Configuration des colonnes
        self.password_tree.column("category", width=120)
        self.password_tree.column("site", width=200)
        self.password_tree.column("username", width=200)
        self.password_tree.column("password", width=200)
        
        # Ajout d'une barre de défilement
        scrollbar = ttk.Scrollbar(main_frame, orient=tk.VERTICAL, command=self.password_tree.yview)
        self.password_tree.configure(yscroll=scrollbar.set)
        
        # Empaquetage du tableau et de la barre de défilement
        self.password_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Liaison du double-clic pour voir le mot de passe
        self.password_tree.bind("<Double-1>", lambda event: self.view_password())
        
        # Style initial
        self.style.configure("Treeview", font=('Arial', 10))
        self.style.configure("Treeview.Heading", font=('Arial', 10, 'bold'))
        
        # Configuration du thème clair par défaut
        self.set_light_theme()
    
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
        
        # Filtrer par catégorie et recherche
        search_term = self.search_var.get().lower()
        selected_category = self.category_var.get()
        
        for site, info in self.passwords.items():
            category = info.get("category", "Divers")  # Par défaut "Divers" si non spécifié
            match_search = search_term in site.lower() or search_term in info["username"].lower()
            match_category = selected_category == "Tous" or category == selected_category
            
            if match_search and match_category:
                # Masquer le mot de passe
                masked_password = "●" * len(info["password"])
                self.password_tree.insert("", tk.END, values=(category, site, info["username"], masked_password))
    
    def search_passwords(self):
        self.update_password_list()
    
    def filter_by_category(self):
        self.update_password_list()
    
    def add_password(self):
        # Créer une fenêtre de dialogue pour ajouter un mot de passe
        add_window = tk.Toplevel(self.root)
        add_window.title("Ajouter un mot de passe")
        add_window.geometry("400x240")
        add_window.resizable(False, False)
        
        ttk.Label(add_window, text="Catégorie:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        category_var = tk.StringVar(value="Divers")
        category_combo = ttk.Combobox(add_window, textvariable=category_var, values=self.categories, width=28, state="readonly")
        category_combo.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(add_window, text="Site:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        site_var = tk.StringVar()
        ttk.Entry(add_window, textvariable=site_var, width=30).grid(row=1, column=1, padx=10, pady=10)
        
        ttk.Label(add_window, text="Nom d'utilisateur:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        username_var = tk.StringVar()
        ttk.Entry(add_window, textvariable=username_var, width=30).grid(row=2, column=1, padx=10, pady=10)
        
        ttk.Label(add_window, text="Mot de passe:").grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        password_var = tk.StringVar()
        password_entry = ttk.Entry(add_window, textvariable=password_var, width=30, show='*')
        password_entry.grid(row=3, column=1, padx=10, pady=10)
        
        # Bouton pour générer un mot de passe
        def generate():
            password_var.set(self.generate_random_password())
        
        ttk.Button(add_window, text="Générer", command=generate).grid(row=3, column=2, padx=5, pady=10)
        
        # Bouton pour afficher/masquer le mot de passe
        def toggle_password():
            if password_entry['show'] == '*':
                password_entry['show'] = ''
                show_button['text'] = "Masquer"
            else:
                password_entry['show'] = '*'
                show_button['text'] = "Afficher"
        
        show_button = ttk.Button(add_window, text="Afficher", command=toggle_password)
        show_button.grid(row=3, column=3, padx=5, pady=10)
        
        # Fonction pour sauvegarder l'entrée
        def save():
            category = category_var.get().strip()
            site = site_var.get().strip()
            username = username_var.get().strip()
            password = password_var.get()
            
            if not site or not username or not password:
                messagebox.showerror("Erreur", "Tous les champs site, nom d'utilisateur et mot de passe sont requis", parent=add_window)
                return
            
            if site in self.passwords:
                confirm = messagebox.askyesno("Attention", 
                    f"Une entrée pour {site} existe déjà. Voulez-vous la remplacer?", 
                    parent=add_window)
                if not confirm:
                    return
            
            self.passwords[site] = {
                "category": category,
                "username": username,
                "password": password,
                "created_date": datetime.datetime.now().isoformat(),
                "last_modified": datetime.datetime.now().isoformat()
            }
            
            self.save_passwords()
            self.update_password_list()
            add_window.destroy()
        
        ttk.Button(add_window, text="Sauvegarder", command=save).grid(row=4, column=0, columnspan=4, pady=20)
        
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
        site = item['values'][1]  # Site est maintenant à l'index 1 car la catégorie est à l'index 0
        
        # Créer une fenêtre de dialogue pour éditer le mot de passe
        edit_window = tk.Toplevel(self.root)
        edit_window.title(f"Modifier {site}")
        edit_window.geometry("400x240")
        edit_window.resizable(False, False)
        
        current_category = self.passwords[site].get("category", "Divers")
        
        ttk.Label(edit_window, text="Catégorie:").grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        category_var = tk.StringVar(value=current_category)
        category_combo = ttk.Combobox(edit_window, textvariable=category_var, values=self.categories, width=28, state="readonly")
        category_combo.grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(edit_window, text="Site:").grid(row=1, column=0, padx=10, pady=10, sticky=tk.W)
        site_var = tk.StringVar(value=site)
        site_entry = ttk.Entry(edit_window, textvariable=site_var, width=30)
        site_entry.grid(row=1, column=1, padx=10, pady=10)
        site_entry.configure(state="readonly")  # Le site ne peut pas être modifié
        
        ttk.Label(edit_window, text="Nom d'utilisateur:").grid(row=2, column=0, padx=10, pady=10, sticky=tk.W)
        username_var = tk.StringVar(value=self.passwords[site]["username"])
        ttk.Entry(edit_window, textvariable=username_var, width=30).grid(row=2, column=1, padx=10, pady=10)
        
        ttk.Label(edit_window, text="Mot de passe:").grid(row=3, column=0, padx=10, pady=10, sticky=tk.W)
        password_var = tk.StringVar(value=self.passwords[site]["password"])
        password_entry = ttk.Entry(edit_window, textvariable=password_var, width=30, show='*')
        password_entry.grid(row=3, column=1, padx=10, pady=10)
        
        # Bouton pour générer un mot de passe
        def generate():
            password_var.set(self.generate_random_password())
        
        ttk.Button(edit_window, text="Générer", command=generate).grid(row=3, column=2, padx=5, pady=10)
        
        # Bouton pour afficher/masquer le mot de passe
        def toggle_password():
            if password_entry['show'] == '*':
                password_entry['show'] = ''
                show_button['text'] = "Masquer"
            else:
                password_entry['show'] = '*'
                show_button['text'] = "Afficher"
        
        show_button = ttk.Button(edit_window, text="Afficher", command=toggle_password)
        show_button.grid(row=3, column=3, padx=5, pady=10)
        
        # Fonction pour sauvegarder les modifications
        def save():
            category = category_var.get()
            username = username_var.get().strip()
            password = password_var.get()
            
            if not username or not password:
                messagebox.showerror("Erreur", "Tous les champs sont requis", parent=edit_window)
                return
            
            # Conserver les informations existantes (dates, etc.)
            existing_data = dict(self.passwords[site])
            existing_data.update({
                "category": category,
                "username": username,
                "password": password,
                "last_modified": datetime.datetime.now().isoformat()
            })
            self.passwords[site] = existing_data
            
            self.save_passwords()
            self.update_password_list()
            edit_window.destroy()
    
    def delete_password(self):
        # Obtenir l'élément sélectionné
        selected = self.password_tree.selection()
        if not selected:
            messagebox.showinfo("Information", "Veuillez sélectionner une entrée à supprimer")
            return
        
        # Obtenir les informations de l'entrée sélectionnée
        item = self.password_tree.item(selected[0])
        site = item['values'][1]  # Site est maintenant à l'index 1
        
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
        site = item['values'][1]  # Site est maintenant à l'index 1
        
        # Copier le mot de passe dans le presse-papiers et programmer son effacement
        self.copy_password_with_timeout(self.passwords[site]["password"])
    
    def copy_password_with_timeout(self, password, timeout=30):
        self.root.clipboard_clear()
        self.root.clipboard_append(password)
        messagebox.showinfo("Information", f"Mot de passe copié dans le presse-papiers pour {timeout} secondes")
        self.root.after(timeout * 1000, self.clear_clipboard)
    
    def clear_clipboard(self):
        self.root.clipboard_clear()
        self.root.clipboard_append("")
    
    def view_password(self):
        # Obtenir l'élément sélectionné
        selected = self.password_tree.selection()
        if not selected:
            return
        
        # Obtenir les informations de l'entrée sélectionnée
        item = self.password_tree.item(selected[0])
        site = item['values'][1]  # Site est maintenant à l'index 1
        
        # Afficher le mot de passe
        messagebox.showinfo("Mot de passe", f"Catégorie: {self.passwords[site].get('category', 'Divers')}\nSite: {site}\nUtilisateur: {self.passwords[site]['username']}\nMot de passe: {self.passwords[site]['password']}")
    
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
        site = item['values'][1]  # Site est maintenant à l'index 1
        
        # Mettre à jour le mot de passe
        self.passwords[site]["password"] = password
        self.passwords[site]["last_modified"] = datetime.datetime.now().isoformat()
        self.save_passwords()
        self.update_password_list()
        
        # Copier le mot de passe dans le presse-papiers avec timeout
        self.copy_password_with_timeout(password)
    
    def generate_random_password(self, length=16):
        # Caractères pour le mot de passe
        chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
        
        # Générer un mot de passe aléatoire
        password = ''.join(secrets.choice(chars) for _ in range(length))
        
        return password
        
    # Fonctions pour les thèmes
    def set_light_theme(self):
        self.style.configure(".", background="#f0f0f0", foreground="black")
        self.style.configure("Treeview", background="white", fieldbackground="white", foreground="black")
        self.style.map('Treeview', background=[('selected', '#0078d7')])
        self.current_theme = "light"
    
    def set_dark_theme(self):
        self.style.configure(".", background="#2d2d2d", foreground="white")
        self.style.configure("Treeview", background="#3d3d3d", fieldbackground="#3d3d3d", foreground="white")
        self.style.map('Treeview', background=[('selected', '#0078d7')])
        self.current_theme = "dark"
    
    def toggle_theme(self):
        if self.current_theme == "light":
            self.set_dark_theme()
        else:
            self.set_light_theme()
            
    # Fonctions pour l'exportation/importation
    def export_data(self):
        # Demander où enregistrer le fichier exporté
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Exporter les données"
        )
        if not filename:
            return
            
        # Demander le mot de passe pour confirmer l'export
        password = simpledialog.askstring(
            "Sécurité", "Entrez votre mot de passe maître pour confirmer l'export:", show='*'
        )
        if not password or password != self.master_password:
            messagebox.showerror("Erreur", "Mot de passe incorrect")
            return
            
        # Préparer les données pour l'export (sans les mots de passe en clair)
        export_data = {}
        for site, info in self.passwords.items():
            export_data[site] = dict(info)
            # Masquer le mot de passe réel pour la sécurité
            export_data[site]["password"] = "********"
            
        # Sauvegarder les données
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("Export", "Données exportées avec succès (mots de passe masqués pour la sécurité)")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export: {str(e)}")
    
    def export_data_with_passwords(self):
        # Avertissement sur la sécurité
        warning = messagebox.askokcancel(
            "Avertissement de sécurité", 
            "Attention: Vous êtes sur le point d'exporter vos mots de passe en clair.\n\n"
            "Ce fichier ne sera PAS chiffré et quiconque y a accès pourra voir vos mots de passe.\n\n"
            "Continuez uniquement si vous êtes dans un environnement sécurisé."
        )
        if not warning:
            return
            
        # Demander où enregistrer le fichier exporté
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Exporter les données (avec mots de passe)"
        )
        if not filename:
            return
            
        # Double vérification du mot de passe
        password = simpledialog.askstring(
            "Sécurité", "Entrez votre mot de passe maître pour confirmer l'export des mots de passe:", show='*'
        )
        if not password or password != self.master_password:
            messagebox.showerror("Erreur", "Mot de passe incorrect")
            return
            
        # Sauvegarder les données complètes
        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(self.passwords, f, indent=4, ensure_ascii=False)
            messagebox.showinfo("Export", "Données et mots de passe exportés avec succès")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'export: {str(e)}")
    
    def import_data(self):
        # Demander le fichier à importer
        filename = filedialog.askopenfilename(
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            title="Importer des données"
        )
        if not filename:
            return
            
        # Demander confirmation
        confirm = messagebox.askyesno(
            "Confirmation",
            "L'importation va ajouter de nouvelles entrées à votre base de données actuelle.\n"
            "Les entrées existantes ne seront pas écrasées.\n\n"
            "Voulez-vous continuer?"
        )
        if not confirm:
            return
            
        # Charger les données importées
        try:
            with open(filename, "r", encoding="utf-8") as f:
                imported_data = json.load(f)
                
            # Vérifier le format des données
            if not isinstance(imported_data, dict):
                messagebox.showerror("Erreur", "Format de fichier invalide")
                return
                
            # Compter les entrées ajoutées
            added_count = 0
            skipped_count = 0
            
            # Ajouter les nouvelles entrées
            for site, info in imported_data.items():
                if site not in self.passwords:
                    # Vérifier les champs requis
                    if "username" in info and info.get("password") != "********":
                        # S'assurer que la catégorie existe
                        if "category" in info and info["category"] not in self.categories:
                            self.categories.append(info["category"])
                            
                        # Ajouter l'horodatage si absent
                        if "created_date" not in info:
                            info["created_date"] = datetime.datetime.now().isoformat()
                        if "last_modified" not in info:
                            info["last_modified"] = datetime.datetime.now().isoformat()
                            
                        self.passwords[site] = info
                        added_count += 1
                    else:
                        skipped_count += 1
                else:
                    skipped_count += 1
                    
            # Sauvegarder et mettre à jour
            self.save_passwords()
            self.update_password_list()
            
            messagebox.showinfo(
                "Import terminé", 
                f"{added_count} entrées ont été ajoutées.\n{skipped_count} entrées ont été ignorées."
            )
            
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'import: {str(e)}")
    
    # Fonction pour créer la barre de menu
    def create_menu(self):
        menubar = tk.Menu(self.root)
        
        # Menu Fichier
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Changer le mot de passe maître", command=self.change_master_password)
        file_menu.add_separator()
        file_menu.add_command(label="Exporter (sécurisé)", command=self.export_data)
        file_menu.add_command(label="Exporter avec mots de passe", command=self.export_data_with_passwords)
        file_menu.add_command(label="Importer", command=self.import_data)
        file_menu.add_separator()
        file_menu.add_command(label="Quitter", command=self.root.quit)
        menubar.add_cascade(label="Fichier", menu=file_menu)
        
        # Menu Édition
        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Ajouter un mot de passe", command=self.add_password)
        edit_menu.add_command(label="Modifier le mot de passe sélectionné", command=self.edit_password)
        edit_menu.add_command(label="Supprimer le mot de passe sélectionné", command=self.delete_password)
        edit_menu.add_command(label="Copier le mot de passe", command=self.copy_password)
        edit_menu.add_command(label="Générer un nouveau mot de passe", command=self.generate_password)
        menubar.add_cascade(label="Édition", menu=edit_menu)
        
        # Menu Affichage
        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Thème clair", command=self.set_light_theme)
        view_menu.add_command(label="Thème sombre", command=self.set_dark_theme)
        menubar.add_cascade(label="Affichage", menu=view_menu)
        
        # Menu Catégories
        category_menu = tk.Menu(menubar, tearoff=0)
        category_menu.add_command(label="Gérer les catégories", command=self.manage_categories)
        menubar.add_cascade(label="Catégories", menu=category_menu)
        
        # Menu Aide
        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="À propos", command=self.show_about)
        menubar.add_cascade(label="Aide", menu=help_menu)
        
        self.root.config(menu=menubar)
    
    def change_master_password(self):
        # Demander l'ancien mot de passe
        old_password = simpledialog.askstring("Sécurité", "Entrez votre mot de passe maître actuel:", show='*')
        if not old_password or old_password != self.master_password:
            messagebox.showerror("Erreur", "Mot de passe incorrect")
            return
            
        # Demander le nouveau mot de passe
        new_password = simpledialog.askstring("Sécurité", "Entrez votre nouveau mot de passe maître:", show='*')
        if not new_password:
            messagebox.showerror("Erreur", "Le nouveau mot de passe ne peut pas être vide")
            return
            
        # Confirmer le nouveau mot de passe
        confirm_password = simpledialog.askstring("Sécurité", "Confirmez votre nouveau mot de passe maître:", show='*')
        if new_password != confirm_password:
            messagebox.showerror("Erreur", "Les mots de passe ne correspondent pas")
            return
            
        # Générer un nouveau sel
        salt = secrets.token_bytes(16)
        
        # Dériver une nouvelle clé
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(new_password.encode()))
        
        # Sauvegarder le sel
        with open(self.key_file, "wb") as f:
            f.write(salt)
        
        # Mettre à jour Fernet avec la nouvelle clé
        self.fernet = Fernet(key)
        self.master_password = new_password
        
        # Rechiffrer et sauvegarder les mots de passe
        self.save_passwords()
        
        messagebox.showinfo("Sécurité", "Mot de passe maître changé avec succès!")
    
    def manage_categories(self):
        # Créer une fenêtre pour gérer les catégories
        cat_window = tk.Toplevel(self.root)
        cat_window.title("Gérer les catégories")
        cat_window.geometry("400x300")
        cat_window.resizable(False, False)
        
        # Liste des catégories
        ttk.Label(cat_window, text="Catégories actuelles:").pack(pady=10)
        
        # Créer un frame avec scrollbar pour la liste
        list_frame = ttk.Frame(cat_window)
        list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        scrollbar = ttk.Scrollbar(list_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        category_listbox = tk.Listbox(list_frame, height=10, width=40, yscrollcommand=scrollbar.set)
        category_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar.config(command=category_listbox.yview)
        
        # Remplir la liste
        for category in self.categories:
            category_listbox.insert(tk.END, category)
        
        # Frame pour ajouter/supprimer des catégories
        action_frame = ttk.Frame(cat_window)
        action_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Label(action_frame, text="Nouvelle catégorie:").grid(row=0, column=0, padx=5, pady=5)
        new_cat_var = tk.StringVar()
        new_cat_entry = ttk.Entry(action_frame, textvariable=new_cat_var, width=20)
        new_cat_entry.grid(row=0, column=1, padx=5, pady=5)
        
        # Fonction pour ajouter une catégorie
        def add_category():
            new_cat = new_cat_var.get().strip()
            if not new_cat:
                messagebox.showerror("Erreur", "La catégorie ne peut pas être vide", parent=cat_window)
                return
                
            if new_cat in self.categories:
                messagebox.showerror("Erreur", "Cette catégorie existe déjà", parent=cat_window)
                return
                
            self.categories.append(new_cat)
            category_listbox.insert(tk.END, new_cat)
            new_cat_var.set("")
        
        # Fonction pour supprimer une catégorie
        def delete_category():
            selection = category_listbox.curselection()
            if not selection:
                messagebox.showinfo("Information", "Veuillez sélectionner une catégorie", parent=cat_window)
                return
                
            category = category_listbox.get(selection[0])
            
            # Vérifier si la catégorie est utilisée
            is_used = False
            for site, info in self.passwords.items():
                if info.get("category") == category:
                    is_used = True
                    break
                    
            if is_used:
                confirm = messagebox.askyesno(
                    "Attention", 
                    f"La catégorie '{category}' est utilisée par certains mots de passe. "
                    f"Si vous la supprimez, ces mots de passe seront déplacés dans 'Divers'.\n\n"
                    f"Voulez-vous continuer?",
                    parent=cat_window
                )
                if not confirm:
                    return
                    
                # Déplacer les mots de passe vers Divers
                for site, info in self.passwords.items():
                    if info.get("category") == category:
                        info["category"] = "Divers"
                        
                self.save_passwords()
            
            # Supprimer la catégorie
            self.categories.remove(category)
            category_listbox.delete(selection[0])
            
            # Mettre à jour l'interface
            self.update_password_list()
        
        ttk.Button(action_frame, text="Ajouter", command=add_category).grid(row=0, column=2, padx=5, pady=5)
        ttk.Button(action_frame, text="Supprimer sélection", command=delete_category).grid(row=1, column=1, columnspan=2, padx=5, pady=5)
        
        # Bouton de fermeture
        ttk.Button(cat_window, text="Fermer", command=cat_window.destroy).pack(pady=10)
        
        # Centrer la fenêtre
        cat_window.update_idletasks()
        width = cat_window.winfo_width()
        height = cat_window.winfo_height()
        x = (cat_window.winfo_screenwidth() // 2) - (width // 2)
        y = (cat_window.winfo_screenheight() // 2) - (height // 2)
        cat_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
        
        cat_window.transient(self.root)
        cat_window.grab_set()
    
    def show_about(self):
        messagebox.showinfo(
            "À propos", 
            "SecurePass - Gestionnaire de mots de passe sécurisé\n\n"
            "Version 1.0\n\n"
            "Développé avec Python et Tkinter\n"
            "Chiffrement AES-256 via Fernet\n\n"
            "© 2025 Tous droits réservés"
        )

if __name__ == "__main__":
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()
