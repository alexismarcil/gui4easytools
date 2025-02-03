import base64
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext
import subprocess
import locale
import os
from pathlib import Path
from datetime import datetime
import psutil
import ctypes


class EZToolsGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("EZ Tools Forensics GUI")
        self.root.geometry("1000x800")
        #chemin pour timelineexplorer
        self.timeline_explorer_path = "../net6/TimelineExplorer/TimelineExplorer"
        
        # Définir l'icône de la fenêtre
        icon = tk.PhotoImage(file="danger.png")  
        self.root.iconphoto(True, icon)
        
        # Initialiser les variables
        self.selected_tool = None
        self.input_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.output_name = tk.StringVar()
        
        # Définir le lecteur par défaut
        self.drive = "C:"
        
        # Définir le chemin de base en fonction de l'emplacement du script
        base_path = os.path.dirname(os.path.abspath(__file__))

        self.tools = {
            "MFTECmd": {
                "description": "Analyse MFT",
                "extensions": [("All files", "*.*")],
                "command": os.path.abspath(os.path.join(base_path, "../net6/MFTECmd.exe")),  # Chemin absolu
                "direct_drive": True,
                "default_path": lambda drive: f"{drive}/$MFT"
            },
            "RECmd": {
                "description": "Analyse Registre",
                "extensions": [("All files", "*.*")],
                "command": os.path.abspath(os.path.join(base_path, "../net6/RECmd/RECmd.exe")),  # Chemin absolu
                "default_path": lambda drive: f"{drive}/Windows/System32/config"
            },
            "JLECmd": {
                "description": "Analyse Jump Lists",
                "extensions": [("All files", "*.*")],
                "command": os.path.abspath(os.path.join(base_path, "../net6/JLECmd.exe")),  # Chemin absolu
                "default_path": lambda drive, user: f"{drive}/Users/{user}/AppData/Roaming/Microsoft/Windows/Recent"
            },
            "PECmd": {
                "description": "Analyse Prefetch",
                "extensions": [("All files", "*.*")],
                "command": os.path.abspath(os.path.join(base_path, "../net6/PECmd.exe")),  # Chemin absolu
                "default_path": lambda drive: f"{drive}/Windows/Prefetch"
            }
        }
        
        # Configurer l'interface
        self.setup_gui()
        
        # Vérifier les privilèges
        if not is_admin():
            self.root.after(1000, lambda: self.show_admin_warning())
        
        # Afficher les informations sur les partitions lors de l'ouverture
        self.show_partition_info()

        self.console.insert(tk.END, "\n")  # Ligne vide pour espacement
        self.console.insert(tk.END, "\n")  # Ligne vide pour espacement
        self.console.insert(tk.END, "\n")  # Ligne vide pour espacement
        self.update_users_list()  # Afficher les utilisateurs trouvés une seule fois
        self.console.insert(tk.END, "\n")  # Ligne vide pour espacement
        self.console.insert(tk.END, "\n")  # Ligne vide pour espacement
        self.console.insert(tk.END, "\n")  # Ligne vide pour espacement

    def setup_gui(self):
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky="nsew")
        
        # Panneau de gauche pour les contrôles
        control_frame = ttk.Frame(main_frame)
        control_frame.grid(row=0, column=0, sticky="nsew", padx=(0,10))
        
        # Zone de sélection du lecteur
        drive_frame = ttk.LabelFrame(control_frame, text="Sélectionner le lecteur", padding="5")
        drive_frame.grid(row=0, column=0, sticky="ew", pady=(0,10))
        
        # Liste des lecteurs disponibles
        drives = [f"{chr(x)}:" for x in range(65, 91) if os.path.exists(f"{chr(x)}:")]
        self.drive_var = tk.StringVar(value=self.drive)
        
        drive_buttons_frame = ttk.Frame(drive_frame)
        drive_buttons_frame.pack(fill=tk.X, padx=5, pady=2)
        
        for drive in drives:
            tk.Radiobutton(
                drive_buttons_frame,
                text=drive,
                variable=self.drive_var,
                value=drive,
                font=('Arial', 10),
                command=self.on_drive_change
            ).pack(side=tk.LEFT, padx=5)
            
        # Zone de sélection de l'utilisateur
        user_frame = ttk.LabelFrame(control_frame, text="Sélectionner l'utilisateur", padding="5")
        user_frame.grid(row=1, column=0, sticky="ew", pady=(0,10))
        
        self.user_listbox = tk.Listbox(user_frame, height=5, font=('Arial', 10))
        self.user_listbox.pack(fill=tk.X, padx=5, pady=2)
        
        # Zone des outils
        tools_frame = ttk.LabelFrame(control_frame, text="Sélectionner l'outil", padding="5")
        tools_frame.grid(row=2, column=0, sticky="ew", pady=(0,10))
        
        self.tool_buttons = {}
        for idx, (tool_name, tool_info) in enumerate(self.tools.items()):
            btn = tk.Button(
                tools_frame,
                text=f"{tool_name}\n{tool_info['description']}",
                command=lambda t=tool_name: self.select_tool(t),
                relief="raised",
                bg="white",
                fg="black",
                height=2
            )
            btn.grid(row=idx, column=0, padx=5, pady=2, sticky="ew")
            self.tool_buttons[tool_name] = btn
            
        # Zone de sélection des fichiers
        files_frame = ttk.LabelFrame(control_frame, text="Sélectionner les fichiers", padding="5")
        files_frame.grid(row=3, column=0, sticky="ew", pady=(0,10))
        
        ttk.Button(files_frame, text="Choisir fichier d'entrée", command=self.select_input).grid(row=0, column=0, pady=5, sticky="ew")
        ttk.Label(files_frame, textvariable=self.input_path, wraplength=300).grid(row=1, column=0, pady=5)
        
        ttk.Button(files_frame, text="Choisir dossier de sortie", command=self.select_output).grid(row=2, column=0, pady=5, sticky="ew")
        ttk.Label(files_frame, textvariable=self.output_path, wraplength=300).grid(row=3, column=0, pady=5)
        
        # Nom de sortie
        ttk.Label(files_frame, text="Nom du fichier de sortie:").grid(row=4, column=0, pady=(5,0))
        ttk.Entry(files_frame, textvariable=self.output_name).grid(row=5, column=0, pady=5, sticky="ew")
        
        # Bouton d'exécution
        ttk.Button(control_frame, text="Lancer l'analyse", command=self.run_analysis).grid(row=4, column=0, sticky="ew")
        
        # Panneau de droite pour la console
        console_frame = ttk.LabelFrame(main_frame, text="Console", padding="5")
        console_frame.grid(row=0, column=1, sticky="nsew")
        
        self.console = scrolledtext.ScrolledText(console_frame, wrap=tk.WORD, height=40)
        self.console.grid(row=0, column=0, sticky="nsew")
        
        # Configuration du redimensionnement
        self.root.grid_rowconfigure(0, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        main_frame.grid_columnconfigure(1, weight=1)
        

        

    def select_tool(self, tool_name):
        if self.selected_tool:
            self.tool_buttons[self.selected_tool].configure(
                bg="white",
                fg="black",
                relief="raised"
            )
            # Réinitialiser le chemin d'entrée quand on change d'outil
            self.input_path.set("")
        
        self.selected_tool = tool_name
        self.tool_buttons[tool_name].configure(
            bg="#0078D7",
            fg="white",
            relief="sunken"
        )
        
        # Définir automatiquement le chemin d'entrée pour certains outils
        if tool_name == "MFTECmd":
            self.select_input()
        elif tool_name == "RECmd":
            config_path = f"{self.drive}\\Windows\\System32\\config"
            self.input_path.set(config_path)
            self.console.insert(tk.END, f"Entrée sélectionnée: {config_path}\n")

    def select_input(self):
        if not self.selected_tool:
            self.console.insert(tk.END, "Erreur: Sélectionnez d'abord un outil\n")
            return
            
        if self.selected_tool == "MFTECmd":
            mft_path = f"{self.drive}\\$MFT"
            self.input_path.set(mft_path)
            self.console.insert(tk.END, f"Entrée sélectionnée: {mft_path}\n")
            return
            
        elif self.selected_tool == "PECmd":
            prefetch_path = f"{self.drive}\\Windows\\Prefetch"
            self.input_path.set(prefetch_path)
            self.console.insert(tk.END, f"Entrée sélectionnée: {prefetch_path}\n")
            return
            
        elif self.selected_tool == "JLECmd":
            user = self.get_selected_user()
            if user:
                # Définir les deux chemins pour JLECmd
                custom_dest = f"{self.drive}\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\CustomDestinations"
                auto_dest = f"{self.drive}\\Users\\{user}\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\AutomaticDestinations"
                
                paths = []
                if os.path.exists(custom_dest):
                    paths.append(custom_dest)
                if os.path.exists(auto_dest):
                    paths.append(auto_dest)
                
                if paths:
                    self.input_path.set(";".join(paths))  # Utiliser ; comme séparateur
                    self.console.insert(tk.END, f"Entrées sélectionnées:\n")
                    for path in paths:
                        self.console.insert(tk.END, f"- {path}\n")
                else:
                    self.console.insert(tk.END, "Aucun dossier de Jump Lists trouvé\n")
                return
            
        # Pour RECmd
        initial_dir = f"{self.drive}\\Windows\\System32\\config"
        if not os.path.exists(initial_dir):
            initial_dir = self.drive + "\\"
            
        if self.selected_tool == "RECmd":
            dir_path = filedialog.askdirectory(
                title="Sélectionner le dossier des fichiers registre",
                initialdir=initial_dir
            )
            if dir_path:
                self.input_path.set(dir_path)
                self.console.insert(tk.END, f"Dossier sélectionné: {dir_path}\n")
            return
        
        # Pour les autres outils (si ajoutés plus tard)
        file_path = filedialog.askopenfilename(
            title=f"Sélectionner le fichier pour {self.selected_tool}",
            filetypes=self.tools[self.selected_tool]["extensions"],
            initialdir=initial_dir
        )
        if file_path:
            self.input_path.set(file_path)
            self.console.insert(tk.END, f"Entrée sélectionnée: {file_path}\n")

    def select_output(self):
        dir_path = filedialog.askdirectory(title="Sélectionner le dossier de sortie")
        if dir_path:
            self.output_path.set(dir_path)
            self.output_name.set(f"output_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
            self.console.insert(tk.END, f"Dossier de sortie sélectionné: {dir_path}\n")
            
    def run_analysis(self):
        if not all([self.selected_tool, self.input_path.get(), self.output_path.get()]):
            self.console.insert(tk.END, "Erreur: Tous les champs sont requis\n")
            return
        
        if self.selected_tool == "JLECmd":
            # Créer le dossier de sortie avec le nom choisi par l'utilisateur
            output_dir = os.path.join(self.output_path.get(), self.output_name.get())
            os.makedirs(output_dir, exist_ok=True)
            
            # Séparer les chemins et les traiter séquentiellement
            paths = self.input_path.get().split(";")
            
            csv_files = []  # Liste pour stocker les chemins des fichiers CSV créés
            
            for path in paths:
                self.console.insert(tk.END, f"\nTraitement du dossier: {path}\n")
                
                command = [
                    self.tools["JLECmd"]["command"],
                    "-d",
                    f'"{path}"',
                    "--csv",
                    f'"{output_dir}"'
                ]
                
                command = " ".join(filter(None, command))
                self.console.insert(tk.END, f"Exécution: {command}\n")
                
                try:
                    process = subprocess.Popen(
                        command,
                        shell=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        encoding='utf-8',
                        errors='replace'
                    )
                    
                    while True:
                        output = process.stdout.readline()
                        if output == '' and process.poll() is not None:
                            break
                        if output:
                            self.console.insert(tk.END, output)
                            self.console.see(tk.END)
                            self.root.update()
                    
                    stderr_output = process.stderr.read()
                    if stderr_output:
                        self.console.insert(tk.END, f"Erreurs: {stderr_output}\n")
                    
                    process.wait()
                    
                    if process.returncode != 0:
                        self.console.insert(tk.END, f"\nErreur lors de l'exécution (code {process.returncode})\n")
                        return
                        
                    # Ajouter les fichiers CSV créés à la liste
                    for file in os.listdir(output_dir):
                        if file.endswith('.csv'):
                            csv_files.append(os.path.join(output_dir, file))
                            
                except Exception as e:
                    self.console.insert(tk.END, f"Erreur: {str(e)}\n")
                    return
            
            self.console.insert(tk.END, "\nAnalyse terminée avec succès\n")
            self.console.insert(tk.END, f"Fichiers créés dans : {output_dir}\n")
            
            # Ouvrir chaque fichier CSV avec TimelineExplorer
            for csv_file in csv_files:
                self.open_with_timeline_explorer(csv_file)
        
        else:
            # Pour les autres outils
            output_file = Path(self.output_path.get()) / self.output_name.get()
            command = [
                self.tools[self.selected_tool]["command"],
                "-f" if self.selected_tool == "MFTECmd" else "-d",
                f'"{self.input_path.get()}"',
                "--csv",
                f'"{output_file}"'
            ]

            if self.selected_tool == "RECmd":
                reb_path = r"..\net6\RECmd\BatchExamples\CTL.reb"
                if os.path.exists(reb_path):
                    command.extend(["--bn", f'"{reb_path}"'])
                else:
                    self.console.insert(tk.END, f"Attention: Fichier .reb non trouvé à {reb_path}\n")
                    return
            
            command = " ".join(filter(None, command))
            self.console.insert(tk.END, f"Exécution: {command}\n")
            
            try:
                process = subprocess.Popen(
                    command,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    encoding='utf-8',
                    errors='replace'
                )
                
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        self.console.insert(tk.END, output)
                        self.console.see(tk.END)
                        self.root.update()
                
                stderr_output = process.stderr.read()
                if stderr_output:
                    self.console.insert(tk.END, f"Erreurs: {stderr_output}\n")
                
                process.wait()
                
                if process.returncode == 0:
                    self.console.insert(tk.END, "\nAnalyse terminée avec succès\n")
                    self.console.insert(tk.END, f"Fichier créé : {output_file}\n")
                    # Ouvrir le fichier CSV avec TimelineExplorer
                    self.open_with_timeline_explorer(output_file)
                else:
                    self.console.insert(tk.END, f"\nErreur lors de l'exécution (code {process.returncode})\n")
                    
            except Exception as e:
                self.console.insert(tk.END, f"Erreur: {str(e)}\n")

    def open_with_timeline_explorer(self, csv_file):
        """Ouvre un fichier CSV avec TimelineExplorer"""
        try:
            # Corriger le chemin pour inclure l'extension .exe
            timeline_explorer = os.path.abspath(os.path.join(os.path.dirname(__file__), self.timeline_explorer_path + ".exe"))
            
            if not os.path.exists(timeline_explorer):
                self.console.insert(tk.END, f"Erreur: TimelineExplorer non trouvé à {timeline_explorer}\n")
                return
                
            command = f'"{timeline_explorer}" "{csv_file}"'
            self.console.insert(tk.END, f"Ouverture avec TimelineExplorer: {csv_file}\n")
            
            subprocess.Popen(command, shell=True)
            
        except Exception as e:
            self.console.insert(tk.END, f"Erreur lors de l'ouverture avec TimelineExplorer: {str(e)}\n")

    def on_drive_change(self):
        # Mettre à jour le lecteur sélectionné
        self.drive = self.drive_var.get()
        
        # Effacer la console avant de mettre à jour
        self.console.delete('1.0', tk.END)

        #Réafficher la liste des partitions
        self.show_partition_info()

        # Mettre à jour la liste des utilisateurs
        self.update_users_list()
        
        
        
        # Si un outil est déjà sélectionné, mettre à jour le chemin d'entrée
        if self.selected_tool == "MFTECmd":
            self.select_input()
        
        # Forcer une mise à jour de l'interface
        self.root.update_idletasks()

    def show_partition_info(self):
        """Affiche les informations détaillées sur les disques physiques et leurs partitions"""
        try:
            # Utiliser PowerShell pour obtenir les informations détaillées des disques physiques
            powershell_script = '''
            Get-Disk | ForEach-Object {
                $diskNumber = $_.Number
                $diskSize = [math]::Round($_.Size / 1GB, 2)
                $diskType = $_.MediaType
                
                Write-Host ("Disque physique #" + $diskNumber + " - Type: " + $diskType + " - Taille: " + $diskSize + " Go")

                Get-Partition -DiskNumber $diskNumber | ForEach-Object {
                    $partition = $_
                    $volume = Get-Volume -Partition $partition
                    $driveLetter = if ($volume.DriveLetter) { $volume.DriveLetter + ":" } else { "Non assigné" }
                    Write-Host ("  Partition " + $partition.PartitionNumber + 
                                " - Type: " + $partition.Type + 
                                " - Taille: " + [math]::Round($partition.Size / 1GB, 2) + " Go" +
                                " - File system: " + $volume.FileSystem +
                                " - Lecteur: " + $driveLetter)
                }
                Write-Host ""
            }
            '''
            
            # Exécuter le script PowerShell
            output = subprocess.check_output(["powershell", "-Command", powershell_script], 
                                            universal_newlines=True, 
                                            stderr=subprocess.STDOUT)
            
            # Afficher les résultats dans la console
            self.console.insert(tk.END, output)
            
        except Exception as e:
            self.console.insert(tk.END, f"Erreur lors de la récupération des informations de disque: {str(e)}\n")

    def show_admin_warning(self):
        """Affiche un avertissement dans la console si le programme n'est pas exécuté en tant qu'administrateur"""
        self.console.insert(tk.END, "⚠️ ATTENTION: Programme lancé sans privilèges administrateur.\n")
        self.console.insert(tk.END, "Certaines fonctionnalités pourraient ne pas fonctionner correctement.\n\n")
        self.console.see(tk.END)  # Fait défiler jusqu'au dernier message

    def update_users_list(self):
        """Met à jour la liste des utilisateurs en fonction du lecteur sélectionné"""
        self.user_listbox.delete(0, tk.END)  # Effacer la liste actuelle
        users_path = f"{self.drive}\\Users" if os.path.exists(f"{self.drive}\\Users") else f"{self.drive}\\Utilisateurs"
        
        
        if os.path.exists(users_path):
            try:
                # Lister tous les dossiers dans Users/Utilisateurs sauf les dossiers système
                users = []
                for d in os.listdir(users_path):
                    full_path = os.path.join(users_path, d)
                    if (os.path.isdir(full_path) 
                        and not d.startswith(".") 
                        and d not in ["Public", "Default", "Default User", "All Users", "defaultuser0"]):
                        users.append(d)
                
                for user in users:
                    self.user_listbox.insert(tk.END, user)
                if users:  # Sélectionner le premier utilisateur par défaut
                    self.user_listbox.selection_set(0)
                    
                self.console.insert(tk.END, f"Utilisateurs trouvés: {', '.join(users)}\n")
            except Exception as e:
                self.console.insert(tk.END, f"Erreur lors de la lecture des utilisateurs: {str(e)}\n")
        else:
            self.console.insert(tk.END, f"Dossier Users/Utilisateurs non trouvé sur le lecteur {self.drive}\n")

    def get_selected_user(self):
        """Retourne l'utilisateur sélectionné ou None"""
        selection = self.user_listbox.curselection()
        if selection:
            return self.user_listbox.get(selection[0])
        return None

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def main():
    root = tk.Tk()
    app = EZToolsGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
