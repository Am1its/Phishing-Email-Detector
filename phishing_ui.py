import customtkinter as ctk 
from tkinter import filedialog
from phishing_detector import PhishingScanner

# --- Global UI Configuration ---
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class PhishingApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ Cyber Phishing Detector")
        self.geometry("700x650") 
        
        self.scanner = PhishingScanner()

        # 1. Header
        self.label = ctk.CTkLabel(self, text="Email Threat Scanner", font=("Roboto", 24, "bold"))
        self.label.pack(pady=(20, 10))

        # 2. Input Section
        self.text_area = ctk.CTkTextbox(self, width=600, height=180, font=("Consolas", 14))
        self.text_area.pack(pady=10)
        self.text_area.insert("0.0", "Paste email content here or load a file...")

        # 3. Controls
        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=10)

        self.btn_load = ctk.CTkButton(self.btn_frame, text="📂 Load File", command=self.load_file, width=150)
        self.btn_load.pack(side="left", padx=10)

        self.btn_scan = ctk.CTkButton(self.btn_frame, text="🔍 SCAN NOW", command=self.run_scan, width=150, fg_color="#d9534f", hover_color="#c9302c")
        self.btn_scan.pack(side="left", padx=10)

        # 4. Score Section (חדש!)
        self.score_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.score_frame.pack(pady=(10, 0))
        
        self.score_label = ctk.CTkLabel(self.score_frame, text="Risk Score: 0%", font=("Roboto", 22, "bold"), text_color="#888")
        self.score_label.pack()
        
        self.progress_bar = ctk.CTkProgressBar(self.score_frame, width=400, height=15)
        self.progress_bar.set(0)
        self.progress_bar.pack(pady=5)

        # 5. Detailed Results
        self.result_label = ctk.CTkLabel(self, text="Detailed Findings:", font=("Roboto", 16))
        self.result_label.pack(pady=(15, 5), anchor="w", padx=50)
        
        self.result_area = ctk.CTkTextbox(self, width=600, height=150, font=("Consolas", 14), fg_color="#1e1e1e")
        self.result_area.pack(pady=10)
        self.result_area.configure(state="disabled")

    def load_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "r", encoding="utf-8") as f:
                self.text_area.delete("0.0", "end")
                self.text_area.insert("0.0", f.read())

    def run_scan(self):
        content = self.text_area.get("0.0", "end").strip()
        threats = self.scanner.run_scan(content)
        
        # --- Risk Score Calculation ---
        score = 0
        for t in threats:
            if "Suspicious Link" in t: score += 40
            elif "Spoofing" in t: score += 50
            elif "Urgency" in t: score += 10
            else: score += 10
        
        if score > 100: score = 100
        

        
        self.result_area.configure(state="normal")
        self.result_area.delete("0.0", "end")
        self.progress_bar.set(score / 100)
        
        if score == 0:
            self.score_label.configure(text=f"Risk Score: {score}% (SAFE)", text_color="#00cc66")
            self.progress_bar.configure(progress_color="#00cc66")
            self.result_area.insert("0.0", "✅ CLEAN: No threats detected.")
            self.result_area.configure(text_color="#00cc66")
        else:
            self.score_label.configure(text=f"Risk Score: {score}% (CRITICAL)", text_color="#ff4444")
            self.progress_bar.configure(progress_color="#ff4444")
            text = "\n".join([f"• {t}" for t in threats])
            self.result_area.insert("0.0", text)
            self.result_area.configure(text_color="#ff4444")
        
        self.result_area.configure(state="disabled")

if __name__ == "__main__":
    app = PhishingApp()
    app.mainloop()
