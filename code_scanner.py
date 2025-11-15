import os
import tkinter as tk
from tkinter import ttk, messagebox
import threading

class CodeScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("代码库扫描工具")
        self.root.geometry("600x400")
        
        # 创建界面组件
        self.create_widgets()
        
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="代码库扫描工具", font=("Arial", 16))
        title_label.grid(row=0, column=0, columnspan=2, pady=10)
        
        # 扫描按钮
        self.scan_button = ttk.Button(main_frame, text="开始扫描", command=self.start_scan)
        self.scan_button.grid(row=1, column=0, pady=10, sticky=tk.W)
        
        # 进度条
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=1, column=1, pady=10, sticky=(tk.W, tk.E))
        
        # 结果文本框
        self.result_text = tk.Text(main_frame, height=15, width=70)
        self.result_text.grid(row=2, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 滚动条
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.result_text.yview)
        scrollbar.grid(row=2, column=2, sticky=(tk.N, tk.S))
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        # 配置网格权重
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
    def start_scan(self):
        # 禁用扫描按钮，启动进度条
        self.scan_button.config(state='disabled')
        self.progress.start(10)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "正在扫描...\n")
        
        # 在新线程中执行扫描
        thread = threading.Thread(target=self.scan_drives)
        thread.daemon = True
        thread.start()
        
    def scan_drives(self):
        try:
            # 获取所有驱动器
            drives = self.get_available_drives()
            git_repos = []
            
            for drive in drives:
                self.update_result(f"扫描驱动器: {drive}")
                
                # 遍历驱动器查找.git文件夹
                for root_dir, dirs, files in os.walk(drive):
                    if '.git' in dirs:
                        git_path = os.path.join(root_dir, '.git')
                        git_repos.append(root_dir)
                        self.update_result(f"发现代码库: {root_dir}")
            
            # 扫描完成
            self.scan_complete(git_repos)
            
        except Exception as e:
            self.scan_complete([], str(e))
    
    def get_available_drives(self):
        # 获取Windows系统下的所有驱动器
        drives = []
        for drive in range(ord('A'), ord('Z')+1):
            drive_letter = chr(drive) + ":\\"
            if os.path.exists(drive_letter):
                drives.append(drive_letter)
        return drives
    
    def update_result(self, message):
        # 线程安全地更新结果文本框
        self.root.after(0, lambda: self.result_text.insert(tk.END, message + "\n"))
    
    def scan_complete(self, git_repos, error=None):
        # 扫描完成后的处理
        def complete():
            self.progress.stop()
            self.scan_button.config(state='normal')
            
            if error:
                messagebox.showerror("错误", f"扫描过程中发生错误: {error}")
                return
            
            if not git_repos:
                self.result_text.insert(tk.END, "未发现任何代码库")
            else:
                self.result_text.insert(tk.END, f"\n扫描完成! 共发现 {len(git_repos)} 个代码库")
        
        self.root.after(0, complete)

def main():
    root = tk.Tk()
    app = CodeScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()