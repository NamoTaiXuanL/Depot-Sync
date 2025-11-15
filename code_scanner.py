import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import multiprocessing
import shutil
import concurrent.futures
from pathlib import Path

class CodeScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("代码库扫描工具")
        self.root.geometry("1000x700")
        
        # 创建界面组件
        self.create_widgets()
        
    def create_widgets(self):
        # 主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 标题
        title_label = ttk.Label(main_frame, text="代码库扫描工具", font=("Arial", 16))
        title_label.grid(row=0, column=0, columnspan=3, pady=10)
        
        # 文件夹选择框架
        folder_frame = ttk.LabelFrame(main_frame, text="扫描选项", padding="5")
        folder_frame.grid(row=1, column=0, columnspan=4, pady=10, sticky=(tk.W, tk.E))
        
        # 全盘扫描选项
        self.scan_all_var = tk.BooleanVar(value=True)
        self.scan_all_check = ttk.Checkbutton(folder_frame, text="全盘扫描", variable=self.scan_all_var, command=self.toggle_folder_selection)
        self.scan_all_check.grid(row=0, column=0, padx=5, sticky=tk.W)
        
        # 选择文件夹选项
        self.select_folders_var = tk.BooleanVar(value=False)
        self.select_folders_check = ttk.Checkbutton(folder_frame, text="选择特定文件夹", variable=self.select_folders_var, command=self.toggle_folder_selection)
        self.select_folders_check.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # 文件夹选择按钮
        self.folder_button = ttk.Button(folder_frame, text="选择文件夹", command=self.select_folders, state='disabled')
        self.folder_button.grid(row=0, column=2, padx=5, sticky=tk.W)
        
        # 已选文件夹显示
        self.folder_label = ttk.Label(folder_frame, text="未选择文件夹", foreground="gray")
        self.folder_label.grid(row=1, column=0, columnspan=4, pady=5, sticky=tk.W)
        
        # 同步路径选择
        sync_frame = ttk.LabelFrame(main_frame, text="同步选项", padding="5")
        sync_frame.grid(row=2, column=0, columnspan=4, pady=10, sticky=(tk.W, tk.E))
        
        # 同步路径选择按钮
        self.sync_button = ttk.Button(sync_frame, text="选择同步路径", command=self.select_sync_path)
        self.sync_button.grid(row=0, column=0, padx=5, sticky=tk.W)
        
        # 同步路径显示
        self.sync_label = ttk.Label(sync_frame, text="未选择同步路径", foreground="gray")
        self.sync_label.grid(row=0, column=1, padx=5, sticky=tk.W)
        
        # 开始同步按钮
        self.sync_start_button = ttk.Button(sync_frame, text="开始同步", command=self.start_sync, state='disabled')
        self.sync_start_button.grid(row=0, column=2, padx=5, sticky=tk.W)
        
        # 扫描按钮
        self.scan_button = ttk.Button(main_frame, text="开始扫描", command=self.start_scan)
        self.scan_button.grid(row=3, column=0, pady=10, sticky=tk.W)
        
        # 进度条
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=3, column=1, columnspan=3, pady=10, sticky=(tk.W, tk.E))
        
        # 结果文本框
        self.result_text = tk.Text(main_frame, height=20, width=90)
        self.result_text.grid(row=4, column=0, columnspan=4, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # 滚动条
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.result_text.yview)
        scrollbar.grid(row=4, column=4, sticky=(tk.N, tk.S))
        self.result_text.configure(yscrollcommand=scrollbar.set)
        
        # 配置网格权重
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(4, weight=1)
        folder_frame.columnconfigure(1, weight=1)
        sync_frame.columnconfigure(1, weight=1)
        
    def toggle_folder_selection(self):
        # 切换文件夹选择状态
        if self.select_folders_var.get():
            self.folder_button.config(state='normal')
            self.scan_all_var.set(False)
        else:
            self.folder_button.config(state='disabled')
            self.scan_all_var.set(True)
    
    def select_folders(self):
        # 选择多个文件夹
        folders = filedialog.askdirectory(
            title="选择要扫描的文件夹（可多选）",
            mustexist=True
        )
        if folders:
            if not hasattr(self, 'selected_folders'):
                self.selected_folders = []
            self.selected_folders.append(folders)
            # 显示前3个文件夹，超过则显示数量
            if len(self.selected_folders) <= 3:
                folder_names = "\n".join([os.path.basename(f) for f in self.selected_folders])
                display_text = f"已选择 {len(self.selected_folders)} 个文件夹:\n{folder_names}"
            else:
                folder_names = "\n".join([os.path.basename(f) for f in self.selected_folders[:3]])
                display_text = f"已选择 {len(self.selected_folders)} 个文件夹:\n{folder_names}\n...（还有{len(self.selected_folders)-3}个）"
            self.folder_label.config(text=display_text, foreground="black")
    
    def select_sync_path(self):
        # 选择同步路径
        sync_path = filedialog.askdirectory(
            title="选择同步目标路径",
            mustexist=True
        )
        if sync_path:
            self.sync_path = sync_path
            self.sync_label.config(text=f"同步到: {sync_path}", foreground="black")
            self.sync_start_button.config(state='normal')
    
    def start_scan(self):
        # 禁用扫描按钮，启动进度条
        self.scan_button.config(state='disabled')
        self.progress.start(10)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "正在扫描...\n")
        
        # 确定扫描路径
        if self.select_folders_var.get() and hasattr(self, 'selected_folders'):
            scan_paths = self.selected_folders
            self.result_text.insert(tk.END, f"扫描特定文件夹: {scan_paths}\n")
        else:
            scan_paths = self.get_available_drives()
            self.result_text.insert(tk.END, "全盘扫描中...\n")
        
        # 在新线程中执行扫描
        thread = threading.Thread(target=self.scan_drives, args=(scan_paths,))
        thread.daemon = True
        thread.start()
        
    def scan_drives(self, scan_paths):
        try:
            git_repos = []
            
            for path in scan_paths:
                self.update_result(f"扫描路径: {path}")
                
                # 遍历路径查找.git文件夹
                for root_dir, dirs, files in os.walk(path):
                    if '.git' in dirs:
                        git_path = os.path.join(root_dir, '.git')
                        git_repos.append(root_dir)
                        self.update_result(f"发现代码库: {root_dir}")
            
            # 扫描完成
            self.scan_complete(git_repos)
            
        except Exception as e:
            self.scan_complete([], str(e))
    
    def start_sync(self):
        # 开始同步
        if not hasattr(self, 'git_repos') or not self.git_repos:
            messagebox.showwarning("警告", "请先扫描代码库")
            return
        
        if not hasattr(self, 'sync_path'):
            messagebox.showwarning("警告", "请先选择同步路径")
            return
        
        self.sync_start_button.config(state='disabled')
        self.progress.start(10)
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, "开始同步代码库...\n")
        
        # 在新线程中执行同步
        thread = threading.Thread(target=self.sync_repositories)
        thread.daemon = True
        thread.start()
    
    def sync_repositories(self):
        try:
            # 创建同步目录
            sync_base = os.path.join(self.sync_path, "Depot_Sync", "Data")
            os.makedirs(sync_base, exist_ok=True)
            
            self.update_result(f"同步到: {sync_base}")
            
            # 使用进程池进行多进程同步
            cpu_count = multiprocessing.cpu_count()
            max_workers = min(cpu_count * 2, len(self.git_repos))
            
            self.update_result(f"使用 {max_workers} 个进程进行同步...")
            
            # 准备同步任务
            sync_tasks = []
            for repo_path in self.git_repos:
                repo_name = os.path.basename(repo_path)
                target_path = os.path.join(sync_base, repo_name)
                sync_tasks.append((repo_path, target_path))
            
            # 显示所有待同步任务
            for repo_path, target_path in sync_tasks:
                self.update_result(f"待同步: {os.path.basename(repo_path)} -> {target_path}")
            
            # 使用进程池执行同步
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for repo_path, target_path in sync_tasks:
                    # 使用独立的同步函数，避免传递self
                    future = executor.submit(self._sync_repository_task, repo_path, target_path)
                    futures[future] = os.path.basename(repo_path)
                
                # 等待所有任务完成并更新进度
                completed_count = 0
                for future in concurrent.futures.as_completed(futures):
                    repo_name = futures[future]
                    completed_count += 1
                    try:
                        result = future.result()
                        self.update_result(f"[{completed_count}/{len(sync_tasks)}] {result}")
                    except Exception as e:
                        self.update_result(f"[{completed_count}/{len(sync_tasks)}] 同步失败 {repo_name}: {e}")
            
            self.update_result("同步完成!")
            self.sync_complete()
            
        except Exception as e:
            self.update_result(f"同步过程中发生错误: {e}")
            self.sync_complete()
    
    def _sync_repository_task(self, repo_path, target_path):
        # 独立的同步任务函数，不包含任何tkinter引用
        try:
            # 如果目标路径存在，先删除
            if os.path.exists(target_path):
                shutil.rmtree(target_path)
            
            # 复制整个代码库
            shutil.copytree(repo_path, target_path)
            
            return f"成功同步: {os.path.basename(repo_path)}"
            
        except Exception as e:
            return f"同步失败 {os.path.basename(repo_path)}: {e}"
    
    def sync_complete(self):
        # 同步完成后的处理
        def complete():
            self.progress.stop()
            self.sync_start_button.config(state='normal')
        
        self.root.after(0, complete)
    
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
                # 保存扫描结果用于同步
                self.git_repos = git_repos
        
        self.root.after(0, complete)

def main():
    root = tk.Tk()
    app = CodeScanner(root)
    root.mainloop()

if __name__ == "__main__":
    main()