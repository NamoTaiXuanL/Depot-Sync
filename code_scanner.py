import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import multiprocessing
import shutil
import concurrent.futures
import json
import hashlib
from pathlib import Path
from datetime import datetime

def calculate_file_hash(file_path):
    # 计算文件的MD5哈希值（快速模式）
    hash_md5 = hashlib.md5()
    try:
        # 使用文件大小和修改时间作为快速哈希（避免读取大文件内容）
        stat = os.stat(file_path)
        # 结合文件大小和修改时间生成快速哈希
        hash_data = f"{stat.st_size}:{stat.st_mtime}".encode()
        hash_md5.update(hash_data)
        return hash_md5.hexdigest()
    except Exception:
        return None

def scan_repository_files(repo_path):
    # 扫描代码库中的所有文件并计算哈希
    file_hashes = {}
    if not os.path.exists(repo_path):
        return file_hashes
    
    for root, dirs, files in os.walk(repo_path):
        # 跳过.git目录（版本控制文件不需要同步）
        if '.git' in dirs:
            dirs.remove('.git')
        
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, repo_path)
            file_hash = calculate_file_hash(file_path)
            if file_hash:
                file_hashes[rel_path] = file_hash
    
    return file_hashes

def sync_repository_task(repo_path, target_path, sync_info=None):
    # 文件级别的智能同步任务函数
    try:
        repo_name = os.path.basename(repo_path)
        
        # 扫描源代码库中的所有文件
        current_files = scan_repository_files(repo_path)
        
        # 检查是否需要同步（文件级别增量更新）
        if sync_info and repo_name in sync_info:
            last_files = sync_info[repo_name].get("files", {})
            
            # 比较文件变化
            changed_files = []
            new_files = []
            deleted_files = []
            
            # 检查修改和新增的文件
            for file_path, current_hash in current_files.items():
                if file_path not in last_files:
                    new_files.append(file_path)
                elif last_files[file_path] != current_hash:
                    changed_files.append(file_path)
            
            # 检查删除的文件
            for file_path in last_files:
                if file_path not in current_files:
                    deleted_files.append(file_path)
            
            # 如果没有变化，跳过同步
            if not changed_files and not new_files and not deleted_files:
                return f"跳过同步（无变化）: {repo_name}", None
            
            # 执行增量同步
            sync_count = 0
            
            # 确保目标目录存在
            os.makedirs(target_path, exist_ok=True)
            
            # 复制新增和修改的文件
            for file_path in new_files + changed_files:
                src_file = os.path.join(repo_path, file_path)
                dst_file = os.path.join(target_path, file_path)
                
                # 确保目标目录存在
                os.makedirs(os.path.dirname(dst_file), exist_ok=True)
                
                # 复制文件
                shutil.copy2(src_file, dst_file)
                sync_count += 1
            
            # 删除已删除的文件
            for file_path in deleted_files:
                dst_file = os.path.join(target_path, file_path)
                if os.path.exists(dst_file):
                    os.remove(dst_file)
                    sync_count += 1
            
            # 清理空目录
            cleanup_empty_directories(target_path)
            
            sync_result = {
                "files": current_files,
                "last_sync": datetime.now().isoformat(),
                "source_path": repo_path,
                "target_path": target_path,
                "sync_count": sync_count
            }
            
            return f"增量同步成功: {repo_name} ({sync_count}个文件)", sync_result
        
        else:
            # 首次同步或没有历史信息，执行完整同步
            if os.path.exists(target_path):
                shutil.rmtree(target_path)
            
            shutil.copytree(repo_path, target_path)
            
            sync_result = {
                "files": current_files,
                "last_sync": datetime.now().isoformat(),
                "source_path": repo_path,
                "target_path": target_path,
                "sync_count": len(current_files)
            }
            
            return f"完整同步成功: {repo_name} ({len(current_files)}个文件)", sync_result
        
    except Exception as e:
        return f"同步失败 {os.path.basename(repo_path)}: {e}", None

def cleanup_empty_directories(directory):
    # 清理空目录
    for root, dirs, files in os.walk(directory, topdown=False):
        for dir_name in dirs:
            dir_path = os.path.join(root, dir_name)
            try:
                if not os.listdir(dir_path):  # 目录为空
                    os.rmdir(dir_path)
            except OSError:
                pass  # 目录不为空或权限问题，跳过

class CodeScanner:
    def __init__(self, root):
        self.root = root
        self.root.title("代码库扫描工具")
        self.root.geometry("1000x700")
        
        # 同步信息存储
        self.sync_info = {}
        self.main_index_path = None
        self.repo_json_dir = None
        
        # 同步历史记录
        self.sync_history = {}
        self.history_dir = None
        
        # 配置文件路径
        self.config_file = os.path.join(os.path.dirname(__file__), "scanner_config.json")
        
        # 加载配置
        self.load_config()
        
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
            
            # 保存配置并加载历史记录
            self.save_config()
            self.load_history_for_path(sync_path)
    
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
            
            # 加载同步信息
            self.load_sync_info(self.sync_path)
            
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
                repo_name = os.path.basename(repo_path)
                if repo_name in self.sync_info:
                    self.update_result(f"待同步（增量）: {repo_name}")
                else:
                    self.update_result(f"待同步（新增）: {repo_name}")
            
            # 使用进程池执行同步
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                futures = {}
                for repo_path, target_path in sync_tasks:
                    repo_name = os.path.basename(repo_path)
                    # 使用完全独立的同步函数，传递同步信息
                    future = executor.submit(sync_repository_task, repo_path, target_path, self.sync_info)
                    futures[future] = repo_name
                
                # 等待所有任务完成并更新进度
                completed_count = 0
                for future in concurrent.futures.as_completed(futures):
                    repo_name = futures[future]
                    completed_count += 1
                    try:
                        result, sync_result = future.result()
                        self.update_result(f"[{completed_count}/{len(sync_tasks)}] {result}")
                        
                        # 更新同步信息
                        if sync_result:
                            self.sync_info[repo_name] = sync_result
                            # 添加成功同步历史记录
                            self.add_sync_history(repo_name, sync_result, "success")
                        
                    except Exception as e:
                        error_msg = f"[{completed_count}/{len(sync_tasks)}] 同步失败 {repo_name}: {e}"
                        self.update_result(error_msg)
                        # 添加失败同步历史记录
                        self.add_sync_history(repo_name, error_msg, "failed")
            
            # 保存同步信息
            self.save_sync_info()
            self.update_result("同步完成!")
            
            # 显示同步历史摘要
            self.show_sync_history_summary()
            self.sync_complete()
            
        except Exception as e:
            self.update_result(f"同步过程中发生错误: {e}")
            self.sync_complete()
    
    # _sync_repository_task 方法已移除，使用顶部的独立函数
    
    def sync_complete(self):
        # 同步完成后的处理
        def complete():
            self.progress.stop()
            self.sync_start_button.config(state='normal')
        
        self.root.after(0, complete)

    def load_sync_info(self, sync_path):
        # 从JSON文件加载同步信息（多文件结构）
        json_dir = os.path.join(sync_path, "Depot_Sync", "JSON")
        os.makedirs(json_dir, exist_ok=True)
        
        # 主索引文件路径
        self.main_index_path = os.path.join(json_dir, "sync_info.json")
        # 代码库JSON文件目录
        self.repo_json_dir = os.path.join(json_dir, "repos")
        os.makedirs(self.repo_json_dir, exist_ok=True)
        
        # 同步历史记录目录
        self.history_dir = os.path.join(json_dir, "history")
        os.makedirs(self.history_dir, exist_ok=True)
        
        self.sync_info = {}
        
        # 加载主索引文件
        if os.path.exists(self.main_index_path):
            try:
                with open(self.main_index_path, 'r', encoding='utf-8') as f:
                    main_index = json.load(f)
                
                # 加载每个代码库的独立JSON文件
                for repo_name, repo_info in main_index.items():
                    repo_json_path = os.path.join(self.repo_json_dir, f"{repo_name}_sync_info.json")
                    if os.path.exists(repo_json_path):
                        try:
                            with open(repo_json_path, 'r', encoding='utf-8') as repo_f:
                                self.sync_info[repo_name] = json.load(repo_f)
                        except Exception as e:
                            self.update_result(f"加载代码库 {repo_name} 信息失败: {e}")
                            self.sync_info[repo_name] = repo_info  # 使用主索引中的基本信息
                
                self.update_result(f"已加载同步信息: {len(self.sync_info)} 个代码库记录")
                
            except Exception as e:
                self.update_result(f"加载主索引信息失败: {e}")
                self.sync_info = {}
        else:
            self.update_result("未找到同步信息文件，将创建新文件")

    def save_sync_info(self):
        # 保存同步信息到JSON文件（多文件结构）
        if self.main_index_path and self.repo_json_dir:
            try:
                # 创建主索引（包含基本信息）
                main_index = {}
                for repo_name, repo_info in self.sync_info.items():
                    main_index[repo_name] = {
                        "last_sync": repo_info.get("last_sync", ""),
                        "source_path": repo_info.get("source_path", ""),
                        "target_path": repo_info.get("target_path", ""),
                        "file_count": len(repo_info.get("files", {}))
                    }
                
                # 保存主索引
                with open(self.main_index_path, 'w', encoding='utf-8') as f:
                    json.dump(main_index, f, ensure_ascii=False, indent=2)
                
                # 保存每个代码库的独立JSON文件
                for repo_name, repo_info in self.sync_info.items():
                    repo_json_path = os.path.join(self.repo_json_dir, f"{repo_name}_sync_info.json")
                    with open(repo_json_path, 'w', encoding='utf-8') as repo_f:
                        json.dump(repo_info, repo_f, ensure_ascii=False, indent=2)
                
                self.update_result(f"同步信息已保存 ({len(self.sync_info)} 个代码库)")
                
            except Exception as e:
                self.update_result(f"保存同步信息失败: {e}")

    def add_sync_history(self, repo_name, sync_result, status="success"):
        # 添加同步历史记录
        if not self.history_dir:
            return
        
        try:
            history_file = os.path.join(self.history_dir, f"{repo_name}_history.json")
            
            # 加载现有历史记录
            history_data = []
            if os.path.exists(history_file):
                with open(history_file, 'r', encoding='utf-8') as f:
                    history_data = json.load(f)
            
            # 添加新的历史记录
            history_entry = {
                "timestamp": datetime.now().isoformat(),
                "status": status,
                "sync_count": sync_result.get("sync_count", 0) if status == "success" else 0,
                "file_count": len(sync_result.get("files", {})) if status == "success" else 0,
                "message": sync_result if isinstance(sync_result, str) else "同步完成"
            }
            
            # 保留最近100条记录
            history_data.append(history_entry)
            if len(history_data) > 100:
                history_data = history_data[-100:]
            
            # 保存历史记录
            with open(history_file, 'w', encoding='utf-8') as f:
                json.dump(history_data, f, ensure_ascii=False, indent=2)
                
        except Exception as e:
            self.update_result(f"保存同步历史记录失败: {e}")

    def load_sync_history(self, repo_name):
        # 加载同步历史记录
        if not self.history_dir:
            return []
        
        try:
            history_file = os.path.join(self.history_dir, f"{repo_name}_history.json")
            if os.path.exists(history_file):
                with open(history_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            self.update_result(f"加载同步历史记录失败: {e}")
        
        return []

    def get_all_sync_history(self):
        # 获取所有代码库的同步历史摘要
        history_summary = {}
        if not self.history_dir:
            return history_summary
        
        try:
            for file_name in os.listdir(self.history_dir):
                if file_name.endswith('_history.json'):
                    repo_name = file_name.replace('_history.json', '')
                    history_data = self.load_sync_history(repo_name)
                    if history_data:
                        history_summary[repo_name] = {
                            "last_sync": history_data[-1]["timestamp"] if history_data else "",
                            "total_syncs": len(history_data),
                            "last_status": history_data[-1]["status"] if history_data else ""
                        }
        except Exception as e:
            self.update_result(f"获取历史记录摘要失败: {e}")
        
        return history_summary

    def load_config(self):
        # 加载配置文件
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                    # 设置最后使用的同步路径
                    if 'last_sync_path' in config:
                        self.sync_path = config['last_sync_path']
                        self.sync_label.config(text=f"同步到: {self.sync_path}", foreground="black")
                        self.sync_start_button.config(state='normal')
                        
                        # 加载该路径的历史记录
                        self.load_history_for_path(self.sync_path)
                        
        except Exception as e:
            self.update_result(f"加载配置失败: {e}")

    def save_config(self):
        # 保存配置文件
        try:
            config = {
                'last_sync_path': self.sync_path if hasattr(self, 'sync_path') and self.sync_path else ''
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.update_result(f"保存配置失败: {e}")

    def load_history_for_path(self, sync_path):
        # 为指定路径加载历史记录
        if not sync_path:
            return
        
        # 设置历史记录目录
        json_dir = os.path.join(sync_path, "Depot_Sync", "JSON")
        self.history_dir = os.path.join(json_dir, "history")
        
        # 显示历史摘要
        self.show_sync_history_summary()

    def show_sync_history_summary(self):
        # 显示同步历史摘要
        history_summary = self.get_all_sync_history()
        if history_summary:
            self.update_result("\n=== 同步历史摘要 ===")
            for repo_name, summary in history_summary.items():
                last_sync = summary["last_sync"][:19] if summary["last_sync"] else "从未同步"
                status_emoji = "✅" if summary["last_status"] == "success" else "❌"
                self.update_result(f"{status_emoji} {repo_name}: {summary['total_syncs']}次同步, 最后同步: {last_sync}")
        else:
            self.update_result("\n暂无同步历史记录")

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