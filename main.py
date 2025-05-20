import tkinter as tk
from tkinter import ttk, messagebox

# --- 数据模型 ---
class User:
    def __init__(self, username, password, role):
        self.username = username
        self.password = password # 在实际应用中，密码应该被哈希存储
        self.role = role

class Person:
    def __init__(self, person_id, name, age):
        self.id = person_id
        self.name = name
        self.age = age

    def __str__(self):
        return f"编号: {self.id}, 姓名: {self.name}, 年龄: {self.age}"

# --- 管理器类 ---
class DataManager:
    def __init__(self):
        # 预设用户数据
        self.users = {
            "admin": User("admin", "admin123", "admin"),
            "user1": User("user1", "user123", "user"),
            "user2": User("user2", "user456", "user")
        }
        # 预设人员数据
        self.personnel = {
            "P001": Person("P001", "Alice Smith", 30),
            "P002": Person("P002", "Bob Johnson", 25)
        }
        # 预设权限配置 (action: permission_name)
        # 角色: { "action_name": True/False }
        self.permissions = {
            "admin": {
                "add_person": True,
                "view_personnel": True,
                "find_person": True,
                "update_person": True,
                "delete_person": True,
                "configure_permissions": True
            },
            "user": {
                "add_person": False,
                "view_personnel": True,
                "find_person": True,
                "update_person": False, # 普通用户默认不能更新
                "delete_person": False,
                "configure_permissions": False
            }
        }
        self.available_actions = [
            "add_person", "view_personnel", "find_person",
            "update_person", "delete_person"
        ] # configure_permissions 是特殊权限

    def authenticate_user(self, username, password):
        user = self.users.get(username)
        if user and user.password == password:
            return user
        return None

    def has_permission(self, role, action):
        return self.permissions.get(role, {}).get(action, False)

    def get_all_users_info(self):
        # 返回用户名和角色，不暴露密码
        return {uname: u.role for uname, u in self.users.items()}

    def update_role_permission(self, role, action, value):
        if role in self.permissions and action in self.permissions[role]:
            self.permissions[role][action] = value
            return True
        return False

    def add_user(self, username, password, role):
        if username in self.users:
            return False, "用户名已存在。"
        if role not in self.permissions: # 确保角色是已知的（admin, user）
             return False, f"角色 '{role}' 不是预定义角色类型。"
        self.users[username] = User(username, password, role)
        # 为新用户角色（如果之前不存在）初始化权限，通常新用户会是 'user' 角色
        # 如果是全新的角色类型，需要管理员手动配置其权限，这里简化为新用户默认继承'user'权限
        if role not in self.permissions:
            self.permissions[role] = self.permissions.get("user", {}).copy() # 默认权限
        return True, "用户添加成功。"

    def delete_user(self, username):
        if username == "admin": # 禁止删除管理员
            return False, "无法删除管理员用户。"
        if username in self.users:
            del self.users[username]
            # 理论上也应该清理该用户特定权限，但这里简化为基于角色的权限
            return True, "用户删除成功。"
        return False, "用户未找到。"

    # --- 人员管理方法 ---
    def add_person(self, person_id, name, age):
        if person_id in self.personnel:
            return False, "人员编号已存在。"
        try:
            age_int = int(age)
            if age_int <= 0:
                return False, "年龄必须是正数。"
        except ValueError:
            return False, "年龄必须是有效数字。"

        self.personnel[person_id] = Person(person_id, name, age_int)
        return True, "人员添加成功。"

    def get_all_personnel(self):
        return list(self.personnel.values())

    def find_person(self, person_id):
        return self.personnel.get(person_id)

    def update_person(self, person_id, name, age):
        if person_id not in self.personnel:
            return False, "人员编号未找到。"
        try:
            age_int = int(age)
            if age_int <= 0:
                return False, "年龄必须是正数。"
        except ValueError:
            return False, "年龄必须是有效数字。"

        person = self.personnel[person_id]
        person.name = name
        person.age = age_int
        return True, "人员更新成功。"

    def delete_person(self, person_id):
        if person_id in self.personnel:
            del self.personnel[person_id]
            return True, "人员删除成功。"
        return False, "人员编号未找到。"

# --- GUI 类 ---
class LoginWindow:
    def __init__(self, master, app_controller):
        self.master = master
        self.app_controller = app_controller
        master.title("登录")
        master.geometry("600x450")  # 增加界面宽度
        master.resizable(False, False)

        # Center the window
        master.update_idletasks()
        width = master.winfo_width()
        height = master.winfo_height()
        x = (master.winfo_screenwidth() // 2) - (width // 2)
        y = (master.winfo_screenheight() // 2) - (height // 2)
        master.geometry(f'{width}x{height}+{x}+{y}')

        # Add a background image or color
        self.bg_frame = tk.Frame(master, bg="#8B0000")  # 调暗红色
        self.bg_frame.pack(fill="both", expand=True)

        # Add a flag image (assuming you have a flag image named 'flag.png')
        try:
            self.flag_image = tk.PhotoImage(file="flag.png")
            self.flag_label = tk.Label(self.bg_frame, image=self.flag_image, bg="#8B0000")
            self.flag_label.pack(pady=10)
        except Exception as e:
            print("Error loading flag image:", e)

        # Add a title label
        self.title_label = tk.Label(self.bg_frame, text="欢迎使用人员管理系统", font=("Arial", 18, "bold"), fg="darkblue", bg="#8B0000")
        self.title_label.pack(pady=5)

        # Add a slogan
        self.slogan_label = tk.Label(self.bg_frame, text="爱岗敬业，爱国奉献", font=("Arial", 14, "italic"), fg="darkblue", bg="#8B0000")
        self.slogan_label.pack(pady=5)

        # Add username and password fields
        tk.Label(self.bg_frame, text="用户名：", font=("Arial", 12), fg="white", bg="#8B0000").pack(pady=5)
        self.username_entry = tk.Entry(self.bg_frame, font=("Arial", 12))
        self.username_entry.pack(pady=5)

        tk.Label(self.bg_frame, text="密码：", font=("Arial", 12), fg="white", bg="#8B0000").pack(pady=5)
        self.password_entry = tk.Entry(self.bg_frame, show="*", font=("Arial", 12))
        self.password_entry.pack(pady=5)

        # Add a login button
        self.login_button = tk.Button(self.bg_frame, text="登录", font=("Arial", 12, "bold"), bg="white", fg="red", command=self.login)
        self.login_button.pack(pady=10)

        # Add a dynamic element (e.g., a moving text)
        self.dynamic_label = tk.Label(self.bg_frame, text="安全登录", font=("Arial", 10, "italic"), fg="white", bg="#8B0000")
        self.dynamic_label.pack(pady=5)
        self.animate_text()

        master.bind('<Return>', lambda event: self.login()) # Bind Enter key to login

    def animate_text(self):
        current_text = self.dynamic_label.cget("text")
        new_text = current_text[1:] + current_text[0]  # Rotate the text
        self.dynamic_label.config(text=new_text)
        self.master.after(200, self.animate_text)  # Update every 200ms

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        user = self.app_controller.data_manager.authenticate_user(username, password)
        if user:
            self.app_controller.current_user = user
            self.master.destroy() # Close login window
            self.app_controller.show_main_window()
        else:
            messagebox.showerror("登录失败", "用户名或密码错误。")

class MainWindow:
    def __init__(self, master, app_controller):
        self.master = master
        self.app_controller = app_controller
        self.data_manager = app_controller.data_manager
        self.current_user = app_controller.current_user

        master.title(f"人员管理系统 - 当前用户：{self.current_user.username}（{self.current_user.role}）")
        master.geometry("800x600")
        master.configure(bg="#8B0000")  # 设置主窗口背景色

        # --- Menu Bar (for Admin functions) ---
        menubar = tk.Menu(master, bg="#8B0000", fg="white")
        master.config(menu=menubar)
        if self.data_manager.has_permission(self.current_user.role, "configure_permissions"):
            admin_menu = tk.Menu(menubar, tearoff=0, bg="#8B0000", fg="white")
            menubar.add_cascade(label="管理员", menu=admin_menu)
            admin_menu.add_command(label="权限配置", command=self.open_permission_config_window)
            admin_menu.add_command(label="用户管理", command=self.open_user_management_window)

        # --- Main Layout Frames ---
        control_frame = ttk.LabelFrame(master, text="操作区", padding=10)
        control_frame.pack(pady=10, padx=10, fill="x")
        control_frame.configure(style="Red.TLabelframe")

        display_frame = ttk.LabelFrame(master, text="人员列表", padding=10)
        display_frame.pack(pady=10, padx=10, fill="both", expand=True)
        display_frame.configure(style="Red.TLabelframe")

        # --- 控件样式 ---
        style = ttk.Style()
        style.configure("Red.TLabelframe", background="#8B0000", foreground="darkblue")
        style.configure("Red.TLabelframe.Label", background="#8B0000", foreground="darkblue", font=("Arial", 14, "bold"))
        style.configure("Red.TButton", background="white", foreground="#8B0000", font=("Arial", 11, "bold"))
        style.configure("Red.TLabel", background="#8B0000", foreground="white", font=("Arial", 12))

        # --- Control Frame Widgets (Input fields and buttons) ---
        tk.Label(control_frame, text="编号：", font=("Arial", 12), fg="white", bg="#8B0000").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.id_entry = tk.Entry(control_frame, font=("Arial", 12))
        self.id_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        tk.Label(control_frame, text="姓名：", font=("Arial", 12), fg="white", bg="#8B0000").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.name_entry = tk.Entry(control_frame, font=("Arial", 12))
        self.name_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")

        tk.Label(control_frame, text="年龄：", font=("Arial", 12), fg="white", bg="#8B0000").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.age_entry = tk.Entry(control_frame, font=("Arial", 12))
        self.age_entry.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        control_frame.columnconfigure(1, weight=1) # Make entry fields expand

        # Buttons Frame
        button_frame = ttk.Frame(control_frame, style="Red.TLabelframe")
        button_frame.grid(row=3, column=0, columnspan=2, pady=10)

        self.add_button = tk.Button(button_frame, text="添加人员", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.add_person)
        self.add_button.pack(side="left", padx=5)

        self.view_button = tk.Button(button_frame, text="查看全部", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.view_all_personnel)
        self.view_button.pack(side="left", padx=5)

        self.find_button = tk.Button(button_frame, text="按编号查找", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.find_person)
        self.find_button.pack(side="left", padx=5)

        self.update_button = tk.Button(button_frame, text="更新人员", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.update_person)
        self.update_button.pack(side="left", padx=5)

        self.delete_button = tk.Button(button_frame, text="删除人员", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.delete_person)
        self.delete_button.pack(side="left", padx=5)
        
        self.clear_button = tk.Button(button_frame, text="清空输入", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.clear_fields)
        self.clear_button.pack(side="left", padx=5)

        # --- Display Frame Widgets (Listbox) ---
        self.personnel_listbox = tk.Listbox(display_frame, height=15, font=("Arial", 12), bg="#8B0000", fg="white", selectbackground="darkblue", selectforeground="white")
        self.personnel_listbox.pack(side="left", fill="both", expand=True, padx=(0,5))
        self.personnel_listbox.bind('<<ListboxSelect>>', self.on_personnel_select)

        scrollbar = ttk.Scrollbar(display_frame, orient="vertical", command=self.personnel_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.personnel_listbox.config(yscrollcommand=scrollbar.set)

        # --- Apply Permissions to Buttons ---
        self.apply_button_permissions()
        self.view_all_personnel() # Initial load

    def apply_button_permissions(self):
        role = self.current_user.role
        self.add_button.config(state=tk.NORMAL if self.data_manager.has_permission(role, "add_person") else tk.DISABLED)
        self.view_button.config(state=tk.NORMAL if self.data_manager.has_permission(role, "view_personnel") else tk.DISABLED)
        self.find_button.config(state=tk.NORMAL if self.data_manager.has_permission(role, "find_person") else tk.DISABLED)
        self.update_button.config(state=tk.NORMAL if self.data_manager.has_permission(role, "update_person") else tk.DISABLED)
        self.delete_button.config(state=tk.NORMAL if self.data_manager.has_permission(role, "delete_person") else tk.DISABLED)

    def clear_fields(self):
        self.id_entry.delete(0, tk.END)
        self.name_entry.delete(0, tk.END)
        self.age_entry.delete(0, tk.END)
        self.personnel_listbox.selection_clear(0, tk.END)


    def on_personnel_select(self, event: object):
        try:
            selected_index = self.personnel_listbox.curselection()[0]
            selected_item_str = self.personnel_listbox.get(selected_index)
            # Parse the string to get ID (assuming format "编号: PXXX, ...")
            person_id = selected_item_str.split(",")[0].split(":")[1].strip()
            person = self.data_manager.find_person(person_id)
            if person:
                self.id_entry.delete(0, tk.END)
                self.id_entry.insert(0, person.id)
                self.name_entry.delete(0, tk.END)
                self.name_entry.insert(0, person.name)
                self.age_entry.delete(0, tk.END)
                self.age_entry.insert(0, str(person.age))
        except IndexError:
            pass # No item selected or list is empty

    def add_person(self):
        person_id = self.id_entry.get()
        name = self.name_entry.get()
        age = self.age_entry.get()

        if not person_id or not name or not age:
            messagebox.showerror("错误", "所有字段均为必填项。")
            return

        success, message = self.data_manager.add_person(person_id, name, age)
        if success:
            messagebox.showinfo("成功", message)
            self.view_all_personnel()
            self.clear_fields()
        else:
            messagebox.showerror("错误", message)

    def view_all_personnel(self):
        self.personnel_listbox.delete(0, tk.END)
        personnel_list = self.data_manager.get_all_personnel()
        if personnel_list:
            for person in personnel_list:
                self.personnel_listbox.insert(tk.END, str(person))
        else:
            self.personnel_listbox.insert(tk.END, "暂无人员数据。")


    def find_person(self):
        person_id = self.id_entry.get()
        if not person_id:
            messagebox.showerror("错误", "请输入编号进行查找。")
            return

        person = self.data_manager.find_person(person_id)
        if person:
            self.personnel_listbox.delete(0, tk.END)
            self.personnel_listbox.insert(tk.END, str(person))
            self.name_entry.delete(0, tk.END)
            self.name_entry.insert(0, person.name)
            self.age_entry.delete(0, tk.END)
            self.age_entry.insert(0, str(person.age))
            messagebox.showinfo("找到", f"已找到编号为 {person_id} 的人员。")
        else:
            messagebox.showinfo("未找到", f"未找到编号为 {person_id} 的人员。")
            self.view_all_personnel() # Refresh to show all if not found

    def update_person(self):
        person_id = self.id_entry.get()
        name = self.name_entry.get()
        age = self.age_entry.get()

        if not person_id or not name or not age:
            messagebox.showerror("错误", "编号、姓名和年龄均为必填项。")
            return

        success, message = self.data_manager.update_person(person_id, name, age)
        if success:
            messagebox.showinfo("成功", message)
            self.view_all_personnel()
            self.clear_fields()
        else:
            messagebox.showerror("错误", message)

    def delete_person(self):
        person_id = self.id_entry.get()
        if not person_id:
            messagebox.showerror("错误", "请输入编号进行删除。")
            return

        if messagebox.askyesno("确认删除", f"确定要删除编号为 {person_id} 的人员吗？"):
            success, message = self.data_manager.delete_person(person_id)
            if success:
                messagebox.showinfo("成功", message)
                self.view_all_personnel()
                self.clear_fields()
            else:
                messagebox.showerror("错误", message)

    def open_permission_config_window(self):
        config_win = tk.Toplevel(self.master)
        PermissionConfigWindow(config_win, self.app_controller)

    def open_user_management_window(self):
        user_manage_win = tk.Toplevel(self.master)
        UserManagementWindow(user_manage_win, self.app_controller)


class PermissionConfigWindow:
    def __init__(self, master, app_controller):
        self.master = master
        self.app_controller = app_controller
        self.data_manager = app_controller.data_manager
        master.title("权限配置")
        master.geometry("600x400")
        master.configure(bg="#8B0000")
        master.grab_set() # Modal window

        self.permission_vars = {} # To store Checkbutton variables

        tk.Label(master, text="角色权限配置", font=("Arial", 14), bg="#8B0000", fg="darkblue").pack(pady=10)

        header_frame = ttk.Frame(master)
        header_frame.pack(fill="x", padx=10)
        tk.Label(header_frame, text="角色", width=10, relief="groove", bg="#8B0000", fg="white").pack(side="left")
        for action_name in self.data_manager.available_actions:
            zh_action = {
                "add_person": "添加人员",
                "view_personnel": "查看人员",
                "find_person": "查找人员",
                "update_person": "更新人员",
                "delete_person": "删除人员"
            }.get(action_name, str(action_name) if action_name is not None else "")
            tk.Label(header_frame, text=zh_action, width=15, relief="groove", bg="#8B0000", fg="white").pack(side="left")

        for role, perms in self.data_manager.permissions.items():
            if role == "admin": # Admin permissions are not editable through UI
                continue
            role_frame = ttk.Frame(master)
            role_frame.pack(fill="x", padx=10, pady=2)
            tk.Label(role_frame, text=role.title(), width=10, bg="#8B0000", fg="white").pack(side="left")
            self.permission_vars[role] = {}
            for action in self.data_manager.available_actions:
                var = tk.BooleanVar(value=perms.get(action, False))
                self.permission_vars[role][action] = var
                chk = tk.Checkbutton(role_frame, variable=var, width=15, bg="#8B0000", fg="white", selectcolor="#8B0000", activebackground="#8B0000")
                chk.pack(side="left")

        save_button = tk.Button(master, text="保存权限", command=self.save_permissions, bg="white", fg="#8B0000", font=("Arial", 11, "bold"))
        save_button.pack(pady=20)

    def save_permissions(self):
        for role, actions_vars in self.permission_vars.items():
            for action, var in actions_vars.items():
                self.data_manager.update_role_permission(role, action, var.get())
        messagebox.showinfo("成功", "权限更新成功。")
        if self.app_controller.main_window_instance:
            self.app_controller.main_window_instance.apply_button_permissions()
        self.master.destroy()

class UserManagementWindow:
    def __init__(self, master, app_controller):
        self.master = master
        self.app_controller = app_controller
        self.data_manager = app_controller.data_manager
        master.title("用户管理（管理员）")
        master.geometry("500x450")
        master.configure(bg="#8B0000")
        master.grab_set()

        # --- User List Frame ---
        list_frame = ttk.LabelFrame(master, text="当前用户", padding=10)
        list_frame.pack(pady=10, padx=10, fill="x")
        list_frame.configure(style="Red.TLabelframe")

        self.user_listbox = tk.Listbox(list_frame, height=5, font=("Arial", 12), bg="#8B0000", fg="white", selectbackground="darkblue", selectforeground="white")
        self.user_listbox.pack(side="left", fill="x", expand=True, padx=(0,5))
        user_scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.user_listbox.yview)
        user_scrollbar.pack(side="right", fill="y")
        self.user_listbox.config(yscrollcommand=user_scrollbar.set)
        self.user_listbox.bind('<<ListboxSelect>>', self.on_user_select)

        # --- User Details & Actions Frame ---
        details_frame = ttk.LabelFrame(master, text="添加/编辑用户", padding=10)
        details_frame.pack(pady=10, padx=10, fill="x")
        details_frame.configure(style="Red.TLabelframe")

        tk.Label(details_frame, text="用户名：", font=("Arial", 12), fg="white", bg="#8B0000").grid(row=0, column=0, padx=5, pady=5, sticky="w")
        self.username_entry = tk.Entry(details_frame, font=("Arial", 12))
        self.username_entry.grid(row=0, column=1, padx=5, pady=5, sticky="ew")

        tk.Label(details_frame, text="密码：", font=("Arial", 12), fg="white", bg="#8B0000").grid(row=1, column=0, padx=5, pady=5, sticky="w")
        self.password_entry = tk.Entry(details_frame, show="*", font=("Arial", 12))
        self.password_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        tk.Label(details_frame, text="（如果编辑，留空保持当前密码）", font=("Arial", 10), fg="white", bg="#8B0000").grid(row=1, column=2, padx=5, pady=5, sticky="w")

        tk.Label(details_frame, text="角色：", font=("Arial", 12), fg="white", bg="#8B0000").grid(row=2, column=0, padx=5, pady=5, sticky="w")
        self.role_var = tk.StringVar(master)
        roles = [r for r in self.data_manager.permissions.keys() if r != "admin"]
        if not roles: roles = ["user"]
        self.role_var.set(roles[0] if roles else "user")
        self.role_menu = ttk.Combobox(details_frame, textvariable=self.role_var, values=roles, state="readonly", font=("Arial", 12))
        self.role_menu.grid(row=2, column=1, padx=5, pady=5, sticky="ew")

        details_frame.columnconfigure(1, weight=1)

        action_button_frame = ttk.Frame(details_frame, style="Red.TLabelframe")
        action_button_frame.grid(row=3, column=0, columnspan=3, pady=10)

        self.add_user_button = tk.Button(action_button_frame, text="添加用户", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.add_user)
        self.add_user_button.pack(side="left", padx=5)
        self.update_user_button = tk.Button(action_button_frame, text="更新用户（仅角色）", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.update_user)
        self.update_user_button.pack(side="left", padx=5)
        self.update_user_button.config(state=tk.DISABLED)
        self.delete_user_button = tk.Button(action_button_frame, text="删除用户", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.delete_user)
        self.delete_user_button.pack(side="left", padx=5)
        self.delete_user_button.config(state=tk.DISABLED)
        self.clear_user_fields_button = tk.Button(action_button_frame, text="清空输入", font=("Arial", 11, "bold"), bg="white", fg="#8B0000", command=self.clear_user_fields)
        self.clear_user_fields_button.pack(side="left", padx=5)

        self.refresh_user_list()

    def refresh_user_list(self):
        self.user_listbox.delete(0, tk.END)
        users_info = self.data_manager.get_all_users_info()
        for username, role in users_info.items():
            self.user_listbox.insert(tk.END, f"{username}（{role}）")
        self.clear_user_fields() # Also clear fields and disable buttons

    def on_user_select(self, event: object):
        try:
            selected_index = self.user_listbox.curselection()[0]
            selected_item_str = self.user_listbox.get(selected_index)
            username = selected_item_str.split("（")[0]
            user_obj = self.data_manager.users.get(username)

            if user_obj:
                self.username_entry.delete(0, tk.END)
                self.username_entry.insert(0, user_obj.username)
                self.username_entry.config(state=tk.DISABLED) # Username is key, don't edit
                
                self.password_entry.delete(0, tk.END) # Clear password field for security
                
                self.role_var.set(user_obj.role)

                if username == "admin":
                    self.update_user_button.config(state=tk.DISABLED)
                    self.delete_user_button.config(state=tk.DISABLED)
                    self.role_menu.config(state=tk.DISABLED)
                else:
                    self.update_user_button.config(state=tk.NORMAL)
                    self.delete_user_button.config(state=tk.NORMAL)
                    self.role_menu.config(state="readonly")
                self.add_user_button.config(state=tk.DISABLED)

        except IndexError:
            self.clear_user_fields() # No selection

    def clear_user_fields(self):
        self.username_entry.config(state=tk.NORMAL)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
        if self.role_menu['values']: # Check if Combobox has values
            self.role_var.set(self.role_menu['values'][0]) # Reset to first role
        self.user_listbox.selection_clear(0, tk.END)
        self.update_user_button.config(state=tk.DISABLED)
        self.delete_user_button.config(state=tk.DISABLED)
        self.add_user_button.config(state=tk.NORMAL)
        self.role_menu.config(state="readonly")


    def add_user(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        role = self.role_var.get()

        if not username or not password or not role:
            messagebox.showerror("错误", "用户名、密码和角色均为必填项。", parent=self.master)
            return

        success, message = self.data_manager.add_user(username, password, role)
        if success:
            messagebox.showinfo("成功", message, parent=self.master)
            self.refresh_user_list()
        else:
            messagebox.showerror("错误", message, parent=self.master)

    def update_user(self):
        username = self.username_entry.get() # Should be disabled and pre-filled
        new_role = self.role_var.get()
        new_password = self.password_entry.get() # Optional new password

        if not username:
            messagebox.showerror("错误", "请选择一个用户进行更新。", parent=self.master)
            return
        
        user_obj = self.data_manager.users.get(username)
        if not user_obj:
            messagebox.showerror("错误", "用户未找到。", parent=self.master)
            return

        if username == "admin" and new_role != "admin":
             messagebox.showerror("错误", "管理员用户角色无法更改。", parent=self.master)
             self.role_var.set("admin") # Revert
             return

        user_obj.role = new_role
        if new_password: # If password field is not empty, update password
            user_obj.password = new_password
        
        messagebox.showinfo("成功", f"用户 '{username}' 更新成功。", parent=self.master)
        self.refresh_user_list()


    def delete_user(self):
        username = self.username_entry.get() # Should be disabled and pre-filled
        if not username:
            messagebox.showerror("错误", "请选择一个用户进行删除。", parent=self.master)
            return

        if messagebox.askyesno("确认删除", f"确定要删除用户 '{username}' 吗？", parent=self.master):
            success, message = self.data_manager.delete_user(username)
            if success:
                messagebox.showinfo("成功", message, parent=self.master)
                self.refresh_user_list()
            else:
                messagebox.showerror("错误", message, parent=self.master)


# --- Application Controller ---
class AppController:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.data_manager = DataManager()
        self.current_user: User | None = None
        self.main_window_instance: MainWindow | None = None # To keep track of main window for updates

        # Hide the root window initially
        self.root.withdraw()
        self.show_login_window()

    def show_login_window(self):
        login_toplevel = tk.Toplevel(self.root)
        LoginWindow(login_toplevel, self)
        login_toplevel.protocol("WM_DELETE_WINDOW", self.root.destroy) # Exit app if login closed

    def show_main_window(self):
        # The main application window will be the root window itself or a new Toplevel
        # Using a new Toplevel for main window to keep root hidden as a controller base
        main_toplevel = tk.Toplevel(self.root)
        self.main_window_instance = MainWindow(main_toplevel, self)
        main_toplevel.protocol("WM_DELETE_WINDOW", self.root.destroy) # Exit app if main window closed

    def run(self):
        self.root.mainloop()

# --- Main Execution ---
if __name__ == "__main__":
    root = tk.Tk()
    app = AppController(root)
    app.run() # Start the application

# 最新修改日期2023年5月15日
