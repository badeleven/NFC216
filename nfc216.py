import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
import ndef

# 通用的 URI 前缀映射
URI_PREFIXES = {
    0x00: "",
    0x01: "http://www.",
    0x02: "https://www.",
    0x03: "http://",
    0x04: "https://",
    0x05: "tel:",
    0x06: "mailto:",
    0x07: "ftp://anonymous:anonymous@",
    0x08: "ftp://ftp.",
    0x09: "ftps://",
    0x0A: "sftp://",
    0x0B: "smb://",
    0x0C: "nfs://",
    0x0D: "ftp://",
    0x0E: "dav://",
    0x0F: "news:",
    0x10: "telnet://",
    0x11: "imap:",
    0x12: "rtsp://",
    0x13: "urn:",
    0x14: "pop:",
    0x15: "sip:",
    0x16: "sips:",
    0x17: "tftp:",
    0x18: "btspp://",
    0x19: "btl2cap://",
    0x1A: "btgoep://",
    0x1B: "tcpobex://",
    0x1C: "irdaobex://",
    0x1D: "file://",
    0x1E: "urn:epc:id:",
    0x1F: "urn:epc:tag:",
    0x20: "urn:epc:pat:",
    0x21: "urn:epc:raw:",
    0x22: "urn:epc:",
    0x23: "urn:nfc:"
}

# NTAG 系列卡片参数
NTAG_PARAMS = {
    'NTAG213': {
        'uid_length': 7,
        'capacity': 144,
        'uri_prefixes': URI_PREFIXES,
        'max_blocks': 36
    },
    'NTAG215': {
        'uid_length': 7,
        'capacity': 504,
        'uri_prefixes': URI_PREFIXES,
        'max_blocks': 126
    },
    'NTAG216': {
        'uid_length': 7,
        'capacity': 888,
        'uri_prefixes': URI_PREFIXES,
        'max_blocks': 222
    },
    'NTAG424 DNA': {
        'uid_length': 7,
        'capacity': None,
        'uri_prefixes': URI_PREFIXES,
        'max_blocks': None
    }
}


class NFCApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Dinglan Soft NFC标签写入工具 v1.0")
        self.geometry("1200x900")

        # 初始化组件
        self.ndef_data = bytearray()
        self.reader = None
        self.current_card_type = None
        self.records_to_write = []
        self.setup_ui()
        self.init_reader()
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def setup_ui(self):
        # 主框架
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 顶部状态栏
        status_frame = ttk.Frame(main_frame, padding=5)
        status_frame.pack(fill=tk.X)
        ttk.Label(status_frame, text="状态:").pack(side=tk.LEFT)
        self.status_label = ttk.Label(status_frame, text="等待读卡器连接...")
        self.status_label.pack(side=tk.LEFT, padx=10)

        # 中间操作面板
        operation_frame = ttk.LabelFrame(main_frame, text="操作面板", padding=10)
        operation_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        # 读取、查看详情、清除数据按钮
        button_frame = ttk.Frame(operation_frame, padding=5)
        button_frame.pack(fill=tk.X)
        ttk.Button(button_frame, text="读取卡片", command=self.read_card).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="查看详情", command=self.show_detail).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="清除数据", command=self.clear_card).pack(side=tk.LEFT, padx=5)

        # 写入数据部分
        write_frame = ttk.Frame(operation_frame, padding=5)
        write_frame.pack(fill=tk.X, pady=10)

        # 第一行：选择记录类型、URI 前缀选择框、输入内容、应用名称输入
        first_row_frame = ttk.Frame(write_frame)
        first_row_frame.pack(fill=tk.X, pady=5)

        # 选择记录类型
        record_type_frame = ttk.Frame(first_row_frame)
        record_type_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(record_type_frame, text="记录类型:").pack(side=tk.LEFT)
        self.record_type_var = tk.StringVar()
        self.record_type_var.set("url")
        record_type_combobox = ttk.Combobox(record_type_frame, textvariable=self.record_type_var,
                                            values=["url", "text", "app", "composite", "aar"])
        record_type_combobox.pack(side=tk.LEFT, padx=5)
        record_type_combobox.bind("<<ComboboxSelected>>", self.on_record_type_change)

        # URI 前缀选择框
        uri_prefix_frame = ttk.Frame(first_row_frame)
        uri_prefix_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(uri_prefix_frame, text="URI 前缀:").pack(side=tk.LEFT)
        self.uri_prefix_var = tk.StringVar()
        self.uri_prefix_combobox = ttk.Combobox(uri_prefix_frame, textvariable=self.uri_prefix_var)
        self.uri_prefix_combobox['values'] = list(URI_PREFIXES.values())
        self.uri_prefix_combobox.pack(side=tk.LEFT, padx=5)
        self.uri_prefix_combobox.config(state=tk.DISABLED)

        # 确保初始化时 URL 记录类型下的前缀框显示默认值
        if self.record_type_var.get() == "url":
            self.uri_prefix_combobox.config(state=tk.NORMAL)
            self.uri_prefix_var.set("http://www.")

        # 输入内容
        input_content_frame = ttk.Frame(first_row_frame)
        input_content_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(input_content_frame, text="输入内容:").pack(side=tk.LEFT)
        self.input_content_entry = ttk.Entry(input_content_frame, width=30)
        self.input_content_entry.insert(0, "dinglansoft.com")
        self.input_content_entry.pack(side=tk.LEFT, padx=5)

        # 应用名称输入
        app_name_frame = ttk.Frame(first_row_frame)
        app_name_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(app_name_frame, text="应用名称:").pack(side=tk.LEFT)
        self.app_name_entry = ttk.Entry(app_name_frame, width=20)
        self.app_name_entry.insert(0, "com.tencent.mm")
        self.app_name_entry.pack(side=tk.LEFT, padx=5)
        self.app_name_entry.config(state=tk.DISABLED)

        # 第二行：复合记录输入
        second_row_frame = ttk.Frame(write_frame)
        second_row_frame.pack(fill=tk.X, pady=5)

        # 复合记录输入
        composite_record_frame = ttk.Frame(second_row_frame)
        composite_record_frame.pack(side=tk.LEFT, padx=5)
        ttk.Label(composite_record_frame, text="复合记录(格式: type1:content1,type2:content2):").pack(side=tk.LEFT)
        self.composite_record_entry = ttk.Entry(composite_record_frame, width=30)
        self.composite_record_entry.insert(0, "url:example.com,text:example text")
        self.composite_record_entry.pack(side=tk.LEFT, padx=5)
        self.composite_record_entry.config(state=tk.DISABLED)

        # 第三行：添加记录、写入记录、清空记录、删除单条记录按钮
        third_row_frame = ttk.Frame(write_frame)
        third_row_frame.pack(fill=tk.X, pady=5)

        # 添加记录和写入按钮
        button_group_frame = ttk.Frame(third_row_frame)
        button_group_frame.pack(side=tk.LEFT, padx=5)
        add_record_button = ttk.Button(button_group_frame, text="添加记录", command=self.add_record)
        add_record_button.pack(side=tk.LEFT, padx=5)
        write_button = ttk.Button(button_group_frame, text="写入记录", command=self.write_ndef)
        write_button.pack(side=tk.LEFT, padx=5)
        clear_records_button = ttk.Button(button_group_frame, text="清空记录", command=self.clear_records)
        clear_records_button.pack(side=tk.LEFT, padx=5)
        delete_record_button = ttk.Button(button_group_frame, text="删除单条记录", command=self.delete_selected_record)
        delete_record_button.pack(side=tk.LEFT, padx=5)

        # 显示已添加记录的列表框
        self.record_listbox = tk.Listbox(write_frame, width=80, height=5)
        self.record_listbox.pack(pady=5)

        # 信息面板
        info_frame = ttk.LabelFrame(main_frame, text="卡片信息", padding=10)
        info_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.info_tree = ttk.Treeview(info_frame, columns=('value'), show='tree')
        self.info_tree.column('#0', width=200, anchor='w')
        self.info_tree.column('value', width=400, anchor='w')
        self.info_tree.pack(fill=tk.BOTH, expand=True)

        # 为卡片信息框添加右键复制菜单
        self.info_tree.bind("<Button-3>", self.show_copy_menu)
        self.copy_menu = tk.Menu(self, tearoff=0)
        self.copy_menu.add_command(label="复制", command=self.copy_info)

        # 底部日志面板
        log_frame = ttk.LabelFrame(main_frame, text="通信日志", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        self.log_area = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_area.pack(fill=tk.BOTH, expand=True)
        clear_log_button = ttk.Button(log_frame, text="清空日志", command=self.clear_log)
        clear_log_button.pack(anchor=tk.E, padx=5, pady=5)

        # 初始化信息树
        self.init_info_tree()
        self.on_record_type_change(None)

    def init_info_tree(self):
        info_items = [
            ('标签标识符', '未读取'),
            ('卡片类型', '未知'),
            ('数据格式', 'NFC Forum Type 2'),
            ('记录内容', '无数据'),
            ('数据验证', '未验证'),
            ('存储容量', '未知')
        ]
        for item in info_items:
            self.info_tree.insert('', 'end', text=item[0], values=(item[1],))

    def init_reader(self):
        try:
            reader_list = readers()
            if reader_list:
                self.reader = reader_list[0]
                self.update_status("ACR122U 已连接")
                self.log("读卡器初始化成功")
            else:
                self.update_status("未检测到读卡器", error=True)
        except Exception as e:
            self.log_error(f"读卡器连接失败: {str(e)}")

    def read_card(self):
        if not self.reader:
            self.log_error("错误：读卡器未连接")
            return

        try:
            conn = self.reader.createConnection()
            conn.connect()

            # 读取 UID
            uid = self.send_apdu(conn, [0xFF, 0xCA, 0x00, 0x00, 0x00])
            if uid:
                self.update_info('标签标识符', self.format_uid(uid))
            else:
                return

            # 识别卡片类型
            card_type = self.identify_card_type(conn)
            if card_type:
                self.current_card_type = card_type
                self.update_info('卡片类型', card_type)
                capacity = NTAG_PARAMS.get(card_type, {}).get('capacity')
                if capacity:
                    self.update_info('存储容量', f"{capacity} 字节")
                if self.verify_ntag_card(conn, uid, card_type):
                    self.read_ndef_data(conn, card_type)
                else:
                    self.log_error("卡片类型验证失败")
            else:
                self.log_error("无法识别卡片类型")

        except Exception as e:
            self.log_error(f"读取失败: {str(e)}")

    def identify_card_type(self, conn):
        # 读取 UID
        SELECT_UID = [0xFF, 0xCA, 0x00, 0x00, 0x00]
        response, sw1, sw2 = conn.transmit(SELECT_UID)
        if sw1 != 0x90 or sw2 != 0x00:
            print("Failed to read UID.")
            return None

        # 尝试读取 CC 区域 (Capability Container) 来判断存储容量
        READ_CC = [0xFF, 0xB0, 0x00, 0x03, 0x04]
        response, sw1, sw2 = conn.transmit(READ_CC)
        if sw1 == 0x90 and sw2 == 0x00:
            cc_data = response[:4]
            print(f"CC Data: {toHexString(cc_data)}")
            try:
                if cc_data[0] != 0xE1:
                    print("Not a valid Type 2 Tag.")
                    return None
                version_and_capacity = cc_data[1]
                capacity_code = version_and_capacity & 0x0F
                if capacity_code == 0x01:
                    return "NTAG216"
                elif capacity_code == 0x02:
                    return "NTAG215"
                elif capacity_code == 0x03:
                    return "NTAG213"
                else:
                    print("Unknown capacity code.")
            except IndexError:
                print("Invalid CC data. Possibly not an NTAG card.")
        else:
            print("Failed to read CC data. Possibly not a Type 2 Tag.")

        # 检查是否为 NTAG424 DNA（尝试发送原创性验证命令）
        SELECT_ISO_14443_4 = [0xFF, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01]
        response, sw1, sw2 = conn.transmit(SELECT_ISO_14443_4)
        if sw1 == 0x90 and sw2 == 0x00:
            return "NTAG424 DNA"
        return None

    def verify_ntag_card(self, conn, uid, card_type):
        params = NTAG_PARAMS.get(card_type)
        if not params:
            return False
        uid_valid = len(uid) == params['uid_length']
        if not uid_valid:
            self.log_error(f"UID 长度验证失败: 期望 {params['uid_length']} 字节，实际 {len(uid)} 字节")
            return False
        return True

    def read_ndef_data(self, conn, card_type):
        self.ndef_data = bytearray()
        params = NTAG_PARAMS.get(card_type)
        if not params:
            return
        try:
            for block in range(4, params['max_blocks']):
                resp = self.send_apdu(conn, [0xFF, 0xB0, 0x00, block, 4])
                if not resp:
                    continue
                if 0xFE in resp:
                    term_pos = len(self.ndef_data) + resp.index(0xFE)
                    self.ndef_data.extend(resp[:resp.index(0xFE)])
                    break
                else:
                    self.ndef_data.extend(resp)
            self.log(f"读取完成，共 {len(self.ndef_data)} 字节")
            self.process_ndef_data()
        except Exception as e:
            self.log_error(f"数据读取失败: {str(e)}")

    def process_ndef_data(self):
        try:
            records = list(ndef.message_decoder(bytes(self.ndef_data)))
            for record in records:
                if isinstance(record, ndef.UriRecord):
                    self._handle_standard_record(record)
                elif isinstance(record, ndef.TextRecord):
                    self._handle_text_record(record)
        except ndef.DecodeError as e:
            self.log_warning(f"标准解析失败: {str(e)}")
        try:
            self._enhanced_parse()
        except Exception as e:
            self.log_warning(f"增强解析失败: {str(e)}")
            self._fallback_parse()

    def _handle_standard_record(self, record):
        self.update_info('记录内容', record.uri)
        self.update_info('数据验证', '标准验证通过')

    def _handle_text_record(self, record):
        self.update_info('记录内容', record.text)
        self.update_info('数据验证', '标准验证通过')

    def _enhanced_parse(self):
        if len(self.ndef_data) < 8:
            raise ValueError("数据长度不足 8 字节")
        payload = self.ndef_data[4:]
        try:
            type_length = payload[0]
            payload_length = payload[1]
            uri_code = payload[2]
            uri_body_bytes = payload[3:3 + payload_length - 1]
            uri_body = uri_body_bytes.decode('utf-8').split('\x00')[0]
            full_url = NTAG_PARAMS[self.current_card_type]['uri_prefixes'].get(uri_code, "") + uri_body
            self._update_parsed_data(full_url)
        except IndexError as e:
            raise ValueError("数据结构异常") from e

    def _fallback_parse(self):
        try:
            for index, byte in enumerate(self.ndef_data):
                if byte in NTAG_PARAMS[self.current_card_type]['uri_prefixes']:
                    uri_start = index + 1
                    try:
                        term_pos = self.ndef_data.index(0xFE, uri_start)
                        uri_body = bytes(self.ndef_data[uri_start:term_pos]).decode('utf-8')
                    except ValueError:
                        uri_body = bytes(self.ndef_data[uri_start:]).decode('utf-8', errors='ignore').split('\x00')[0]
                    full_url = NTAG_PARAMS[self.current_card_type]['uri_prefixes'][byte] + uri_body
                    self._update_parsed_data(full_url)
                    return
            raise ValueError("未找到有效的 URI 代码")
        except Exception as e:
            self.log_error(f"最终解析失败: {str(e)}")
            self.update_info('数据验证', '解析异常')

    def _update_parsed_data(self, url):
        clean_url = url.split('\x00')[0].strip()
        self.update_info('记录内容', clean_url)
        self.update_info('数据验证', '验证通过')

    def add_record(self):
        record_type = self.record_type_var.get()
        input_content = self.input_content_entry.get()
        app_name = self.app_name_entry.get()
        if record_type == "aar":
            if not app_name:
                messagebox.showerror("错误", "AAR 记录需要输入应用包名")
                return
            record = ndef.Record(name='android.com:pkg', data=app_name.encode())
            record_content = f"AAR: {app_name}"
        elif record_type == "url":
            uri_prefix = self.uri_prefix_var.get()
            if not uri_prefix:
                uri_prefix = "http://www."
                self.uri_prefix_var.set(uri_prefix)
            full_url = uri_prefix + input_content
            record = ndef.UriRecord(full_url)
            record_content = f"URL: {full_url}"
        elif record_type == "text":
            record = ndef.TextRecord(input_content)
            record_content = f"文本: {input_content}"
        elif record_type == "app":
            if not app_name:
                messagebox.showerror("错误", "应用记录需要输入应用包名")
                return
            record = ndef.Record(
                type='urn:nfc:ext:android.com:pkg',
                name='',
                data=app_name.encode()
            )
            record_content = f"应用: {app_name}"
        elif record_type == "composite":
            messagebox.showerror("错误", "复合记录功能未完全实现")
            return
        else:
            messagebox.showerror("错误", "不支持的记录类型")
            return
        self.records_to_write.append(record)
        self.record_listbox.insert(tk.END, record_content)
        self.log(f"添加记录: {record_content}")

    def write_ndef(self):
        if not self.records_to_write:
            messagebox.showerror("错误", "请先添加记录")
            return
        if not self.current_card_type:
            messagebox.showerror("错误", "未识别到卡片类型，无法写入数据")
            return
        try:
            conn = self.reader.createConnection()
            conn.connect()
            ndef_message = b''.join(ndef.message_encoder(self.records_to_write))
            tlv_header = bytes([0x03, len(ndef_message)])
            tlv_terminator = bytes([0xFE])
            tlv_data = tlv_header + ndef_message + tlv_terminator
            params = NTAG_PARAMS.get(self.current_card_type)
            if not params:
                return
            max_capacity = (params['max_blocks'] - 4) * 4
            if len(tlv_data) > max_capacity:
                messagebox.showerror("错误", f"数据超出容量限制（最大 {max_capacity} 字节）")
                return
            self.log("正在写入能力容器...")
            cc_data = [0xE1, 0x10, 0x06, 0x00]
            self.send_apdu(conn, [0xFF, 0xD6, 0x00, 3, 4] + cc_data)
            self.log("正在写入数据块...")
            for block_index, chunk in enumerate(self.chunked(tlv_data, 4)):
                block_number = 4 + block_index
                if block_number > params['max_blocks']:
                    raise ValueError("超出卡片最大块限制")
                padded_chunk = chunk.ljust(4, b'\x00')
                self.send_apdu(conn, [0xFF, 0xD6, 0x00, block_number, 4] + list(padded_chunk))
                self.log(f"块 {block_number} 写入完成")
            if tlv_terminator not in tlv_data:
                self.log_warning("未检测到 TLV 终止符，补充写入")
                last_block = 4 + len(list(self.chunked(tlv_data, 4)))
                self.send_apdu(conn, [0xFF, 0xD6, 0x00, last_block, 4] + [0xFE, 0x00, 0x00, 0x00])
            self.ndef_data = tlv_data
            self.log(f"成功写入 {len(tlv_data)} 字节数据")
            self.update_info('记录内容', ', '.join([str(record) for record in self.records_to_write]))
            self.records_to_write = []
            self.record_listbox.delete(0, tk.END)
            messagebox.showinfo("成功", "记录写入完成")
        except Exception as e:
            self.log_error(f"写入失败: {str(e)}")

    def clear_card(self):
        if not self.current_card_type:
            self.log_error("未识别到卡片类型，无法清除数据")
            return
        try:
            conn = self.reader.createConnection()
            conn.connect()
            params = NTAG_PARAMS.get(self.current_card_type)
            if not params:
                return
            for block in range(4, params['max_blocks']):
                self.send_apdu(conn, [0xFF, 0xD6, 0x00, block, 4, 0, 0, 0, 0])
            self.log("数据清除成功")
            self.update_info('记录内容', '无数据')
            self.ndef_data = bytearray()
        except Exception as e:
            self.log_error(f"清除失败: {str(e)}")

    def show_detail(self):
        if not self.ndef_data:
            messagebox.showinfo("详情", "没有可显示的数据")
            return
        detail_win = tk.Toplevel(self)
        detail_win.title("数据详情")
        text_area = scrolledtext.ScrolledText(detail_win, width=90, height=25)
        text_area.pack(padx=10, pady=10)
        hex_data = ' '.join(f"{b:02X}" for b in self.ndef_data)
        text_content = self.ndef_data.decode('utf-8', errors='replace').split('\x00')[0]
        content = [
            "HEX 数据:",
            hex_data,
            "\n文本内容:",
            text_content,
            "\n验证状态:",
            self.info_tree.item(self.find_tree_item('数据验证'))['values'][0]
        ]
        text_area.insert(tk.END, '\n'.join(content))
        text_area.configure(state='disabled')

    def send_apdu(self, conn, apdu):
        try:
            data, sw1, sw2 = conn.transmit(apdu)
            status = (sw1 << 8) | sw2
            status_messages = {
                0x6A81: "不支持的指令",
                0x6300: "需要认证",
                0x6700: "长度错误",
                0x6982: "安全条件不满足"
            }
            if status in status_messages:
                self.log_warning(f"指令 {toHexString(apdu)} 返回: {status_messages[status]} (0x{status:04X})")
                return []
            elif status != 0x9000:
                self.log_warning(f"指令 {toHexString(apdu)} 返回未知状态: 0x{status:04X}")
                return []
            return data
        except Exception as e:
            self.log_error(f"APDU 传输错误: {str(e)}")
            return []

    def update_status(self, message, error=False):
        color = "red" if error else "black"
        self.status_label.config(text=message, foreground=color)

    def log(self, message):
        self.log_area.insert(tk.END, f"{message}\n")
        self.log_area.see(tk.END)

    def log_warning(self, message):
        self.log_area.insert(tk.END, f"警告: {message}\n")
        self.log_area.see(tk.END)

    def log_error(self, message):
        self.log_area.insert(tk.END, f"错误: {message}\n")
        self.log_area.see(tk.END)

    def update_info(self, key, value):
        item = self.find_tree_item(key)
        if item:
            self.info_tree.item(item, values=(value,))

    def find_tree_item(self, key):
        for item in self.info_tree.get_children():
            if self.info_tree.item(item)['text'] == key:
                return item
        return None

    def show_copy_menu(self, event):
        item = self.info_tree.identify_row(event.y)
        if item:
            self.copy_menu.post(event.x_root, event.y_root)

    def copy_info(self):
        selected_item = self.info_tree.selection()
        if selected_item:
            value = self.info_tree.item(selected_item)['values'][0]
            self.clipboard_clear()
            self.clipboard_append(value)

    def clear_log(self):
        self.log_area.delete(1.0, tk.END)

    def clear_records(self):
        self.records_to_write = []
        self.record_listbox.delete(0, tk.END)

    def delete_selected_record(self):
        selected_index = self.record_listbox.curselection()
        if selected_index:
            index = selected_index[0]
            del self.records_to_write[index]
            self.record_listbox.delete(index)

    def chunked(self, iterable, n):
        """Yield successive n-sized chunks from iterable."""
        for i in range(0, len(iterable), n):
            yield iterable[i:i + n]

    def format_uid(self, uid):
        return '-'.join(f'{b:02X}' for b in uid)

    def on_close(self):
        self.destroy()

    def on_record_type_change(self, event):
        record_type = self.record_type_var.get()
        if record_type == "url":
            self.uri_prefix_combobox.config(state=tk.NORMAL)
            if not self.uri_prefix_var.get():
                self.uri_prefix_var.set("http://www.")
            self.app_name_entry.config(state=tk.DISABLED)
            self.composite_record_entry.config(state=tk.DISABLED)
        elif record_type == "text":
            self.uri_prefix_combobox.config(state=tk.DISABLED)
            self.app_name_entry.config(state=tk.DISABLED)
            self.composite_record_entry.config(state=tk.DISABLED)
        elif record_type in ["app", "aar"]:
            self.uri_prefix_combobox.config(state=tk.DISABLED)
            self.app_name_entry.config(state=tk.NORMAL)
            self.composite_record_entry.config(state=tk.DISABLED)
        elif record_type == "composite":
            self.uri_prefix_combobox.config(state=tk.DISABLED)
            self.app_name_entry.config(state=tk.DISABLED)
            self.composite_record_entry.config(state=tk.NORMAL)


if __name__ == "__main__":
    app = NFCApp()
    app.mainloop()
    
