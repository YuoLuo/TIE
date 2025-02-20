# -*- coding: utf-8 -*-
from burp import IBurpExtender, IHttpListener, ITab
from javax.swing import (JPanel, JCheckBox, JScrollPane, JTable, BoxLayout, JButton, 
                        BorderFactory, JTextField, JLabel, SwingUtilities, JPopupMenu, JMenuItem, Box)
from javax.swing.table import DefaultTableModel, TableRowSorter
from javax.swing.RowFilter import regexFilter
from javax.swing.event import DocumentListener
from java.awt import BorderLayout, Dimension, Insets
from java.awt.datatransfer import StringSelection
from java.awt.Toolkit import getDefaultToolkit
import re
import time

# 定义 UI 文本
UI_TEXT = {
    'plugin_name': u'目标信息提取器',
    'proxy_traffic': u'记录代理流量',
    'extender_traffic': u'记录扩展流量',
    'repeater_traffic': u'记录重放流量',
    'scanner_traffic': u'记录扫描流量',
    'enable_plugin': u'启用插件',
    'filter_label': u'过滤: ',
    'copy_ips': u'复制所有IP',
    'copy_domains': u'复制所有域名',
    'clear_records': u'清除所有记录',
    'export_file': u'导出到文件',
    'ip_column': u'IP地址',
    'domain_column': u'域名',
    'copy_selected': u'复制选中项',
    'delete_selected': u'删除选中项',
    'max_entries_alert': u'已达到最大条目数，请考虑清理旧数据。',
    'cleanup_alert': u'正在执行自动清理...',
    'export_ip_title': u'=== IP地址列表 ===\n',
    'export_domain_title': u'\n\n=== 域名列表 ===\n',
    'export_failed': u'导出失败: ',
    'http_error': u'处理HTTP消息时出错: ',
    'extract_error': u'提取信息时出错: ',
    'filter_error': u'过滤错误: ',
    'traffic_sources': u'流量来源'
}

# 在文件顶部添加域名后缀常量
DOMAIN_SUFFIXES = {
    ".com", ".net", ".org", ".edu", ".gov", ".mil", ".cn", ".com.cn", ".net.cn", ".org.cn", 
    ".info", ".biz", ".tv", ".cc", ".co", ".me", ".us", ".uk", ".de", ".fr", ".jp", ".kr", ".in", 
    ".au", ".ru", ".br", ".it", ".es", ".nl", ".se", ".no", ".fi", ".dk", ".at", ".ch", ".be", 
    ".pl", ".cz", ".sk", ".hu", ".gr", ".pt", ".tr", ".ua", ".mx", ".ar", ".cl", ".co", ".ve"
}

class BurpExtender(IBurpExtender, IHttpListener, ITab):
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName(UI_TEXT['plugin_name'])
        
        # 初始化数据限制
        self.MAX_ENTRIES = 10000
        self.current_entries = 0
        self.last_cleanup_time = time.time()
        self.CLEANUP_INTERVAL = 300  # 5分钟清理一次
        
        self.initUI()
        callbacks.addSuiteTab(self)
        callbacks.registerHttpListener(self)
        self.isPluginEnabled = False

    def initUI(self):
        # 创建主面板
        self.panel = JPanel(BorderLayout(10, 10))
        self.panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10))
        
        # 创建启用插件的开关面板
        switchPanel = JPanel(BorderLayout())
        switchPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5))
        self.globalSwitch = JCheckBox(UI_TEXT['enable_plugin'])
        self.globalSwitch.addActionListener(self.togglePlugin)
        switchPanel.add(self.globalSwitch, BorderLayout.WEST)
        
        # 创建功能面板（初始隐藏）
        self.functionPanel = JPanel(BorderLayout())
        
        # 创建北部控制面板
        controlPanel = JPanel(BorderLayout(5, 5))
        controlPanel.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createTitledBorder(UI_TEXT['traffic_sources']),
            BorderFactory.createEmptyBorder(5, 5, 5, 5)
        ))
        
        # 创建复选框面板
        checkboxPanel = JPanel()
        checkboxPanel.setLayout(BoxLayout(checkboxPanel, BoxLayout.X_AXIS))
        
        self.proxyCheckbox = JCheckBox(UI_TEXT['proxy_traffic'])
        self.extenderCheckbox = JCheckBox(UI_TEXT['extender_traffic'])
        self.repeaterCheckbox = JCheckBox(UI_TEXT['repeater_traffic'])
        self.scannerCheckbox = JCheckBox(UI_TEXT['scanner_traffic'])
        
        # 添加复选框和间距
        checkboxPanel.add(Box.createHorizontalStrut(5))
        checkboxPanel.add(self.proxyCheckbox)
        checkboxPanel.add(Box.createHorizontalStrut(10))
        checkboxPanel.add(self.extenderCheckbox)
        checkboxPanel.add(Box.createHorizontalStrut(10))
        checkboxPanel.add(self.repeaterCheckbox)
        checkboxPanel.add(Box.createHorizontalStrut(10))
        checkboxPanel.add(self.scannerCheckbox)
        checkboxPanel.add(Box.createHorizontalGlue())
        
        controlPanel.add(checkboxPanel, BorderLayout.CENTER)
        
        # 创建过滤器面板
        filterPanel = JPanel(BorderLayout(5, 0))
        filterPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0))
        filterLabel = JLabel(UI_TEXT['filter_label'])
        self.filterField = JTextField()
        self.filterField.getDocument().addDocumentListener(FilterListener(self))
        filterPanel.add(filterLabel, BorderLayout.WEST)
        filterPanel.add(self.filterField, BorderLayout.CENTER)
        
        # 创建表格
        self.tableModel = DefaultTableModel()
        self.tableModel.addColumn(UI_TEXT['ip_column'])
        self.tableModel.addColumn(UI_TEXT['domain_column'])
        self.infoTable = JTable(self.tableModel)
        self.sorter = TableRowSorter(self.tableModel)
        self.infoTable.setRowSorter(self.sorter)
        self.infoTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS)
        
        # 设置表格滚动面板
        scrollPane = JScrollPane(self.infoTable)
        scrollPane.setPreferredSize(Dimension(800, 400))
        
        # 创建按钮面板
        buttonPanel = JPanel()
        buttonPanel.setLayout(BoxLayout(buttonPanel, BoxLayout.X_AXIS))
        buttonPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0))
        
        # 创建按钮并设置统一大小
        buttonSize = Dimension(120, 25)
        self.copyIPsButton = JButton(UI_TEXT['copy_ips'])
        self.copyDomainsButton = JButton(UI_TEXT['copy_domains'])
        self.clearButton = JButton(UI_TEXT['clear_records'])
        self.exportButton = JButton(UI_TEXT['export_file'])
        
        for button in [self.copyIPsButton, self.copyDomainsButton, self.clearButton, self.exportButton]:
            button.setPreferredSize(buttonSize)
            button.setMaximumSize(buttonSize)
            button.setEnabled(False)  # 初始禁用所有按钮
        
        # 添加按钮事件
        self.copyIPsButton.addActionListener(self.copyIPsToClipboard)
        self.copyDomainsButton.addActionListener(self.copyDomainsToClipboard)
        self.clearButton.addActionListener(self.clearAllRecords)
        self.exportButton.addActionListener(self.exportToFile)
        
        # 组装按钮面板
        buttonPanel.add(Box.createHorizontalGlue())
        buttonPanel.add(self.copyIPsButton)
        buttonPanel.add(Box.createHorizontalStrut(10))
        buttonPanel.add(self.copyDomainsButton)
        buttonPanel.add(Box.createHorizontalStrut(10))
        buttonPanel.add(self.clearButton)
        buttonPanel.add(Box.createHorizontalStrut(10))
        buttonPanel.add(self.exportButton)
        buttonPanel.add(Box.createHorizontalGlue())
        
        # 添加右键菜单
        self.infoTable.setComponentPopupMenu(self.createPopupMenu())
        
        # 组装功能面板
        northPanel = JPanel()
        northPanel.setLayout(BoxLayout(northPanel, BoxLayout.Y_AXIS))
        northPanel.add(controlPanel)
        northPanel.add(filterPanel)
        
        self.functionPanel.add(northPanel, BorderLayout.NORTH)
        self.functionPanel.add(scrollPane, BorderLayout.CENTER)
        self.functionPanel.add(buttonPanel, BorderLayout.SOUTH)
        
        # 初始隐藏功能面板
        self.functionPanel.setVisible(False)
        
        # 组装主面板
        self.panel.add(switchPanel, BorderLayout.NORTH)
        self.panel.add(self.functionPanel, BorderLayout.CENTER)
        
        # 初始化集合
        self.ipSet = set()
        self.domainSet = set()

    def createPopupMenu(self):
        popup = JPopupMenu()
        copySelectedItem = JMenuItem(UI_TEXT['copy_selected'])
        deleteSelectedItem = JMenuItem(UI_TEXT['delete_selected'])
        
        copySelectedItem.addActionListener(lambda e: self.copySelected())
        deleteSelectedItem.addActionListener(lambda e: self.deleteSelected())
        
        popup.add(copySelectedItem)
        popup.add(deleteSelectedItem)
        return popup

    def copySelected(self):
        rows = self.infoTable.getSelectedRows()
        selected_data = []
        for row in rows:
            model_row = self.infoTable.convertRowIndexToModel(row)
            ip = self.tableModel.getValueAt(model_row, 0)
            domain = self.tableModel.getValueAt(model_row, 1)
            if ip: selected_data.append(ip)
            if domain: selected_data.append(domain)
        
        if selected_data:
            stringSelection = StringSelection('\n'.join(selected_data))
            clipboard = getDefaultToolkit().getSystemClipboard()
            clipboard.setContents(stringSelection, None)

    def deleteSelected(self):
        def delete():
            rows = self.infoTable.getSelectedRows()
            rows = sorted(rows, reverse=True)
            for row in rows:
                model_row = self.infoTable.convertRowIndexToModel(row)
                ip = self.tableModel.getValueAt(model_row, 0)
                domain = self.tableModel.getValueAt(model_row, 1)
                if ip: self.ipSet.remove(ip)
                if domain: self.domainSet.remove(domain)
                self.tableModel.removeRow(model_row)
                self.current_entries -= 1
        
        SwingUtilities.invokeLater(delete)

    def exportToFile(self, event):
        try:
            with open("target_info_export.txt", "w", encoding='utf-8') as f:
                f.write(UI_TEXT['export_ip_title'])
                f.write('\n'.join(sorted(self.ipSet)))
                f.write(UI_TEXT['export_domain_title'])
                f.write('\n'.join(sorted(self.domainSet)))
        except Exception as e:
            self._callbacks.issueAlert(UI_TEXT['export_failed'] + str(e))

    def checkCleanup(self):
        current_time = time.time()
        if current_time - self.last_cleanup_time > self.CLEANUP_INTERVAL:
            self.performCleanup()
            self.last_cleanup_time = current_time

    def performCleanup(self):
        if self.current_entries > self.MAX_ENTRIES * 0.8:
            self._callbacks.issueAlert(UI_TEXT['cleanup_alert'])
            self.clearAllRecords(None)

    def togglePlugin(self, event):
        # 切换插件启用状态
        self.isPluginEnabled = self.globalSwitch.isSelected()
        # 显示/隐藏功能面板
        self.functionPanel.setVisible(self.isPluginEnabled)
        # 启用/禁用按钮
        self.copyIPsButton.setEnabled(self.isPluginEnabled)
        self.copyDomainsButton.setEnabled(self.isPluginEnabled)
        self.clearButton.setEnabled(self.isPluginEnabled)
        self.exportButton.setEnabled(self.isPluginEnabled)

    def copyIPsToClipboard(self, event):
        # 复制所有IP到剪贴板
        ips = '\n'.join(self.ipSet)
        stringSelection = StringSelection(ips)
        clipboard = getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(stringSelection, None)

    def copyDomainsToClipboard(self, event):
        # 复制所有域名到剪贴板
        domains = '\n'.join(self.domainSet)
        stringSelection = StringSelection(domains)
        clipboard = getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(stringSelection, None)

    def clearAllRecords(self, event):
        # 清除所有记录
        self.ipSet.clear()
        self.domainSet.clear()
        SwingUtilities.invokeLater(lambda: self.tableModel.setRowCount(0))

    def getTabCaption(self):
        # 返回标签页名称
        return "Target Info Extractor"

    def getUiComponent(self):
        # 返回UI组件
        return self.panel

    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # 处理HTTP消息，根据工具标记和复选框状态判断是否处理
        if not self.isPluginEnabled:
            return

        if (self.proxyCheckbox.isSelected() and toolFlag == self._callbacks.TOOL_PROXY) or \
           (self.extenderCheckbox.isSelected() and toolFlag == self._callbacks.TOOL_EXTENDER) or \
           (self.repeaterCheckbox.isSelected() and toolFlag == self._callbacks.TOOL_REPEATER) or \
           (self.scannerCheckbox.isSelected() and toolFlag == self._callbacks.TOOL_SCANNER):

            # 提取和显示信息
            self.extractAndDisplayInfo(messageInfo, messageIsRequest)

    def extractAndDisplayInfo(self, messageInfo, messageIsRequest):
        try:
            if messageIsRequest:
                requestInfo = self._helpers.analyzeRequest(messageInfo)
                self.extractAndAddInfo(self._helpers.bytesToString(messageInfo.getRequest()))
            else:
                response = self._helpers.bytesToString(messageInfo.getResponse())
                self.extractAndAddInfo(response)
        except Exception as e:
            self._callbacks.issueAlert(UI_TEXT['http_error'] + str(e))

    def extractAndAddInfo(self, message):
        try:
            # 预编译正则表达式，提高匹配效率
            IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
            DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}\b')
            
            # 使用更精确的IP地址正则表达式，减少后续验证
            ips = IP_PATTERN.findall(message)
            domains = DOMAIN_PATTERN.findall(message)

            # 批量处理数据
            batch_size = 50
            new_ips = []
            new_domains = []

            # 过滤IP（排除内部IP）
            for ip in ips:
                if self.current_entries >= self.MAX_ENTRIES:
                    break
                if ip not in self.ipSet and not self._is_internal_ip(ip):
                    new_ips.append(ip)
                    self.ipSet.add(ip)
                    self.current_entries += 1

            # 过滤域名
            for domain in domains:
                if self.current_entries >= self.MAX_ENTRIES:
                    break
                if domain not in self.domainSet and any(domain.endswith(suffix) for suffix in DOMAIN_SUFFIXES):
                    new_domains.append(domain)
                    self.domainSet.add(domain)
                    self.current_entries += 1

            # 批量更新UI
            if new_ips or new_domains:
                def updateUI():
                    # 批量添加IP
                    for i in range(0, len(new_ips), batch_size):
                        batch = new_ips[i:i + batch_size]
                        for ip in batch:
                            self.tableModel.addRow([ip, ""])
                    
                    # 批量添加域名
                    for i in range(0, len(new_domains), batch_size):
                        batch = new_domains[i:i + batch_size]
                        for domain in batch:
                            self.tableModel.addRow(["", domain])
                
                SwingUtilities.invokeLater(updateUI)

            # 检查是否需要清理
            if self.current_entries >= self.MAX_ENTRIES:
                self._callbacks.issueAlert(UI_TEXT['max_entries_alert'])
            else:
                self.checkCleanup()
                
        except Exception as e:
            self._callbacks.issueAlert(UI_TEXT['extract_error'] + str(e))

    def _is_internal_ip(self, ip):
        # 快速检查内部IP
        try:
            parts = [int(p) for p in ip.split('.')]
            return (
                parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] == 127
            )
        except (ValueError, IndexError):
            return False

class FilterListener(DocumentListener):
    def __init__(self, extender):
        self.extender = extender
        self.last_update = 0
        self.DEBOUNCE_DELAY = 300  # 300ms

    def insertUpdate(self, e):
        self.filterTable()

    def removeUpdate(self, e):
        self.filterTable()

    def changedUpdate(self, e):
        self.filterTable()

    def filterTable(self):
        try:
            current_time = int(time.time() * 1000)
            if current_time - self.last_update < self.DEBOUNCE_DELAY:
                return
            self.last_update = current_time

            text = self.extender.filterField.getText().strip()
            if not text:
                self.extender.sorter.setRowFilter(None)
                return

            self.extender.sorter.setRowFilter(regexFilter("(?i)" + re.escape(text)))
        except Exception as e:
            self.extender.sorter.setRowFilter(None)
            self.extender._callbacks.issueAlert(UI_TEXT['filter_error'] + str(e))
