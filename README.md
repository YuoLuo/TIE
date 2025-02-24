# Target Information Extractor (TIE)

Target Information Extractor (TIE) 是一个 Burp Suite 插件，用于自动提取和管理渗透测试过程中的目标信息。

## 功能特点

- 自动从 HTTP 流量中提取 IP 地址和域名
- 支持多种流量来源的选择性监听：
  - 代理流量
  - 扩展流量
  - 重放流量
  - 扫描流量
- 实时过滤和搜索功能
- 支持数据导出和复制
- 右键菜单支持选中项的复制和删除
- 自动过滤内部IP地址
- 智能域名后缀验证
- 自动数据清理机制，防止内存溢出

## 安装方法

1. 下载 `TIE.py` 文件
2. 打开 Burp Suite
3. 转到 `Extender` 标签页
4. 点击 `Add` 按钮
5. 在 `Extension File` 选项中选择下载的 `TIE.py` 文件
6. 点击 `Next` 完成安装

## 使用说明

1. 启用插件：
   - 在插件标签页中勾选 "启用插件" 复选框

2. 配置流量源：
   - 选择需要监听的流量来源（代理/扩展/重放/扫描）

3. 数据管理：
   - 使用过滤框实时搜索数据
   - 点击表头可以排序
   - 使用底部按钮进行批量操作
   - 右键菜单支持选中项的操作

4. 数据导出：
   - 点击 "导出到文件" 按钮将数据保存到本地
   - 使用复制按钮将数据复制到剪贴板

## 性能优化

- 最大条目限制：10,000条
- 自动清理机制：当数据量超过80%时触发
- 定期清理：每5分钟检查一次数据量

## 注意事项

- 插件默认处于禁用状态，使用前需要手动启用
- 建议定期导出数据并清理记录，以保持最佳性能
- 内部IP地址会被自动过滤，不会显示在结果中

## 贡献

欢迎提交 Issue 和 Pull Request 来帮助改进这个项目。

## 致谢

- 感谢 PortSwigger 提供的 Burp Suite 扩展开发框架
- 感谢所有为这个项目提供反馈和建议的用户
- 特别感谢以下开源项目的启发：
    - [BurpSuite](https://portswigger.net/burp)
    - [Jython](https://www.jython.org/)
- 本项目基于[地图大师returnwrong](https://space.bilibili.com/41150425?spm_id_from=333.337.0.0)的TIE插件进行二次开发和改进
- 感谢原作者提供的基础代码框架


## 版权说明

本项目是基于[地图大师returnwrong](https://space.bilibili.com/41150425?spm_id_from=333.337.0.0)的TIE插件进行的二次开发。在原有功能基础上，增加了以下改进：
- 修改了布局
- 优化了部分性能
- 将默认语言修改为中文
- 增加导出功能
