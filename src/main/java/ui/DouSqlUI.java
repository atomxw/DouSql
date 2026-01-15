package ui;

import burp.*;
import config.DouSqlConfig;
import utils.LogEntry;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;

/**
 * DouSQL UI界面类
 * 参照RVScan的Tags.java实现，使用Legacy API解决render问题
 */
public class DouSqlUI implements ITab, IMessageEditorController {
    
    private final BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    
    // UI组件
    private JSplitPane mainSplitPane;
    private JTabbedPane mainTabs;
    
    // 表格相关
    public JTable scanResultsTable;
    public JTable payloadDetailsTable;
    public ScanResultsTableModel scanResultsModel;
    public PayloadDetailsTableModel payloadDetailsModel;
    
    // HTTP编辑器 - 使用Legacy API
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;
    private IHttpRequestResponse currentDisplayedItem;
    
    // 数据存储
    public final List<LogEntry> scanResults = Collections.synchronizedList(new ArrayList<>());
    public final List<LogEntry> payloadDetails = Collections.synchronizedList(new ArrayList<>());
    
    // 当前选中的扫描结果MD5，用于过滤payload详情显示
    private String currentSelectedScanMd5 = null;
    
    // 控制面板组件
    private JCheckBox enablePluginCheckBox;
    private JCheckBox monitorRepeaterCheckBox;
    private JCheckBox monitorProxyCheckBox;
    private JCheckBox testCookieCheckBox;
    private JCheckBox processNumbersCheckBox;
    
    private JTextField whitelistTextField;
    private JButton whitelistButton;
    private JButton clearListButton;
    private JButton loadPayloadButton;
    
    // 配置面板
    private JTabbedPane configTabs;
    
    public DouSqlUI(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.callbacks;
        
        //callbacks.printOutput("DouSqlUI构造函数开始...");
        
        // 直接在当前线程中初始化UI，而不是异步
        initializeUI();
        
        //callbacks.printOutput("DouSqlUI构造函数完成");
    }
    
    /**
     * 初始化UI - 按照原始三层布局结构
     */
    private void initializeUI() {
        try {
            //callbacks.printOutput("开始初始化UI组件...");
            
            // 创建主分割面板 - 第一层：左右分割（内容区域 + 控制面板）
            mainSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
            //callbacks.printOutput("主分割面板创建完成");
            
            // 创建表格区域 - 左右分割（扫描结果表格 + Payload详情表格）
            JSplitPane tablesSplitPane = createTablesPanel();
            //callbacks.printOutput("表格区域创建完成");
            
            // 创建HTTP编辑器面板
            JSplitPane httpEditorsSplitPane = createHttpEditorsPanel();
            //callbacks.printOutput("HTTP编辑器创建完成");
            
            // 第二层：splitPanes - 左侧内容区域的上下分割（表格区域 + HTTP编辑器）
            JSplitPane splitPanes = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            splitPanes.setTopComponent(tablesSplitPane);
            splitPanes.setBottomComponent(httpEditorsSplitPane);
            splitPanes.setDividerLocation(400);
            splitPanes.setResizeWeight(0.6);
            //callbacks.printOutput("左侧内容区域分割面板创建完成");
            
            // 创建控制面板
            JPanel controlPanel = createControlPanel();
            //callbacks.printOutput("控制面板创建完成");
            
            // 创建配置标签页
            JTabbedPane configTabs = createConfigTabs();
            //callbacks.printOutput("配置标签页创建完成");
            
            // 第三层：splitPanes2 - 右侧面板的上下分割（控制面板 + 配置标签页）
            JSplitPane splitPanes2 = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
            splitPanes2.setTopComponent(controlPanel);
            splitPanes2.setBottomComponent(configTabs);
            splitPanes2.setDividerLocation(280);
            splitPanes2.setResizeWeight(0.0);
            //callbacks.printOutput("右侧面板分割面板创建完成");
            
            // 第一层：主分割面板 - 左右分割（主内容区域 + 右侧面板）
            mainSplitPane.setLeftComponent(splitPanes);
            mainSplitPane.setRightComponent(splitPanes2);
            mainSplitPane.setDividerLocation(1000);
            mainSplitPane.setResizeWeight(0.75);
            //callbacks.printOutput("主分割面板配置完成");
            
            // 应用主题
            callbacks.customizeUiComponent(mainSplitPane);
            callbacks.customizeUiComponent(splitPanes);
            callbacks.customizeUiComponent(splitPanes2);
            callbacks.customizeUiComponent(tablesSplitPane);
            callbacks.customizeUiComponent(httpEditorsSplitPane);
            //callbacks.printOutput("主题应用完成");
            
            //callbacks.printOutput("DouSQL UI组件初始化完成 - 使用原始三层布局结构");
            
        } catch (Exception e) {
            callbacks.printError("UI初始化失败: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     * 创建左侧面板（表格+HTTP编辑器）
     */
    private Component createLeftPanel() {
        JSplitPane leftSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        
        // 上部：表格区域
        leftSplitPane.setTopComponent(createTablesPanel());
        
        // 下部：HTTP编辑器
        leftSplitPane.setBottomComponent(createHttpEditorsPanel());
        
        leftSplitPane.setDividerLocation(400);
        leftSplitPane.setResizeWeight(0.6);
        
        return leftSplitPane;
    }
    
    /**
     * 创建表格面板 - 按照原始布局结构，添加3.0.6版本的右键菜单功能
     */
    private JSplitPane createTablesPanel() {
        JSplitPane tablesSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 左侧：扫描结果表格
        scanResultsModel = new ScanResultsTableModel();
        scanResultsTable = new ScanResultsTable(scanResultsModel);
        
        // 添加3.0.6版本的右键菜单功能 - 扫描结果表格
        addScanResultsContextMenu(scanResultsTable);
        
        JScrollPane scanResultsScrollPane = new JScrollPane(scanResultsTable);
        
        JPanel scanResultsPanel = new JPanel(new BorderLayout());
        scanResultsPanel.setBorder(BorderFactory.createTitledBorder("扫描结果"));
        scanResultsPanel.add(scanResultsScrollPane, BorderLayout.CENTER);
        
        // 右侧：Payload详情表格
        payloadDetailsModel = new PayloadDetailsTableModel();
        payloadDetailsTable = new PayloadDetailsTable(payloadDetailsModel);
        
        // 添加3.0.6版本的右键菜单功能 - Payload详情表格
        addPayloadDetailsContextMenu(payloadDetailsTable);
        
        JScrollPane payloadDetailsScrollPane = new JScrollPane(payloadDetailsTable);
        
        JPanel payloadDetailsPanel = new JPanel(new BorderLayout());
        payloadDetailsPanel.setBorder(BorderFactory.createTitledBorder("参数测试详情"));
        payloadDetailsPanel.add(payloadDetailsScrollPane, BorderLayout.CENTER);
        
        tablesSplitPane.setLeftComponent(scanResultsPanel);
        tablesSplitPane.setRightComponent(payloadDetailsPanel);
        tablesSplitPane.setDividerLocation(0.5);
        tablesSplitPane.setResizeWeight(0.5);
        
        return tablesSplitPane;
    }
    
    /**
     * 创建HTTP编辑器面板 - 按照原始布局结构使用Legacy API
     */
    private JSplitPane createHttpEditorsPanel() {
        JSplitPane editorsSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        
        // 创建请求编辑器 - 使用Legacy API
        requestEditor = callbacks.createMessageEditor(this, false);
        
        // 创建响应编辑器 - 使用Legacy API
        responseEditor = callbacks.createMessageEditor(this, false);
        
        // 按照原始方式：使用带标题的面板而不是JTabbedPane
        JPanel requestPanel = new JPanel(new BorderLayout());
        requestPanel.setBorder(BorderFactory.createTitledBorder("Request"));
        requestPanel.add(requestEditor.getComponent(), BorderLayout.CENTER);
        
        JPanel responsePanel = new JPanel(new BorderLayout());
        responsePanel.setBorder(BorderFactory.createTitledBorder("Response"));
        responsePanel.add(responseEditor.getComponent(), BorderLayout.CENTER);
        
        editorsSplitPane.setLeftComponent(requestPanel);
        editorsSplitPane.setRightComponent(responsePanel);
        editorsSplitPane.setDividerLocation(0.5);
        editorsSplitPane.setResizeWeight(0.5);
        
        //callbacks.printOutput("HTTP编辑器创建完成 - 使用Legacy API和原始布局");
        
        // 测试HTTP编辑器功能
        testHttpEditors();
        
        return editorsSplitPane;
    }
    
    /**
     * 创建右侧控制面板
     */
    private Component createRightPanel() {
        JSplitPane rightSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        
        // 上部：控制面板
        rightSplitPane.setTopComponent(createControlPanel());
        
        // 下部：配置标签页
        rightSplitPane.setBottomComponent(createConfigTabs());
        
        rightSplitPane.setDividerLocation(280);
        rightSplitPane.setResizeWeight(0.0);
        
        return rightSplitPane;
    }
    
    /**
     * 创建控制面板 - 按照原始布局结构，移除payload加载按钮
     */
    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel(new BorderLayout());
        controlPanel.setBorder(BorderFactory.createTitledBorder("控制面板"));
        
        // 创建控制选项面板 - 使用GridBagLayout确保跨平台兼容性
        JPanel controlOptionsPanel = new JPanel(new GridBagLayout());
        controlOptionsPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        gbc.insets = new Insets(2, 5, 2, 5);
        
        int row = 0;
        
        // 标题
        JLabel titleLabel = new JLabel("DouSQL-安全鸭专属【魔改版本】｜Author By：DarkFi5");
        gbc.gridy = row++;
        controlOptionsPanel.add(titleLabel, gbc);
        
        // 基本控制复选框组
        enablePluginCheckBox = new JCheckBox("启动插件", true);
        gbc.gridy = row++;
        gbc.insets = new Insets(3, 5, 1, 5);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        controlOptionsPanel.add(enablePluginCheckBox, gbc);
        
        monitorRepeaterCheckBox = new JCheckBox("监控Repeater", false);
        gbc.gridy = row++;
        gbc.insets = new Insets(1, 5, 1, 5);
        controlOptionsPanel.add(monitorRepeaterCheckBox, gbc);
        
        monitorProxyCheckBox = new JCheckBox("监控Proxy", false);
        gbc.gridy = row++;
        controlOptionsPanel.add(monitorProxyCheckBox, gbc);
        
        processNumbersCheckBox = new JCheckBox("值是数字则进行-1、-0", true);
        gbc.gridy = row++;
        controlOptionsPanel.add(processNumbersCheckBox, gbc);
        
        testCookieCheckBox = new JCheckBox("测试Cookie", false);
        gbc.gridy = row++;
        controlOptionsPanel.add(testCookieCheckBox, gbc);
        
        // 清空列表按钮
        clearListButton = new JButton("清空列表");
        clearListButton.setPreferredSize(new Dimension(120, 25));
        gbc.gridy = row++;
        gbc.insets = new Insets(8, 5, 3, 5);
        controlOptionsPanel.add(clearListButton, gbc);
        
        // 白名单配置区域
        JLabel whitelistLabel = new JLabel("如果需要多个域名加白请用,隔开");
        gbc.gridy = row++;
        gbc.insets = new Insets(5, 5, 2, 5);
        controlOptionsPanel.add(whitelistLabel, gbc);
        
        whitelistTextField = new JTextField("填写白名单域名");
        whitelistTextField.setPreferredSize(new Dimension(220, 25));
        whitelistTextField.setMinimumSize(new Dimension(180, 25));
        whitelistTextField.setMaximumSize(new Dimension(300, 25));
        whitelistTextField.setBorder(BorderFactory.createLoweredBevelBorder());
        gbc.gridy = row++;
        gbc.insets = new Insets(2, 5, 2, 5);
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;
        controlOptionsPanel.add(whitelistTextField, gbc);
        
        whitelistButton = new JButton("启动白名单");
        whitelistButton.setPreferredSize(new Dimension(120, 25));
        gbc.gridy = row++;
        gbc.insets = new Insets(2, 5, 3, 5);
        gbc.fill = GridBagConstraints.NONE;
        gbc.weightx = 0.0;
        controlOptionsPanel.add(whitelistButton, gbc);
        
        // 添加弹性空间，但减少权重避免过多空白
        gbc.gridy = row++;
        gbc.weighty = 0.1;
        gbc.fill = GridBagConstraints.VERTICAL;
        gbc.insets = new Insets(0, 0, 0, 0);
        controlOptionsPanel.add(Box.createVerticalStrut(10), gbc);
        
        controlPanel.add(controlOptionsPanel, BorderLayout.CENTER);
        
        // 设置事件监听器
        setupControlPanelListeners();
        
        return controlPanel;
    }
    
    /**
     * 创建配置标签页 - 恢复完整功能，添加延时发包独立tab
     */
    private JTabbedPane createConfigTabs() {
        configTabs = new JTabbedPane();
        configTabs.setPreferredSize(new Dimension(250, 400));
        configTabs.setMinimumSize(new Dimension(200, 300));
        
        // 创建各个配置面板
        configTabs.addTab("自定义SQL语句", createCustomSqlPanel());
        configTabs.addTab("参数过滤配置", createParamFilterPanel());
        configTabs.addTab("自定义报错信息", createCustomErrorPanel());
        configTabs.addTab("时间阈值配置", createResponseTimePanel());
        configTabs.addTab("长度差异配置", createLengthDiffPanel());
        configTabs.addTab("黑名单URL过滤", createUrlBlacklistPanel());
        configTabs.addTab("延时发包配置", createDelayConfigPanel());
        configTabs.addTab("追加参数配置", createAppendParamsPanel());
        configTabs.addTab("高级配置", createAdvancedConfigPanel());
        
        return configTabs;
    }
    
    /**
     * 创建自定义SQL语句面板 - 按照原始布局，包含payload组管理和加载按钮
     */
    private Component createCustomSqlPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // 顶部控制面板 - 包含组管理和选项
        JPanel topControlPanel = new JPanel();
        topControlPanel.setLayout(new BoxLayout(topControlPanel, BoxLayout.Y_AXIS));
        topControlPanel.setBorder(BorderFactory.createEmptyBorder(5, 5, 5, 5));
        
        // 配置文件路径说明
        String configPath = burpExtender.config.getConfigDirectory() + "/xia_SQL_diy_payload.ini";
        JLabel configLabel = new JLabel("修改payload后点击保存，切换组时点击重新加载（配置文件：" + configPath + "）");
        configLabel.setAlignmentX(Component.LEFT_ALIGNMENT);
        topControlPanel.add(configLabel);
        topControlPanel.add(Box.createVerticalStrut(5));
        
        // Payload组管理区域
        JPanel groupPanel = new JPanel(new GridBagLayout());
        GridBagConstraints gbcGroup = new GridBagConstraints();
        gbcGroup.insets = new Insets(2, 2, 2, 2);
        gbcGroup.anchor = GridBagConstraints.WEST;
        
        JLabel groupLabel = new JLabel("测试组:");
        JComboBox<String> groupComboBox = new JComboBox<>();
        // 加载payload组
        for (String group : burpExtender.payloadUtils.getPayloadGroups()) {
            groupComboBox.addItem(group);
        }
        groupComboBox.setPreferredSize(new Dimension(80, 25));
        
        JTextField newGroupNameField = new JTextField("新组名");
        newGroupNameField.setPreferredSize(new Dimension(80, 25));
        
        JButton newGroupButton = new JButton("新建");
        JButton renameGroupButton = new JButton("重命名");
        JButton deleteGroupButton = new JButton("删除");
        
        // 设置按钮大小
        Dimension buttonSize = new Dimension(60, 25);
        newGroupButton.setPreferredSize(buttonSize);
        renameGroupButton.setPreferredSize(new Dimension(70, 25));
        deleteGroupButton.setPreferredSize(buttonSize);
        
        // 第一行：标签和下拉框
        gbcGroup.gridx = 0; gbcGroup.gridy = 0;
        groupPanel.add(groupLabel, gbcGroup);
        gbcGroup.gridx = 1;
        groupPanel.add(groupComboBox, gbcGroup);
        gbcGroup.gridx = 2;
        groupPanel.add(newGroupNameField, gbcGroup);
        
        // 第二行：按钮组
        gbcGroup.gridx = 0; gbcGroup.gridy = 1;
        groupPanel.add(newGroupButton, gbcGroup);
        gbcGroup.gridx = 1;
        groupPanel.add(renameGroupButton, gbcGroup);
        gbcGroup.gridx = 2;
        groupPanel.add(deleteGroupButton, gbcGroup);
        
        groupPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        topControlPanel.add(groupPanel);
        topControlPanel.add(Box.createVerticalStrut(5));
        
        // 自定义payload选项
        JCheckBox customPayloadCheckBox = new JCheckBox("自定义payload");
        JCheckBox urlEncodeCheckBox = new JCheckBox("空格url编码", true);
        JCheckBox emptyValueCheckBox = new JCheckBox("参数值置空");
        
        customPayloadCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        urlEncodeCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        emptyValueCheckBox.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        topControlPanel.add(customPayloadCheckBox);
        topControlPanel.add(urlEncodeCheckBox);
        topControlPanel.add(emptyValueCheckBox);
        topControlPanel.add(Box.createVerticalStrut(5));
        
        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        JButton savePayloadButton = new JButton("保存payload");
        JButton loadPayloadButton = new JButton("重新加载payload");
        JButton resetPayloadButton = new JButton("重置为默认");
        
        savePayloadButton.setPreferredSize(new Dimension(120, 25));
        loadPayloadButton.setPreferredSize(new Dimension(140, 25));
        resetPayloadButton.setPreferredSize(new Dimension(120, 25));
        
        buttonPanel.add(savePayloadButton);
        buttonPanel.add(loadPayloadButton);
        buttonPanel.add(resetPayloadButton);
        buttonPanel.setAlignmentX(Component.LEFT_ALIGNMENT);
        
        topControlPanel.add(buttonPanel);
        
        // Payload编辑区域
        JTextArea payloadArea = new JTextArea(15, 50);
        payloadArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        payloadArea.setForeground(Color.BLACK);
        payloadArea.setBackground(Color.LIGHT_GRAY);
        
        // 加载当前组的payload
        StringBuilder sb = new StringBuilder();
        for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
            sb.append(payload).append("\n");
        }
        payloadArea.setText(sb.toString());
        
        JScrollPane scrollPane = new JScrollPane(payloadArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("Payload列表（每行一个）"));
        
        // 事件监听器
        // 新建组按钮
        newGroupButton.addActionListener(e -> {
            String newGroupName = newGroupNameField.getText().trim();
            if (newGroupName.isEmpty() || newGroupName.equals("新组名")) {
                JOptionPane.showMessageDialog(panel, "请输入有效的组名", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if (burpExtender.payloadUtils.addPayloadGroup(newGroupName)) {
                // 更新下拉框
                groupComboBox.addItem(newGroupName);
                groupComboBox.setSelectedItem(newGroupName);
                
                // 切换到新组
                burpExtender.payloadUtils.switchToGroup(newGroupName);
                
                // 清空payload区域（新组默认为空）
                payloadArea.setText("");
                
                // 清空输入框
                newGroupNameField.setText("新组名");
                
                JOptionPane.showMessageDialog(panel, "成功创建新组: " + newGroupName, "成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(panel, "创建组失败，可能组名已存在", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // 重命名组按钮
        renameGroupButton.addActionListener(e -> {
            String currentGroup = (String) groupComboBox.getSelectedItem();
            String newGroupName = newGroupNameField.getText().trim();
            
            if (currentGroup == null) {
                JOptionPane.showMessageDialog(panel, "请选择要重命名的组", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if (newGroupName.isEmpty() || newGroupName.equals("新组名")) {
                JOptionPane.showMessageDialog(panel, "请输入有效的新组名", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if (burpExtender.payloadUtils.renamePayloadGroup(currentGroup, newGroupName)) {
                // 更新下拉框
                groupComboBox.removeItem(currentGroup);
                groupComboBox.addItem(newGroupName);
                groupComboBox.setSelectedItem(newGroupName);
                
                // 清空输入框
                newGroupNameField.setText("新组名");
                
                JOptionPane.showMessageDialog(panel, "成功重命名组: " + currentGroup + " -> " + newGroupName, "成功", JOptionPane.INFORMATION_MESSAGE);
            } else {
                JOptionPane.showMessageDialog(panel, "重命名失败", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // 删除组按钮
        deleteGroupButton.addActionListener(e -> {
            String currentGroup = (String) groupComboBox.getSelectedItem();
            
            if (currentGroup == null) {
                JOptionPane.showMessageDialog(panel, "请选择要删除的组", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            if ("default".equals(currentGroup)) {
                JOptionPane.showMessageDialog(panel, "不能删除默认组", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            int result = JOptionPane.showConfirmDialog(panel, 
                "确定要删除组 '" + currentGroup + "' 吗？\n删除后该组的所有payload将丢失。", 
                "确认删除", 
                JOptionPane.YES_NO_OPTION, 
                JOptionPane.WARNING_MESSAGE);
            
            if (result == JOptionPane.YES_OPTION) {
                if (burpExtender.payloadUtils.deletePayloadGroup(currentGroup)) {
                    // 从下拉框中移除
                    groupComboBox.removeItem(currentGroup);
                    
                    // 切换到默认组
                    groupComboBox.setSelectedItem("default");
                    burpExtender.payloadUtils.switchToGroup("default");
                    
                    // 重新加载payload显示
                    StringBuilder newSb = new StringBuilder();
                    for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
                        newSb.append(payload).append("\n");
                    }
                    payloadArea.setText(newSb.toString());
                    
                    JOptionPane.showMessageDialog(panel, "成功删除组: " + currentGroup, "成功", JOptionPane.INFORMATION_MESSAGE);
                } else {
                    JOptionPane.showMessageDialog(panel, "删除失败", "错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        
        // 组切换事件监听器
        groupComboBox.addActionListener(e -> {
            String selectedGroup = (String) groupComboBox.getSelectedItem();
            if (selectedGroup != null && !selectedGroup.equals(burpExtender.payloadUtils.getCurrentGroup())) {
                callbacks.printOutput("正在切换到payload组: " + selectedGroup);
                burpExtender.payloadUtils.switchToGroup(selectedGroup);
                
                // 重新加载payload显示
                StringBuilder newSb = new StringBuilder();
                List<String> currentPayloads = burpExtender.payloadUtils.getCurrentPayloads();
                callbacks.printOutput("当前组 '" + selectedGroup + "' 有 " + currentPayloads.size() + " 个payload");
                
                for (String payload : currentPayloads) {
                    newSb.append(payload).append("\n");
                }
                payloadArea.setText(newSb.toString());
                callbacks.printOutput("已切换到payload组: " + selectedGroup + "，payload列表已更新");
            }
        });
        
        customPayloadCheckBox.addItemListener(e -> {
            boolean enabled = customPayloadCheckBox.isSelected();
            burpExtender.customPayloadEnabled = enabled;
            payloadArea.setEditable(enabled);
            if (enabled) {
                payloadArea.setBackground(Color.WHITE);
            } else {
                payloadArea.setBackground(Color.LIGHT_GRAY);
            }
        });
        
        urlEncodeCheckBox.addItemListener(e -> {
            burpExtender.urlEncodeSpaces = urlEncodeCheckBox.isSelected();
            callbacks.printOutput("空格URL编码: " + (burpExtender.urlEncodeSpaces ? "启用" : "禁用"));
        });
        
        emptyValueCheckBox.addItemListener(e -> {
            burpExtender.emptyParameterValues = emptyValueCheckBox.isSelected();
            callbacks.printOutput("参数值置空: " + (burpExtender.emptyParameterValues ? "启用" : "禁用"));
        });
        
        loadPayloadButton.addActionListener(e -> {
            String currentGroup = (String) groupComboBox.getSelectedItem();
            if (currentGroup != null) {
                burpExtender.payloadUtils.switchToGroup(currentGroup);
            }
            burpExtender.payloadUtils.reloadPayloads();
            // 重新加载payload显示
            StringBuilder newSb = new StringBuilder();
            for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
                newSb.append(payload).append("\n");
            }
            payloadArea.setText(newSb.toString());
            JOptionPane.showMessageDialog(panel, "Payload已重新加载", "成功", JOptionPane.INFORMATION_MESSAGE);
        });
        
        savePayloadButton.addActionListener(e -> {
            if (!customPayloadCheckBox.isSelected()) {
                JOptionPane.showMessageDialog(panel, "请先勾选'自定义payload'以启用编辑功能", "提示", JOptionPane.WARNING_MESSAGE);
                return;
            }
            
            String payloadContent = payloadArea.getText();
            if (payloadContent.trim().isEmpty()) {
                JOptionPane.showMessageDialog(panel, "Payload内容不能为空", "错误", JOptionPane.ERROR_MESSAGE);
                return;
            }
            
            try {
                burpExtender.payloadUtils.saveCurrentGroupPayloads(payloadContent);
                JOptionPane.showMessageDialog(panel, "Payload保存成功", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        resetPayloadButton.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(panel, 
                "确定要重置当前组的payload为默认值吗？\n当前的自定义payload将丢失。", 
                "确认重置", 
                JOptionPane.YES_NO_OPTION, 
                JOptionPane.WARNING_MESSAGE);
            
            if (result == JOptionPane.YES_OPTION) {
                burpExtender.payloadUtils.resetCurrentGroupToDefault();
                
                // 重新加载payload显示
                StringBuilder newSb = new StringBuilder();
                for (String payload : burpExtender.payloadUtils.getCurrentPayloads()) {
                    newSb.append(payload).append("\n");
                }
                payloadArea.setText(newSb.toString());
                
                JOptionPane.showMessageDialog(panel, "已重置为默认payload", "成功", JOptionPane.INFORMATION_MESSAGE);
            }
        });
        
        panel.add(topControlPanel, BorderLayout.NORTH);
        panel.add(scrollPane, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建自定义报错信息面板 - 添加启用复选框和配置文件路径
     */
    private Component createCustomErrorPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 顶部：启用复选框和配置文件路径
        String configPath = burpExtender.config.getConfigDirectory() + "/xia_SQL_diy_error.ini";
        JCheckBox enableCustomErrorCheckBox = new JCheckBox("启用自定义报错信息（配置文件：" + configPath + "）", true);
        enableCustomErrorCheckBox.setPreferredSize(new Dimension(400, 25));
        
        JPanel enablePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enablePanel.add(enableCustomErrorCheckBox);
        
        // 中间：编辑区域
        JPanel errorTextPanel = new JPanel(new BorderLayout());
        errorTextPanel.setBorder(BorderFactory.createEmptyBorder(5, 0, 0, 0));
        
        JLabel errorLabel = new JLabel("报错关键字配置 (每行一个关键字或正则表达式)");
        errorLabel.setBorder(BorderFactory.createEmptyBorder(0, 0, 5, 0));
        
        JTextArea errorKeywordsTextArea = new JTextArea(15, 50);
        errorKeywordsTextArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        errorKeywordsTextArea.setForeground(Color.BLACK);
        errorKeywordsTextArea.setBackground(Color.WHITE);
        errorKeywordsTextArea.setEditable(true);
        
        // 加载当前错误关键字
        StringBuilder sb = new StringBuilder();
        for (String keyword : burpExtender.config.getErrorKeywords()) {
            sb.append(keyword).append("\n");
        }
        errorKeywordsTextArea.setText(sb.toString());
        
        JScrollPane errorScrollPane = new JScrollPane(errorKeywordsTextArea);
        
        // 底部：保存按钮
        JButton saveErrorBtn = new JButton("保存报错信息配置");
        saveErrorBtn.setPreferredSize(new Dimension(150, 30));
        
        JPanel errorButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 5));
        errorButtonPanel.add(saveErrorBtn);
        
        errorTextPanel.add(errorLabel, BorderLayout.NORTH);
        errorTextPanel.add(errorScrollPane, BorderLayout.CENTER);
        errorTextPanel.add(errorButtonPanel, BorderLayout.SOUTH);
        
        // 事件监听器
        enableCustomErrorCheckBox.addItemListener(e -> {
            boolean enabled = enableCustomErrorCheckBox.isSelected();
            errorKeywordsTextArea.setEditable(enabled);
            saveErrorBtn.setEnabled(enabled);
            if (enabled) {
                errorKeywordsTextArea.setBackground(Color.WHITE);
            } else {
                errorKeywordsTextArea.setBackground(Color.LIGHT_GRAY);
            }
        });
        
        saveErrorBtn.addActionListener(e -> {
            try {
                String errorText = errorKeywordsTextArea.getText().trim();
                List<String> keywords = new ArrayList<>();
                
                if (!errorText.isEmpty()) {
                    String[] lines = errorText.split("\n");
                    for (String line : lines) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            keywords.add(line);
                        }
                    }
                }
                
                burpExtender.config.saveErrorKeywords(keywords);
                
                JOptionPane.showMessageDialog(panel, 
                    "报错信息配置保存成功！\n" +
                    "关键字数量: " + keywords.size() + "条", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
                    
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        panel.add(enablePanel, BorderLayout.NORTH);
        panel.add(errorTextPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建时间阈值配置面板（包含响应时间阈值和请求超时时间）
     */
    private Component createResponseTimePanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        int row = 0;
        
        // 响应时间阈值
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("响应时间阈值(毫秒):"), gbc);
        
        JTextField responseTimeField = new JTextField(String.valueOf(burpExtender.config.getResponseTimeThreshold()));
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(responseTimeField, gbc);
        
        // 请求超时时间
        gbc.gridx = 0; gbc.gridy = row;
        gbc.weightx = 0.0;
        panel.add(new JLabel("请求超时时间(毫秒):"), gbc);
        
        JTextField requestTimeoutField = new JTextField(String.valueOf(burpExtender.config.getRequestTimeout()));
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(requestTimeoutField, gbc);
        
        // 说明文本
        JTextArea descArea = new JTextArea(
            "说明：\n\n" +
            "【响应时间阈值】\n" +
            "• 用途：检测时间盲注，当响应时间超过此阈值时标记为TIME\n" +
            "• 默认：2000毫秒(2秒)\n" +
            "• 建议：根据目标服务器性能调整，一般设置为2000-5000毫秒\n" +
            "• 注意：设置过小可能产生误报，设置过大可能遗漏漏洞\n\n" +
            "【请求超时时间】\n" +
            "• 用途：请求超时控制，超过此时间直接丢弃请求\n" +
            "• 默认：30000毫秒(30秒)\n" +
            "• 建议：内网环境10-15秒，外网环境30-60秒\n" +
            "• 注意：超时的请求会被标记为timeout>xx秒\n\n" +
            "【配置建议】\n" +
            "• 请求超时时间应该大于响应时间阈值（建议5倍以上）\n" +
            "• 快速扫描：响应时间1秒，超时5秒\n" +
            "• 慢速目标：响应时间5秒，超时60秒"
        );
        descArea.setEditable(false);
        descArea.setBackground(panel.getBackground());
        descArea.setBorder(BorderFactory.createTitledBorder("使用说明"));
        descArea.setLineWrap(true);
        descArea.setWrapStyleWord(true);
        
        gbc.gridx = 0; gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(descArea, gbc);
        
        // 保存按钮
        JButton saveButton = new JButton("保存时间阈值配置");
        saveButton.addActionListener(e -> {
            try {
                int responseTime = Integer.parseInt(responseTimeField.getText().trim());
                int timeout = Integer.parseInt(requestTimeoutField.getText().trim());
                
                // 验证输入
                if (responseTime < 100) {
                    JOptionPane.showMessageDialog(panel, "响应时间阈值不能小于100毫秒", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (timeout < 1000) {
                    JOptionPane.showMessageDialog(panel, "请求超时时间不能小于1000毫秒", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                if (timeout <= responseTime) {
                    JOptionPane.showMessageDialog(panel, 
                        "请求超时时间应该大于响应时间阈值\n建议超时时间至少是响应时间阈值的5倍", 
                        "警告", JOptionPane.WARNING_MESSAGE);
                    // 不return，允许保存但给出警告
                }
                
                // 保存配置
                burpExtender.config.saveTimeThresholdConfig(responseTime, timeout);
                
                JOptionPane.showMessageDialog(panel, 
                    "时间阈值配置保存成功！\n" +
                    "响应时间阈值: " + responseTime + "毫秒 (" + (responseTime/1000.0) + "秒)\n" +
                    "请求超时时间: " + timeout + "毫秒 (" + (timeout/1000.0) + "秒)", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(panel, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        gbc.gridy = row++;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(saveButton, gbc);
        
        return new JScrollPane(panel);
    }
    
    /**
     * 创建长度差异配置面板
     */
    private Component createLengthDiffPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        int row = 0;
        
        // 长度差异阈值
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("长度差异阈值(字节):"), gbc);
        
        JTextField lengthDiffField = new JTextField(String.valueOf(burpExtender.config.getLengthDiffThreshold()));
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(lengthDiffField, gbc);
        
        // 说明文本
        JTextArea descArea = new JTextArea(
            "说明：\n" +
            "1. 当payload响应长度与原始响应长度差异超过此阈值时，标记为可能的布尔盲注\n" +
            "2. 建议根据目标页面大小调整\n" +
            "3. 设置过小可能产生误报，设置过大可能遗漏漏洞\n" +
            "4. 对于动态内容较多的页面，可以适当增大阈值\n" +
            "5. 结合多个payload的响应长度变化进行综合判断"
        );
        descArea.setEditable(false);
        descArea.setBackground(panel.getBackground());
        descArea.setBorder(BorderFactory.createTitledBorder("使用说明"));
        
        gbc.gridx = 0; gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;
        gbc.weighty = 1.0;
        gbc.fill = GridBagConstraints.BOTH;
        panel.add(descArea, gbc);
        
        // 保存按钮
        JButton saveButton = new JButton("保存长度差异配置");
        saveButton.addActionListener(e -> {
            try {
                int lengthDiff = Integer.parseInt(lengthDiffField.getText().trim());
                if (lengthDiff < 0) {
                    JOptionPane.showMessageDialog(panel, "长度差异阈值不能小于0", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                burpExtender.config.setLengthDiffThreshold(lengthDiff);
                burpExtender.config.saveLengthDiffThreshold(lengthDiff);
                JOptionPane.showMessageDialog(panel, "长度差异配置保存成功", "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(panel, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        gbc.gridy = row++;
        gbc.weighty = 0.0;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        panel.add(saveButton, gbc);
        
        return new JScrollPane(panel);
    }
    
    /**
     * 创建参数过滤面板 - 竖向布局，不使用左右分割
     */
    private Component createParamFilterPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 过滤模式选择 - 竖向排列
        JPanel modePanel = new JPanel(new GridLayout(3, 1, 5, 5));
        modePanel.setBorder(BorderFactory.createTitledBorder("过滤模式"));
        
        ButtonGroup modeGroup = new ButtonGroup();
        JRadioButton noFilterRadio = new JRadioButton("无过滤 (所有参数测试)", burpExtender.config.getParamFilterMode() == 0);
        JRadioButton whitelistRadio = new JRadioButton("白名单模式 (只测试配置参数)", burpExtender.config.getParamFilterMode() == 1);
        JRadioButton blacklistRadio = new JRadioButton("黑名单模式 (跳过配置参数)", burpExtender.config.getParamFilterMode() == 2);
        
        modeGroup.add(noFilterRadio);
        modeGroup.add(whitelistRadio);
        modeGroup.add(blacklistRadio);
        
        modePanel.add(noFilterRadio);
        modePanel.add(whitelistRadio);
        modePanel.add(blacklistRadio);
        
        // 参数配置编辑区
        JPanel paramAreaPanel = new JPanel(new BorderLayout());
        JLabel paramListLabel = new JLabel("参数列表 (每行一个参数名)");
        paramListLabel.setBorder(BorderFactory.createEmptyBorder(5, 0, 5, 0));
        
        JTextArea paramListTextArea = new JTextArea(15, 30);
        paramListTextArea.setForeground(Color.BLACK);
        paramListTextArea.setFont(new Font("宋体", Font.PLAIN, 13));
        paramListTextArea.setBackground(Color.WHITE);
        paramListTextArea.setEditable(true);
        
        // 根据当前模式加载对应的参数列表
        StringBuilder sb = new StringBuilder();
        if (burpExtender.config.getParamFilterMode() == 1) {
            // 白名单模式
            for (String param : burpExtender.config.getWhitelistParams()) {
                sb.append(param).append("\n");
            }
        } else if (burpExtender.config.getParamFilterMode() == 2) {
            // 黑名单模式
            for (String param : burpExtender.config.getBlacklistParams()) {
                sb.append(param).append("\n");
            }
        }
        paramListTextArea.setText(sb.toString());
        
        JScrollPane paramListScrollPane = new JScrollPane(paramListTextArea);
        
        // 按钮区
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER, 10, 10));
        JButton saveParamListBtn = new JButton("保存参数配置");
        buttonPanel.add(saveParamListBtn);
        
        paramAreaPanel.add(paramListLabel, BorderLayout.NORTH);
        paramAreaPanel.add(paramListScrollPane, BorderLayout.CENTER);
        paramAreaPanel.add(buttonPanel, BorderLayout.SOUTH);
        
        // 模式切换事件监听器
        noFilterRadio.addActionListener(e -> {
            paramListTextArea.setText("");
            paramListTextArea.setEditable(false);
            paramListTextArea.setBackground(Color.LIGHT_GRAY);
        });
        
        whitelistRadio.addActionListener(e -> {
            StringBuilder whiteSb = new StringBuilder();
            for (String param : burpExtender.config.getWhitelistParams()) {
                whiteSb.append(param).append("\n");
            }
            paramListTextArea.setText(whiteSb.toString());
            paramListTextArea.setEditable(true);
            paramListTextArea.setBackground(Color.WHITE);
        });
        
        blacklistRadio.addActionListener(e -> {
            StringBuilder blackSb = new StringBuilder();
            for (String param : burpExtender.config.getBlacklistParams()) {
                blackSb.append(param).append("\n");
            }
            paramListTextArea.setText(blackSb.toString());
            paramListTextArea.setEditable(true);
            paramListTextArea.setBackground(Color.WHITE);
        });
        
        // 保存按钮事件监听器
        saveParamListBtn.addActionListener(e -> {
            // 获取选中的模式
            int mode = 0;
            if (whitelistRadio.isSelected()) mode = 1;
            else if (blacklistRadio.isSelected()) mode = 2;
            
            // 解析参数列表
            String paramText = paramListTextArea.getText().trim();
            List<String> paramList = new ArrayList<>();
            if (!paramText.isEmpty()) {
                String[] lines = paramText.split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        paramList.add(line);
                    }
                }
            }
            
            // 根据模式保存到对应的列表，保留另一个列表的现有配置
            List<String> whitelistParams = new ArrayList<>(burpExtender.config.getWhitelistParams());
            List<String> blacklistParams = new ArrayList<>(burpExtender.config.getBlacklistParams());
            
            if (mode == 1) {
                // 保存白名单，保留黑名单
                whitelistParams.clear();
                whitelistParams.addAll(paramList);
            } else if (mode == 2) {
                // 保存黑名单，保留白名单
                blacklistParams.clear();
                blacklistParams.addAll(paramList);
            }
            
            // 保存配置
            try {
                burpExtender.config.saveParamFilterConfig(mode, whitelistParams, blacklistParams);
                
                String modeText = mode == 0 ? "无过滤" : (mode == 1 ? "白名单" : "黑名单");
                JOptionPane.showMessageDialog(panel, 
                    "参数过滤配置保存成功！\n" +
                    "过滤模式: " + modeText + "\n" +
                    "当前编辑参数数量: " + paramList.size() + "个\n" +
                    "白名单参数: " + whitelistParams.size() + "个\n" +
                    "黑名单参数: " + blacklistParams.size() + "个", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, 
                    "保存失败: " + ex.getMessage(), 
                    "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // 初始化状态
        if (burpExtender.config.getParamFilterMode() == 0) {
            paramListTextArea.setEditable(false);
            paramListTextArea.setBackground(Color.LIGHT_GRAY);
        }
        
        panel.add(modePanel, BorderLayout.NORTH);
        panel.add(paramAreaPanel, BorderLayout.CENTER);
        
        return panel;
    }
    
    /**
     * 创建黑名单URL过滤面板 - 简化按钮，只保留保存和重置，加载现有配置
     */
    private Component createUrlBlacklistPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        
        // 黑名单URL列表
        JTextArea urlArea = new JTextArea(15, 50);
        urlArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        
        // 加载现有的黑名单配置
        List<String> existingBlacklist = burpExtender.config.getUrlBlacklist();
        StringBuilder initialContent = new StringBuilder();
        initialContent.append("# URL黑名单配置（每行一个，支持通配符）\n");
        initialContent.append("# 示例：\n");
        initialContent.append("# */admin/*\n");
        initialContent.append("# */static/*\n");
        initialContent.append("# *.css\n");
        initialContent.append("# *.js\n");
        initialContent.append("\n");
        
        if (!existingBlacklist.isEmpty()) {
            initialContent.append("# 当前配置的黑名单规则：\n");
            for (String rule : existingBlacklist) {
                initialContent.append(rule).append("\n");
            }
        } else {
            initialContent.append("# 当前没有配置黑名单规则\n");
            initialContent.append("# 请在下方添加需要过滤的URL模式\n");
        }
        
        urlArea.setText(initialContent.toString());
        
        JScrollPane scrollPane = new JScrollPane(urlArea);
        scrollPane.setBorder(BorderFactory.createTitledBorder("黑名单URL列表（支持通配符 * 和 ?）"));
        
        // 按钮面板 - 只保留保存和重置按钮
        JPanel buttonPanel = new JPanel(new FlowLayout());
        
        JButton saveButton = new JButton("保存黑名单配置");
        saveButton.addActionListener(e -> {
            try {
                String urlText = urlArea.getText().trim();
                List<String> blacklist = new ArrayList<>();
                
                if (!urlText.isEmpty()) {
                    String[] lines = urlText.split("\n");
                    for (String line : lines) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            blacklist.add(line);
                        }
                    }
                }
                
                burpExtender.config.saveUrlBlacklist(blacklist);
                
                JOptionPane.showMessageDialog(panel, 
                    "URL黑名单配置保存成功！\n" +
                    "黑名单条目: " + blacklist.size() + "条", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
                    
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "保存失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        JButton resetButton = new JButton("重置为默认");
        resetButton.addActionListener(e -> {
            urlArea.setText(
                "# URL黑名单配置（每行一个，支持通配符）\n" +
                "# 示例：\n" +
                "*/admin/*\n" +
                "*/static/*\n" +
                "*/assets/*\n" +
                "*/js/*\n" +
                "*/css/*\n" +
                "*/images/*\n"
            );
        });
        
        buttonPanel.add(saveButton);
        buttonPanel.add(resetButton);
        
        panel.add(scrollPane, BorderLayout.CENTER);
        panel.add(buttonPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建追加参数配置面板 - 改进版本：动态参数映射，启用即保存
     */
    private Component createAppendParamsPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 顶部：启用追加参数复选框
        JCheckBox enableAppendParamsCheckBox = new JCheckBox("启用自定义追加参数（启用即生效）", false);
        JPanel enablePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        enablePanel.add(enableAppendParamsCheckBox);
        
        // 主要配置区域 - 左右分割
        JSplitPane configSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        configSplitPane.setResizeWeight(0.6); // 左边占60%
        
        // 左侧：参数配置面板
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("追加参数配置"));
        
        JLabel paramLabel = new JLabel("参数列表 (格式: key:value，一行一个):");
        leftPanel.add(paramLabel, BorderLayout.NORTH);
        
        JTextArea appendParamsTextArea = new JTextArea(12, 25);
        appendParamsTextArea.setFont(new Font("Monospaced", Font.PLAIN, 12));
        appendParamsTextArea.setBorder(BorderFactory.createLoweredBevelBorder());
        appendParamsTextArea.setText(
            "# 追加参数配置（格式：key:value，每行一个）\n" +
            "# 示例：\n" +
            "# token:abc123\n"
        );
        
        JScrollPane leftScrollPane = new JScrollPane(appendParamsTextArea);
        leftScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        leftScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        leftPanel.add(leftScrollPane, BorderLayout.CENTER);
        
        // 右侧：参数测试开关面板
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(BorderFactory.createTitledBorder("测试开关"));
        
        JLabel testLabel = new JLabel("选择参与payload测试的参数:");
        rightPanel.add(testLabel, BorderLayout.NORTH);
        
        // 动态生成的参数勾选框面板
        JPanel paramTestPanel = new JPanel();
        paramTestPanel.setLayout(new BoxLayout(paramTestPanel, BoxLayout.Y_AXIS));
        
        // 初始提示
        JLabel emptyLabel = new JLabel("<html><i>请在左侧输入参数，右侧会自动生成对应的测试选项</i></html>");
        emptyLabel.setBorder(BorderFactory.createEmptyBorder(10, 5, 5, 5));
        paramTestPanel.add(emptyLabel);
        
        JScrollPane rightScrollPane = new JScrollPane(paramTestPanel);
        rightScrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        rightScrollPane.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_NEVER);
        rightPanel.add(rightScrollPane, BorderLayout.CENTER);
        
        configSplitPane.setLeftComponent(leftPanel);
        configSplitPane.setRightComponent(rightPanel);
        
        // 底部按钮面板 - 只保留清除按钮
        JPanel appendParamsButtonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton clearAppendParamsBtn = new JButton("清除配置并禁用");
        clearAppendParamsBtn.setToolTipText("完全清除追加参数配置并禁用功能");
        appendParamsButtonPanel.add(clearAppendParamsBtn);
        
        // 说明文本
        JTextArea helpText = new JTextArea(
            "说明：\n" +
            "1. 启用后，会在每个请求中自动追加指定的参数\n" +
            "2. 支持URL参数、POST参数、JSON参数等格式\n" +
            "3. 参数格式：每行一个参数，使用 key:value 格式\n" +
            "4. 示例：token:abc123、debug:1、test:value\n" +
            "5. 右侧可单独控制每个参数是否参与payload测试\n" +
            "6. 不参与测试时避免重复检测，参与测试时可发现更多漏洞\n" +
            "7. 参数会根据请求格式自动适配添加方式", 6, 30);
        helpText.setEditable(false);
        helpText.setBackground(panel.getBackground());
        helpText.setFont(new Font("宋体", Font.PLAIN, 12));
        helpText.setBorder(BorderFactory.createTitledBorder("使用说明"));
        
        // 保存配置的方法
        Runnable saveCurrentConfig = () -> {
            if (enableAppendParamsCheckBox.isSelected()) {
                // 解析参数文本
                String paramText = appendParamsTextArea.getText().trim();
                Map<String, String> currentParams = new HashMap<>();
                
                if (!paramText.isEmpty()) {
                    String[] lines = paramText.split("\n");
                    for (String line : lines) {
                        line = line.trim();
                        if (!line.isEmpty() && !line.startsWith("#")) {
                            String[] parts = line.split(":", 2);
                            if (parts.length == 2) {
                                String key = parts[0].trim();
                                String value = parts[1].trim();
                                currentParams.put(key, value);
                            }
                        }
                    }
                }
                
                // 获取当前勾选的测试参数
                Set<String> testableParams = new HashSet<>();
                for (Component comp : paramTestPanel.getComponents()) {
                    if (comp instanceof JCheckBox) {
                        JCheckBox cb = (JCheckBox) comp;
                        if (cb.isSelected()) {
                            String text = cb.getText();
                            String paramName = text.split(" \\(")[0]; // 提取参数名
                            testableParams.add(paramName);
                        }
                    }
                }
                
                // 保存到配置
                burpExtender.config.saveAppendParamsConfig(true, currentParams, testableParams);
                
                // 调试信息
                callbacks.printOutput("=== UI保存追加参数配置 ===");
                callbacks.printOutput("参数数量: " + currentParams.size());
                callbacks.printOutput("可测试参数数量: " + testableParams.size());
                for (String testableParam : testableParams) {
                    callbacks.printOutput("可测试参数: " + testableParam);
                }
                callbacks.printOutput("=== UI保存完成 ===");
            }
        };
        
        // 动态参数映射方法
        Runnable updateParameterCheckboxes = () -> {
            // 清空现有的复选框
            paramTestPanel.removeAll();
            
            // 解析参数文本
            String paramText = appendParamsTextArea.getText().trim();
            Map<String, String> currentParams = new HashMap<>();
            
            if (!paramText.isEmpty()) {
                String[] lines = paramText.split("\n");
                for (String line : lines) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.startsWith("#")) {
                        String[] parts = line.split(":", 2);
                        if (parts.length == 2) {
                            String key = parts[0].trim();
                            String value = parts[1].trim();
                            currentParams.put(key, value);
                        }
                    }
                }
            }
            
            if (currentParams.isEmpty()) {
                // 没有参数时显示提示
                JLabel noParamsLabel = new JLabel();
                noParamsLabel.setBorder(BorderFactory.createEmptyBorder(10, 5, 5, 5));
                paramTestPanel.add(noParamsLabel);
            } else {
                // 为每个参数创建复选框，并添加事件监听器
                for (Map.Entry<String, String> entry : currentParams.entrySet()) {
                    String paramName = entry.getKey();
                    String paramValue = entry.getValue();
                    JCheckBox paramCheckBox = new JCheckBox(paramName + " (值: " + paramValue + ")", false);
                    paramCheckBox.setToolTipText("勾选后该参数会参与payload测试");
                    
                    // 添加复选框状态变化监听器
                    paramCheckBox.addItemListener(e -> {
                        // 当复选框状态变化时，保存配置
                        SwingUtilities.invokeLater(saveCurrentConfig);
                    });
                    
                    paramTestPanel.add(paramCheckBox);
                }
            }
            
            // 刷新界面
            paramTestPanel.revalidate();
            paramTestPanel.repaint();
            
            // 保存当前配置（如果启用了功能）
            saveCurrentConfig.run();
        };
        
        // 事件监听器
        enableAppendParamsCheckBox.addItemListener(e -> {
            boolean enabled = enableAppendParamsCheckBox.isSelected();
            
            // 根据启用状态控制文本框的可编辑性
            appendParamsTextArea.setEditable(!enabled);
            if (enabled) {
                // 启用时：文本框不可编辑，背景变灰
                appendParamsTextArea.setBackground(Color.LIGHT_GRAY);
                // 保存当前配置
                saveCurrentConfig.run();
            } else {
                // 禁用时：文本框可编辑，背景变白
                appendParamsTextArea.setBackground(Color.WHITE);
                // 保存禁用状态，但不清空右侧面板
                burpExtender.config.saveAppendParamsConfig(false, new HashMap<>(), new HashSet<>());
            }
        });
        
        // 文本变化监听器 - 实时更新参数映射（无论是否启用都更新显示）
        appendParamsTextArea.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            @Override
            public void insertUpdate(javax.swing.event.DocumentEvent e) {
                SwingUtilities.invokeLater(updateParameterCheckboxes);
            }
            
            @Override
            public void removeUpdate(javax.swing.event.DocumentEvent e) {
                SwingUtilities.invokeLater(updateParameterCheckboxes);
            }
            
            @Override
            public void changedUpdate(javax.swing.event.DocumentEvent e) {
                SwingUtilities.invokeLater(updateParameterCheckboxes);
            }
        });
        
        // 清除配置按钮事件
        clearAppendParamsBtn.addActionListener(e -> {
            int result = JOptionPane.showConfirmDialog(panel, 
                "确定要清除追加参数配置并禁用功能吗？", 
                "确认清除", 
                JOptionPane.YES_NO_OPTION, 
                JOptionPane.WARNING_MESSAGE);
            
            if (result == JOptionPane.YES_OPTION) {
                try {
                    // 清除配置
                    burpExtender.config.clearAppendParamsConfig();
                    
                    // 重置UI状态
                    enableAppendParamsCheckBox.setSelected(false);
                    appendParamsTextArea.setText(
                        "# 追加参数配置（格式：key:value，每行一个）\n" +
                        "# 示例：\n" +
                        "# token:abc123\n"
                    );
                    // 清除后恢复可编辑状态
                    appendParamsTextArea.setEditable(true);
                    appendParamsTextArea.setBackground(Color.WHITE);
                    
                    // 清空右侧面板，重新显示初始提示
                    paramTestPanel.removeAll();
                    JLabel resetLabel = new JLabel("<html><i>请在左侧输入参数，右侧会自动生成对应的测试选项</i></html>");
                    resetLabel.setBorder(BorderFactory.createEmptyBorder(10, 5, 5, 5));
                    paramTestPanel.add(resetLabel);
                    paramTestPanel.revalidate();
                    paramTestPanel.repaint();
                    
                    JOptionPane.showMessageDialog(panel, 
                        "追加参数配置已清除并禁用！", 
                        "清除成功", JOptionPane.INFORMATION_MESSAGE);
                        
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(panel, "清除失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        
        // 初始化状态 - 默认未启用，文本框可编辑，背景为白色
        appendParamsTextArea.setEditable(true);
        appendParamsTextArea.setBackground(Color.WHITE);
        
        // 初始化时更新参数映射显示
        SwingUtilities.invokeLater(updateParameterCheckboxes);
        
        panel.add(enablePanel, BorderLayout.NORTH);
        panel.add(configSplitPane, BorderLayout.CENTER);
        
        // 将说明文本和按钮放在最下方
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(appendParamsButtonPanel, BorderLayout.NORTH);
        bottomPanel.add(helpText, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建延时发包配置面板 - 独立的tab
     */
    private Component createDelayConfigPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        
        // 延时模式选择
        JPanel delayModePanel = new JPanel(new GridLayout(3, 1, 5, 5));
        delayModePanel.setBorder(BorderFactory.createTitledBorder("延时模式"));
        
        ButtonGroup delayModeGroup = new ButtonGroup();
        JRadioButton noDelayRadio = new JRadioButton("无延时 (立即发送)", true);
        JRadioButton fixedDelayRadio = new JRadioButton("固定延时", false);
        JRadioButton randomDelayRadio = new JRadioButton("随机延时", false);
        
        delayModeGroup.add(noDelayRadio);
        delayModeGroup.add(fixedDelayRadio);
        delayModeGroup.add(randomDelayRadio);
        
        delayModePanel.add(noDelayRadio);
        delayModePanel.add(fixedDelayRadio);
        delayModePanel.add(randomDelayRadio);
        
        // 延时配置面板
        JPanel delaySettingsPanel = new JPanel(new GridBagLayout());
        delaySettingsPanel.setBorder(BorderFactory.createTitledBorder("延时设置"));
        GridBagConstraints gbcDelay = new GridBagConstraints();
        gbcDelay.anchor = GridBagConstraints.WEST;
        gbcDelay.insets = new Insets(5, 5, 5, 5);
        
        // 固定延时配置
        gbcDelay.gridx = 0; gbcDelay.gridy = 0;
        delaySettingsPanel.add(new JLabel("固定延时时间(毫秒):"), gbcDelay);
        gbcDelay.gridx = 1;
        JTextField fixedDelayField = new JTextField("1000", 10);
        delaySettingsPanel.add(fixedDelayField, gbcDelay);
        
        // 随机延时配置
        gbcDelay.gridx = 0; gbcDelay.gridy = 1;
        delaySettingsPanel.add(new JLabel("随机延时最小值(毫秒):"), gbcDelay);
        gbcDelay.gridx = 1;
        JTextField randomDelayMinField = new JTextField("1000", 10);
        delaySettingsPanel.add(randomDelayMinField, gbcDelay);
        
        gbcDelay.gridx = 0; gbcDelay.gridy = 2;
        delaySettingsPanel.add(new JLabel("随机延时最大值(毫秒):"), gbcDelay);
        gbcDelay.gridx = 1;
        JTextField randomDelayMaxField = new JTextField("5000", 10);
        delaySettingsPanel.add(randomDelayMaxField, gbcDelay);
        
        // 保存按钮
        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));
        JButton saveDelayConfigBtn = new JButton("应用延时配置（本次会话）");
        buttonPanel.add(saveDelayConfigBtn);
        
        // 说明文本
        JTextArea helpText = new JTextArea(
            "说明：\n" +
            "1. 无延时：立即发送所有payload请求\n" +
            "2. 固定延时：每个请求之间固定等待指定时间\n" +
            "3. 随机延时：每个请求之间随机等待指定范围内的时间\n" +
            "4. 延时发包可以避免对目标服务器造成过大压力\n" +
            "5. 建议根据目标服务器性能和网络状况调整延时时间"
        );
        helpText.setEditable(false);
        helpText.setBackground(panel.getBackground());
        helpText.setFont(new Font("宋体", Font.PLAIN, 12));
        helpText.setBorder(BorderFactory.createTitledBorder("使用说明"));
        
        // 事件监听器
        noDelayRadio.addActionListener(e -> {
            fixedDelayField.setEnabled(false);
            randomDelayMinField.setEnabled(false);
            randomDelayMaxField.setEnabled(false);
        });
        
        fixedDelayRadio.addActionListener(e -> {
            fixedDelayField.setEnabled(true);
            randomDelayMinField.setEnabled(false);
            randomDelayMaxField.setEnabled(false);
        });
        
        randomDelayRadio.addActionListener(e -> {
            fixedDelayField.setEnabled(false);
            randomDelayMinField.setEnabled(true);
            randomDelayMaxField.setEnabled(true);
        });
        
        saveDelayConfigBtn.addActionListener(e -> {
            try {
                // 获取选中的模式
                int mode = 0;
                if (fixedDelayRadio.isSelected()) mode = 1;
                else if (randomDelayRadio.isSelected()) mode = 2;
                
                // 获取延时值
                int fixed = Integer.parseInt(fixedDelayField.getText().trim());
                int minRandom = Integer.parseInt(randomDelayMinField.getText().trim());
                int maxRandom = Integer.parseInt(randomDelayMaxField.getText().trim());
                
                // 验证输入
                if (fixed < 0 || minRandom < 0 || maxRandom < 0) {
                    JOptionPane.showMessageDialog(panel, "延时时间不能小于0", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                if (minRandom >= maxRandom) {
                    JOptionPane.showMessageDialog(panel, "随机延时最小值必须小于最大值", "错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }
                
                // 设置配置（仅内存，不持久化）
                burpExtender.config.setDelayConfig(mode, fixed, minRandom, maxRandom);
                
                String modeText = mode == 0 ? "无延时" : (mode == 1 ? "固定延时" : "随机延时");
                JOptionPane.showMessageDialog(panel, 
                    "延时配置已应用（仅本次会话有效）！\n" +
                    "延时模式: " + modeText + "\n" +
                    "固定延时: " + fixed + "ms\n" +
                    "随机延时: " + minRandom + "-" + maxRandom + "ms\n\n" +
                    "注意：延时配置不会持久化保存，重启插件后恢复默认（无延时）", 
                    "成功", JOptionPane.INFORMATION_MESSAGE);
                    
            } catch (NumberFormatException ex) {
                JOptionPane.showMessageDialog(panel, "请输入有效的数字", "错误", JOptionPane.ERROR_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "应用失败: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        // 初始化状态
        fixedDelayField.setEnabled(false);
        randomDelayMinField.setEnabled(false);
        randomDelayMaxField.setEnabled(false);
        
        panel.add(delayModePanel, BorderLayout.NORTH);
        panel.add(delaySettingsPanel, BorderLayout.CENTER);
        
        // 将说明文本和按钮放在最下方
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(buttonPanel, BorderLayout.NORTH);
        bottomPanel.add(helpText, BorderLayout.CENTER);
        panel.add(bottomPanel, BorderLayout.SOUTH);
        
        return panel;
    }
    
    /**
     * 创建高级配置面板
     */
    private Component createAdvancedConfigPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.insets = new Insets(5, 5, 5, 5);
        
        int row = 0;
        
        // 配置目录显示
        gbc.gridx = 0; gbc.gridy = row;
        panel.add(new JLabel("配置目录:"), gbc);
        
        JTextField configDirField = new JTextField(burpExtender.config.getConfigDirectory());
        configDirField.setEditable(false);
        gbc.gridx = 1; gbc.gridy = row++;
        gbc.weightx = 1.0;
        panel.add(configDirField, gbc);
        
        // 打开配置目录按钮
        JButton openDirButton = new JButton("打开配置目录");
        openDirButton.addActionListener(e -> {
            try {
                Desktop.getDesktop().open(new java.io.File(burpExtender.config.getConfigDirectory()));
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(panel, "无法打开目录: " + ex.getMessage(), "错误", JOptionPane.ERROR_MESSAGE);
            }
        });
        
        gbc.gridx = 0; gbc.gridy = row++;
        gbc.gridwidth = 2;
        gbc.weightx = 0.0;
        panel.add(openDirButton, gbc);
        
        // 重新加载配置按钮
        JButton reloadButton = new JButton("重新加载所有配置");
        reloadButton.addActionListener(e -> {
            burpExtender.config.loadAllConfigs();
            JOptionPane.showMessageDialog(panel, "配置重新加载完成", "成功", JOptionPane.INFORMATION_MESSAGE);
        });
        
        gbc.gridy = row++;
        panel.add(reloadButton, gbc);
        
        // 填充剩余空间
        gbc.gridy = row;
        gbc.weighty = 1.0;
        panel.add(new JPanel(), gbc);
        
        return new JScrollPane(panel);
    }
    
    /**
     * 设置控制面板事件监听器
     */
    private void setupControlPanelListeners() {
        enablePluginCheckBox.addItemListener(e -> {
            burpExtender.isEnabled = enablePluginCheckBox.isSelected();
        });
        
        monitorRepeaterCheckBox.addItemListener(e -> {
            burpExtender.monitorRepeater = monitorRepeaterCheckBox.isSelected();
        });
        
        monitorProxyCheckBox.addItemListener(e -> {
            burpExtender.monitorProxy = monitorProxyCheckBox.isSelected();
        });
        
        testCookieCheckBox.addItemListener(e -> {
            burpExtender.testCookie = testCookieCheckBox.isSelected();
        });
        
        processNumbersCheckBox.addItemListener(e -> {
            burpExtender.processNumbers = processNumbersCheckBox.isSelected();
        });
        
        clearListButton.addActionListener(e -> clearAllResults());
        
        whitelistButton.addActionListener(e -> toggleWhitelist());
    }
    
    /**
     * 清空所有结果
     */
    private void clearAllResults() {
        synchronized (scanResults) {
            scanResults.clear();
        }
        synchronized (payloadDetails) {
            payloadDetails.clear();
        }
        
        // 清空选中状态
        currentSelectedScanMd5 = null;
        
        scanResultsModel.fireTableDataChanged();
        payloadDetailsModel.fireTableDataChanged();
        
        // 清空编辑器
        requestEditor.setMessage(new byte[0], true);
        responseEditor.setMessage(new byte[0], false);
        
        callbacks.printOutput("所有结果已清空，包括选中状态");
    }
    
    /**
     * 切换白名单状态
     */
    private void toggleWhitelist() {
        if (burpExtender.whitelistEnabled) {
            burpExtender.whitelistEnabled = false;
            whitelistButton.setText("启动白名单");
            whitelistTextField.setEditable(true);
        } else {
            burpExtender.whitelistEnabled = true;
            burpExtender.whitelistDomains = whitelistTextField.getText();
            whitelistButton.setText("关闭白名单");
            whitelistTextField.setEditable(false);
        }
    }
    
    /**
     * 添加扫描结果
     */
    public void addScanResult(LogEntry entry) {
        callbacks.printOutput("=== addScanResult调用 ===");
        callbacks.printOutput("添加扫描结果: " + entry.getUrl());
        
        synchronized (scanResults) {
            scanResults.add(entry);
            callbacks.printOutput("扫描结果列表大小: " + scanResults.size());
            
            SwingUtilities.invokeLater(() -> {
                try {
                    int newRowIndex = scanResults.size() - 1;
                    callbacks.printOutput("触发表格更新，新行索引: " + newRowIndex);
                    scanResultsModel.fireTableRowsInserted(newRowIndex, newRowIndex);
                    callbacks.printOutput("表格更新完成");
                    
                    // 强制刷新表格显示
                    scanResultsTable.revalidate();
                    scanResultsTable.repaint();
                } catch (Exception e) {
                    callbacks.printError("更新扫描结果表格失败: " + e.getMessage());
                    e.printStackTrace();
                }
            });
        }
    }
    
    /**
     * 添加Payload详情
     */
    public void addPayloadDetail(LogEntry entry) {
        // callbacks.printOutput("=== addPayloadDetail调用 ===");
        // callbacks.printOutput("添加Payload详情: " + entry.getParameter() + " -> " + entry.getPayload());
        // callbacks.printOutput("Payload详情MD5: " + entry.getDataMd5());
        // callbacks.printOutput("当前选中的扫描结果MD5: " + currentSelectedScanMd5);
        
        synchronized (payloadDetails) {
            payloadDetails.add(entry);
            //callbacks.printOutput("Payload详情列表大小: " + payloadDetails.size());
            
            SwingUtilities.invokeLater(() -> {
                try {
                    int newRowIndex = payloadDetails.size() - 1;
                   // callbacks.printOutput("触发Payload详情表格更新，新行索引: " + newRowIndex);
                    payloadDetailsModel.fireTableRowsInserted(newRowIndex, newRowIndex);
                   // callbacks.printOutput("Payload详情表格更新完成");
                    
                    // 强制刷新表格显示
                    payloadDetailsTable.revalidate();
                    payloadDetailsTable.repaint();
                } catch (Exception e) {
                    callbacks.printError("更新Payload详情表格失败: " + e.getMessage());
                    e.printStackTrace();
                }
            });
        }
    }
    
    /**
     * 刷新扫描结果表格 - 3.0.7版本新增
     * 用于在更新LogEntry数据后刷新表格显示
     */
    public void refreshScanResultsTable() {
        SwingUtilities.invokeLater(() -> {
            try {
                scanResultsModel.fireTableDataChanged();
                scanResultsTable.revalidate();
                scanResultsTable.repaint();
            } catch (Exception e) {
                callbacks.printError("刷新扫描结果表格失败: " + e.getMessage());
                e.printStackTrace();
            }
        });
    }
    
    // ========== ITab接口实现 ==========
    
    @Override
    public String getTabCaption() {
        return "DouSQL";
    }
    
    @Override
    public Component getUiComponent() {
        return mainSplitPane;
    }
    
    // ========== IMessageEditorController接口实现 ==========
    
    @Override
    public byte[] getRequest() {
        return currentDisplayedItem != null ? currentDisplayedItem.getRequest() : new byte[0];
    }
    
    @Override
    public byte[] getResponse() {
        return currentDisplayedItem != null ? currentDisplayedItem.getResponse() : new byte[0];
    }
    
    @Override
    public IHttpService getHttpService() {
        return currentDisplayedItem != null ? currentDisplayedItem.getHttpService() : null;
    }
    
    // ========== 表格模型类 ==========
    
    /**
     * 扫描结果表格模型 - 按照原始xiasql的字段结构
     */
    private class ScanResultsTableModel extends AbstractTableModel {
        private final String[] columnNames = {"#", "来源", "URL", "返回包长度", "状态"};
        
        @Override
        public int getRowCount() {
            int count = scanResults.size();
            return count;
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            if (rowIndex >= scanResults.size()) {
                callbacks.printOutput("警告: 行索引超出范围 " + rowIndex + " >= " + scanResults.size());
                return "";
            }
            
            LogEntry entry = scanResults.get(rowIndex);
            switch (columnIndex) {
                case 0: return entry.getId();
                case 1: return entry.getToolName(); // 来源 - 使用LogEntry的getToolName方法
                case 2: return entry.getUrl();
                case 3: return entry.getResponseLength(); // 返回包长度
                case 4: return entry.getState();
                default: return "";
            }
        }
    }
    
    /**
     * Payload详情表格模型 - 按照原始xiasql的字段结构，支持过滤显示
     */
    private class PayloadDetailsTableModel extends AbstractTableModel {
        private final String[] columnNames = {"参数", "payload", "返回包长度", "变化", "用时", "响应码"};
        
        /**
         * 获取过滤后的payload详情列表
         */
        private List<LogEntry> getFilteredPayloadDetails() {
            if (currentSelectedScanMd5 == null) {
                return payloadDetails; // 如果没有选中任何扫描结果，显示所有详情
            }
            
            List<LogEntry> filtered = new ArrayList<>();
            synchronized (payloadDetails) {
                for (LogEntry detail : payloadDetails) {
                    if (detail.getDataMd5().equals(currentSelectedScanMd5)) {
                        filtered.add(detail);
                    }
                }
            }
            return filtered;
        }
        
        @Override
        public int getRowCount() {
            List<LogEntry> filtered = getFilteredPayloadDetails();
            int count = filtered.size();
            return count;
        }
        
        @Override
        public int getColumnCount() {
            return columnNames.length;
        }
        
        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }
        
        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            List<LogEntry> filtered = getFilteredPayloadDetails();
            if (rowIndex >= filtered.size()) {
                callbacks.printOutput("警告: Payload详情行索引超出范围 " + rowIndex + " >= " + filtered.size());
                return "";
            }
            
            LogEntry entry = filtered.get(rowIndex);
            switch (columnIndex) {
                case 0: return entry.getParameter();
                case 1: return entry.getPayload();
                case 2: return entry.getResponseLength(); // 返回包长度
                case 3: return entry.getChange();
                case 4: return entry.getResponseTime(); // 用时
                case 5: return entry.getStatusCode(); // 响应码
                default: return "";
            }
        }
    }
    
    /**
     * 扫描结果表格 - 处理选择事件
     */
    private class ScanResultsTable extends JTable {
        public ScanResultsTable(TableModel model) {
            super(model);
            
            // 设置列宽 - 根据用户要求调整
            if (getColumnModel().getColumnCount() >= 6) {
                // #缩减一半、来源缩减一半，URL可以扩大一些，返回包长度也可以缩减一半，状态栏可以扩大一些，保持url和状态栏大小一致
                getColumnModel().getColumn(0).setPreferredWidth(30);  // # - 缩减一半 (原60)
                getColumnModel().getColumn(1).setPreferredWidth(200); // URL - 扩大
                getColumnModel().getColumn(2).setPreferredWidth(200); // 状态 - 扩大，与URL一致
                getColumnModel().getColumn(3).setPreferredWidth(30);  // 参数 - 保持
                getColumnModel().getColumn(4).setPreferredWidth(80);  // 时间 - 保持
                getColumnModel().getColumn(5).setPreferredWidth(50);  // 来源 - 缩减一半 (原100)
            }
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            if (row >= 0 && row < scanResults.size()) {
                // 转换为模型行索引（如果有排序）
                int modelRow = convertRowIndexToModel(row);
                if (modelRow >= 0 && modelRow < scanResults.size()) {
                    LogEntry entry = scanResults.get(modelRow);
                    
                    // 更新Payload详情表格
                    updatePayloadDetailsForEntry(entry);
                    
                    // 设置HTTP编辑器内容 - 关键：完全按照RVScan的方式
                    if (entry.getRequestResponse() != null) {
                        currentDisplayedItem = entry.getRequestResponse();
                        
                        // 调试：检查数据是否有效
                        byte[] request = entry.getRequestResponse().getRequest();
                        byte[] response = entry.getRequestResponse().getResponse();
                        
                        callbacks.printOutput("=== 调试信息 ===");
                        callbacks.printOutput("Request长度: " + (request != null ? request.length : "null"));
                        callbacks.printOutput("Response长度: " + (response != null ? response.length : "null"));
                        
                        if (request != null && request.length > 0) {
                            callbacks.printOutput("Request前100字符: " + new String(request, 0, Math.min(100, request.length)));
                        }
                        
                        // 使用Legacy API设置消息 - 完全按照RVScan的方式
                        requestEditor.setMessage(request != null ? request : new byte[0], true);
                        responseEditor.setMessage(response != null ? response : new byte[0], false);
                        
                        callbacks.printOutput("扫描结果表格: HTTP编辑器数据设置完成");
                    } else {
                        callbacks.printOutput("警告: RequestResponse为null");
                        // 清空编辑器
                        requestEditor.setMessage(new byte[0], true);
                        responseEditor.setMessage(new byte[0], false);
                        currentDisplayedItem = null;
                        callbacks.printOutput("扫描结果表格: 清空HTTP编辑器");
                    }
                }
            }
            // 关键：最后调用父类方法，完全按照RVScan的方式
            super.changeSelection(row, col, toggle, extend);
        }
    }
    
    /**
     * Payload详情表格 - 处理选择事件，支持过滤数据
     */
    private class PayloadDetailsTable extends JTable {
        public PayloadDetailsTable(TableModel model) {
            super(model);
        }
        
        @Override
        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            // 获取过滤后的数据
            List<LogEntry> filteredDetails = getFilteredPayloadDetails();
            
            if (row >= 0 && row < filteredDetails.size()) {
                // 转换为模型行索引（如果有排序）
                int modelRow = convertRowIndexToModel(row);
                if (modelRow >= 0 && modelRow < filteredDetails.size()) {
                    LogEntry entry = filteredDetails.get(modelRow);
                    
                    // 设置HTTP编辑器内容 - 关键：完全按照RVScan的方式
                    if (entry.getRequestResponse() != null) {
                        currentDisplayedItem = entry.getRequestResponse();
                        
                        // 使用Legacy API设置消息 - 完全按照RVScan的方式
                        requestEditor.setMessage(entry.getRequestResponse().getRequest(), true);
                        responseEditor.setMessage(entry.getRequestResponse().getResponse(), false);
                        
                        callbacks.printOutput("PayloadTable: HTTP编辑器数据设置完成 (参数: " + entry.getParameter() + ")");
                    } else {
                        // 清空编辑器
                        requestEditor.setMessage(new byte[0], true);
                        responseEditor.setMessage(new byte[0], false);
                        currentDisplayedItem = null;
                        callbacks.printOutput("PayloadTable: 清空HTTP编辑器");
                    }
                }
            }
            // 关键：最后调用父类方法，完全按照RVScan的方式
            super.changeSelection(row, col, toggle, extend);
        }
        
        /**
         * 获取过滤后的payload详情列表 - 与TableModel保持一致
         */
        private List<LogEntry> getFilteredPayloadDetails() {
            if (currentSelectedScanMd5 == null) {
                return payloadDetails; // 如果没有选中任何扫描结果，显示所有详情
            }
            
            List<LogEntry> filtered = new ArrayList<>();
            synchronized (payloadDetails) {
                for (LogEntry detail : payloadDetails) {
                    if (detail.getDataMd5().equals(currentSelectedScanMd5)) {
                        filtered.add(detail);
                    }
                }
            }
            return filtered;
        }
    }
    
    /**
     * 更新指定条目的Payload详情 - 修复版本：不破坏全局数据
     */
    private void updatePayloadDetailsForEntry(LogEntry entry) {
        callbacks.printOutput("=== 更新Payload详情 ===");
        callbacks.printOutput("选中的扫描结果: " + entry.getUrl());
        callbacks.printOutput("MD5标识: " + entry.getDataMd5());
        
        // 保存当前选中的扫描结果MD5，用于过滤显示
        currentSelectedScanMd5 = entry.getDataMd5();
        
        // 统计相关的payload详情数量
        int relatedCount = 0;
        synchronized (payloadDetails) {
            for (LogEntry detail : payloadDetails) {
                if (detail.getDataMd5().equals(entry.getDataMd5())) {
                    relatedCount++;
                }
            }
        }
        
        callbacks.printOutput("找到 " + relatedCount + " 个相关的Payload详情");
        
        // 刷新表格显示 - 表格模型会根据currentSelectedScanMd5过滤数据
        SwingUtilities.invokeLater(() -> {
            payloadDetailsModel.fireTableDataChanged();
            callbacks.printOutput("Payload详情表格已刷新，显示MD5=" + currentSelectedScanMd5 + "的详情");
        });
    }
    
    /**
     * 测试HTTP编辑器功能
     */
    private void testHttpEditors() {
        try {
            // 创建测试请求
            String testRequest = "GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: DouSQL-Test\r\n\r\n";
            String testResponse = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 13\r\n\r\n<html></html>";
            
            // 测试设置消息 - 完全按照RVScan的方式
            requestEditor.setMessage(testRequest.getBytes(), true);
            responseEditor.setMessage(testResponse.getBytes(), false);
            
            //callbacks.printOutput("HTTP编辑器功能测试完成 - 编辑器工作正常");
            
            // 清空测试内容
            SwingUtilities.invokeLater(() -> {
                try {
                    Thread.sleep(1000); // 等待1秒让用户看到测试内容
                    requestEditor.setMessage(new byte[0], true);
                    responseEditor.setMessage(new byte[0], false);
                } catch (InterruptedException e) {
                    // 忽略中断异常
                }
            });
            
        } catch (Exception e) {
            callbacks.printError("HTTP编辑器测试失败: " + e.getMessage());
        }
    }
    
    // ========== 其他必要方法 ==========
    
    /**
     * 添加扫描结果表格右键菜单 - 3.0.6版本新增功能
     */
    private void addScanResultsContextMenu(JTable table) {
        JPopupMenu contextMenu = new JPopupMenu();
        
        // 停止/恢复当前请求测试 - 修复per-request pause逻辑
        JMenuItem stopResumeTestItem = new JMenuItem("停止当前请求测试");
        stopResumeTestItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                if (modelRow >= 0 && modelRow < scanResults.size()) {
                    LogEntry entry = scanResults.get(modelRow);
                    String dataMd5 = entry.getDataMd5();
                    
                    if (burpExtender.pausedRequests.contains(dataMd5)) {
                        // 恢复测试
                        burpExtender.pausedRequests.remove(dataMd5);
                        callbacks.printOutput("已恢复请求测试 (MD5: " + dataMd5 + "): " + entry.getUrl());
                        JOptionPane.showMessageDialog(mainSplitPane, 
                            "已恢复请求测试:\n" + entry.getUrl() + "\n\nMD5: " + dataMd5 + "\n\n只影响此特定请求，不影响其他请求", 
                            "测试控制", 
                            JOptionPane.INFORMATION_MESSAGE);
                    } else {
                        // 停止测试
                        burpExtender.pausedRequests.add(dataMd5);
                        callbacks.printOutput("已停止请求测试 (MD5: " + dataMd5 + "): " + entry.getUrl());
                        JOptionPane.showMessageDialog(mainSplitPane, 
                            "已停止请求测试:\n" + entry.getUrl() + "\n\nMD5: " + dataMd5 + "\n\n只影响此特定请求，不影响其他请求", 
                            "测试控制", 
                            JOptionPane.INFORMATION_MESSAGE);
                    }
                }
            }
        });
        
        // 删除测试请求
        JMenuItem deleteTestItem = new JMenuItem("删除测试请求");
        deleteTestItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                if (modelRow >= 0 && modelRow < scanResults.size()) {
                    deleteTestRequest(modelRow);
                }
            }
        });
        
        // 暂停所有扫描（全局控制）
        JMenuItem pauseAllItem = new JMenuItem("暂停所有扫描");
        pauseAllItem.addActionListener(e -> {
            burpExtender.scanningPaused = true;
            callbacks.printOutput("所有扫描已暂停");
            JOptionPane.showMessageDialog(mainSplitPane, 
                "所有扫描已暂停\n可以通过重新加载插件来恢复扫描", 
                "扫描控制", 
                JOptionPane.INFORMATION_MESSAGE);
        });
        
        contextMenu.add(stopResumeTestItem);
        contextMenu.add(deleteTestItem);
        contextMenu.addSeparator();
        contextMenu.add(pauseAllItem);
        
        // 添加右键菜单到表格
        table.setComponentPopupMenu(contextMenu);
        
        //callbacks.printOutput("扫描结果表格右键菜单已添加 - 3.0.6版本功能");
    }
    
    /**
     * 添加Payload详情表格右键菜单 - 3.0.6版本新增功能
     */
    private void addPayloadDetailsContextMenu(JTable table) {
        JPopupMenu contextMenu = new JPopupMenu();
        
        // 删除此payload测试结果
        JMenuItem deletePayloadItem = new JMenuItem("删除此payload测试结果");
        deletePayloadItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                if (modelRow >= 0 && modelRow < payloadDetails.size()) {
                    deletePayloadResult(modelRow);
                }
            }
        });
        
        // 重新测试此payload
        JMenuItem retestPayloadItem = new JMenuItem("重新测试此payload");
        retestPayloadItem.addActionListener(e -> {
            int selectedRow = table.getSelectedRow();
            if (selectedRow >= 0) {
                int modelRow = table.convertRowIndexToModel(selectedRow);
                if (modelRow >= 0 && modelRow < payloadDetails.size()) {
                    LogEntry entry = payloadDetails.get(modelRow);
                    retestPayload(entry);
                }
            }
        });
        
        contextMenu.add(deletePayloadItem);
        contextMenu.add(retestPayloadItem);
        
        // 添加右键菜单到表格
        table.setComponentPopupMenu(contextMenu);
        
        //callbacks.printOutput("Payload详情表格右键菜单已添加 - 3.0.6版本功能");
    }
    
    /**
     * 停止当前目标请求测试 - 3.0.6版本新增功能
     */
    private void stopTargetTesting(LogEntry entry) {
        callbacks.printOutput("=== 停止目标测试 ===");
        callbacks.printOutput("目标URL: " + entry.getUrl());
        callbacks.printOutput("MD5标识: " + entry.getDataMd5());
        
        // 实现停止逻辑：将该目标的状态标记为已停止
        synchronized (scanResults) {
            for (int i = 0; i < scanResults.size(); i++) {
                LogEntry scanEntry = scanResults.get(i);
                if (scanEntry.getDataMd5().equals(entry.getDataMd5())) {
                    // 创建新的LogEntry，状态改为"stopped"
                    LogEntry stoppedEntry = new LogEntry(
                        scanEntry.getId(),
                        scanEntry.getUrl(),
                        "stopped",
                        scanEntry.getParameterCount(),
                        scanEntry.getTimestamp(),
                        scanEntry.getRequestResponse(),
                        scanEntry.getDataMd5(),
                        scanEntry.getToolFlag()
                    );
                    
                    scanResults.set(i, stoppedEntry);
                    
                    // 更新UI - 使用final变量
                    final int finalIndex = i;
                    SwingUtilities.invokeLater(() -> {
                        scanResultsModel.fireTableRowsUpdated(finalIndex, finalIndex);
                    });
                    
                    break;
                }
            }
        }
        
        // 将该目标添加到停止列表中，防止继续测试
        burpExtender.processedUrls.add(entry.getDataMd5() + "_STOPPED");
        
        callbacks.printOutput("目标测试已停止: " + entry.getUrl());
        
        JOptionPane.showMessageDialog(mainSplitPane, 
            "已停止目标测试:\n" + entry.getUrl(), 
            "停止成功", 
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    /**
     * 删除测试请求 - 3.0.6版本新增功能
     */
    private void deleteTestRequest(int modelRow) {
        callbacks.printOutput("=== 删除测试请求 ===");
        
        LogEntry entryToDelete = scanResults.get(modelRow);
        String dataMd5 = entryToDelete.getDataMd5();
        
        callbacks.printOutput("删除目标URL: " + entryToDelete.getUrl());
        callbacks.printOutput("MD5标识: " + dataMd5);
        
        int result = JOptionPane.showConfirmDialog(mainSplitPane,
            "确定要删除此测试请求吗？\n" +
            "URL: " + entryToDelete.getUrl() + "\n" +
            "删除后相关的所有payload测试结果也会被删除。",
            "确认删除",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (result == JOptionPane.YES_OPTION) {
            // 删除扫描结果
            synchronized (scanResults) {
                scanResults.remove(modelRow);
            }
            
            // 删除相关的payload详情
            synchronized (payloadDetails) {
                payloadDetails.removeIf(detail -> detail.getDataMd5().equals(dataMd5));
            }
            
            // 更新UI
            SwingUtilities.invokeLater(() -> {
                scanResultsModel.fireTableRowsDeleted(modelRow, modelRow);
                payloadDetailsModel.fireTableDataChanged();
                
                // 清空HTTP编辑器
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
                currentDisplayedItem = null;
            });
            
            callbacks.printOutput("测试请求删除完成: " + entryToDelete.getUrl());
            
            JOptionPane.showMessageDialog(mainSplitPane,
                "测试请求删除成功",
                "删除成功",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 删除payload测试结果 - 3.0.6版本新增功能
     */
    private void deletePayloadResult(int modelRow) {
        callbacks.printOutput("=== 删除Payload测试结果 ===");
        
        LogEntry entryToDelete = payloadDetails.get(modelRow);
        
        callbacks.printOutput("删除参数: " + entryToDelete.getParameter());
        callbacks.printOutput("删除payload: " + entryToDelete.getPayload());
        
        int result = JOptionPane.showConfirmDialog(mainSplitPane,
            "确定要删除此payload测试结果吗？\n" +
            "参数: " + entryToDelete.getParameter() + "\n" +
            "Payload: " + entryToDelete.getPayload(),
            "确认删除",
            JOptionPane.YES_NO_OPTION,
            JOptionPane.WARNING_MESSAGE);
        
        if (result == JOptionPane.YES_OPTION) {
            // 删除payload详情
            synchronized (payloadDetails) {
                payloadDetails.remove(modelRow);
            }
            
            // 更新UI
            SwingUtilities.invokeLater(() -> {
                payloadDetailsModel.fireTableRowsDeleted(modelRow, modelRow);
                
                // 清空HTTP编辑器
                requestEditor.setMessage(new byte[0], true);
                responseEditor.setMessage(new byte[0], false);
                currentDisplayedItem = null;
            });
            
            callbacks.printOutput("Payload测试结果删除完成");
            
            JOptionPane.showMessageDialog(mainSplitPane,
                "Payload测试结果删除成功",
                "删除成功",
                JOptionPane.INFORMATION_MESSAGE);
        }
    }
    
    /**
     * 重新测试payload - 3.0.6版本新增功能
     */
    private void retestPayload(LogEntry entry) {
        callbacks.printOutput("=== 重新测试Payload ===");
        callbacks.printOutput("参数: " + entry.getParameter());
        callbacks.printOutput("Payload: " + entry.getPayload());
        
        // 这里可以实现重新测试的逻辑
        // 由于需要原始请求信息，这里先提供一个基础实现
        JOptionPane.showMessageDialog(mainSplitPane,
            "重新测试功能正在开发中\n" +
            "参数: " + entry.getParameter() + "\n" +
            "Payload: " + entry.getPayload(),
            "功能提示",
            JOptionPane.INFORMATION_MESSAGE);
    }
    
    private void createContentArea() {
        // 预留方法，用于创建内容区域
    }
}