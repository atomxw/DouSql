package config;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import java.io.*;
import java.util.*;

/**
 * DouSQL配置管理类
 */
public class DouSqlConfig {
    private final BurpExtender burpExtender;
    private final IBurpExtenderCallbacks callbacks;
    
    // 配置目录
    private String configDirectory;
    
    // 各种配置
    private int responseTimeThreshold = 2000; // 响应时间阈值(毫秒) - 用于检测时间盲注
    private int requestTimeout = 30000; // 请求超时时间(毫秒)，默认30秒 - 超过此时间直接丢弃
    private int lengthDiffThreshold = 100;
    private List<String> errorKeywords = new ArrayList<>();
    private List<String> whitelistParams = new ArrayList<>();
    private List<String> blacklistParams = new ArrayList<>();
    private int paramFilterMode = 0; // 0:无过滤 1:白名单 2:黑名单
    
    // 延时配置
    private int delayMode = 0; // 0:无延时 1:固定延时 2:随机延时
    private int fixedDelay = 1000; // 固定延时时间(毫秒)
    private int randomDelayMin = 1000; // 随机延时最小值(毫秒)
    private int randomDelayMax = 5000; // 随机延时最大值(毫秒)
    
    // 追加参数配置
    private boolean appendParamsEnabled = false;
    private Map<String, String> appendParams = new HashMap<>();
    private Set<String> testableAppendParams = new HashSet<>();
    
    // URL黑名单配置
    private List<String> urlBlacklist = new ArrayList<>();
    
    public DouSqlConfig(BurpExtender burpExtender) {
        this.burpExtender = burpExtender;
        this.callbacks = burpExtender.callbacks;
        
        initializeConfigDirectory();
    }
    
    /**
     * 初始化配置目录
     */
    private void initializeConfigDirectory() {
        // 优先使用用户主目录
        configDirectory = System.getProperty("user.home") + "/dousql";
        
        // 创建目录
        File dir = new File(configDirectory);
        if (!dir.exists()) {
            dir.mkdirs();
        }
        
        callbacks.printOutput("配置目录: " + configDirectory);
    }
    
    /**
     * 加载所有配置
     */
    public void loadAllConfigs() {
        loadResponseTimeThreshold();
        loadLengthDiffThreshold();
        loadErrorKeywords();
        loadParamFilters();
        loadDelayConfig();
        loadAppendParamsConfig();
        loadUrlBlacklist();
        
        callbacks.printOutput("所有配置加载完成");
    }
    
    /**
     * 加载时间阈值配置（包含响应时间阈值和请求超时时间）
     */
    private void loadResponseTimeThreshold() {
        try (BufferedReader reader = new BufferedReader(new FileReader(
                configDirectory + "/xia_SQL_time_threshold.ini"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.trim().isEmpty() || line.trim().startsWith("#")) {
                    continue;
                }
                
                String[] parts = line.split("=", 2);
                if (parts.length == 2) {
                    String key = parts[0].trim();
                    String value = parts[1].trim();
                    
                    if ("responseTimeThreshold".equals(key)) {
                        responseTimeThreshold = Integer.parseInt(value);
                    } else if ("requestTimeout".equals(key)) {
                        requestTimeout = Integer.parseInt(value);
                    }
                }
            }
            
            // callbacks.printOutput("已加载时间阈值配置:");
            // callbacks.printOutput("  响应时间阈值: " + responseTimeThreshold + "毫秒 (" + (responseTimeThreshold/1000.0) + "秒) - 用于检测时间盲注");
            // callbacks.printOutput("  请求超时时间: " + requestTimeout + "毫秒 (" + (requestTimeout/1000.0) + "秒) - 超过此时间直接丢弃");
        } catch (Exception e) {
            // callbacks.printOutput("使用默认时间阈值配置:");
            // callbacks.printOutput("  响应时间阈值: " + responseTimeThreshold + "毫秒 (" + (responseTimeThreshold/1000.0) + "秒)");
            // callbacks.printOutput("  请求超时时间: " + requestTimeout + "毫秒 (" + (requestTimeout/1000.0) + "秒)");
            callbacks.printOutput("配置文件路径: " + configDirectory + "/xia_SQL_time_threshold.ini");
        }
    }
    
    /**
     * 加载长度差异阈值
     */
    private void loadLengthDiffThreshold() {
        try (BufferedReader reader = new BufferedReader(new FileReader(
                configDirectory + "/xia_SQL_length_diff_threshold.ini"))) {
            String line = reader.readLine();
            if (line != null && !line.trim().isEmpty()) {
                lengthDiffThreshold = Integer.parseInt(line.trim());
            }
            //callbacks.printOutput("已加载长度差异阈值: " + lengthDiffThreshold + "字节");
        } catch (Exception e) {
            callbacks.printOutput("使用默认长度差异阈值: " + lengthDiffThreshold + "字节");
            callbacks.printOutput("配置文件路径: " + configDirectory + "/xia_SQL_length_diff_threshold.ini");
        }
    }
    
    /**
     * 加载错误关键字
     */
    private void loadErrorKeywords() {
        errorKeywords.clear();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(
                configDirectory + "/xia_SQL_diy_error.ini"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    errorKeywords.add(line);
                    //callbacks.printOutput("加载错误关键字: " + line);
                }
            }
            callbacks.printOutput("已加载错误关键字，共" + errorKeywords.size() + "条");
            
        
        } catch (Exception e) {
            callbacks.printOutput("加载自定义错误关键字失败: " + e.getMessage());
            callbacks.printOutput("配置文件路径: " + configDirectory + "/xia_SQL_diy_error.ini");
            // 使用默认错误关键字
            loadDefaultErrorKeywords();
            callbacks.printOutput("使用默认错误关键字，共" + errorKeywords.size() + "条");
        }
    }
    
    /**
     * 加载默认错误关键字
     */
    private void loadDefaultErrorKeywords() {
        errorKeywords.addAll(Arrays.asList(
            "ORA-\\d{5}",
            "SQL syntax.*?MySQL",
            "Unknown column",
            "SQL syntax",
            "java.sql.SQLSyntaxErrorException",
            "Error SQL:",
            "Syntax error",
            "附近有语法错误",
            "java.sql.SQLException",
            "引号不完整",
            "System.Exception: SQL Execution Error!",
            "com.mysql.jdbc",
            "MySQLSyntaxErrorException",
            "valid MySQL result",
            "your MySQL server version",
            "MySqlClient",
            "MySqlException",
            "valid PostgreSQL result",
            "PG::SyntaxError:",
            "org.postgresql.jdbc",
            "PSQLException",
            "Microsoft SQL Native Client error",
            "ODBC SQL Server Driver",
            "SQLServer JDBC Driver",
            "com.jnetdirect.jsql",
            "macromedia.jdbc.sqlserver",
            "com.microsoft.sqlserver.jdbc",
            "Microsoft Access",
            "Access Database Engine",
            "ODBC Microsoft Access",
            "Oracle error",
            "DB2 SQL error",
            "SQLite error",
            "Sybase message",
            "SybSQLException"
        ));
    }
    
    /**
     * 加载参数过滤配置
     */
    private void loadParamFilters() {
        // 加载过滤模式
        try (BufferedReader reader = new BufferedReader(new FileReader(
                configDirectory + "/xia_SQL_param_filter_mode.ini"))) {
            String line = reader.readLine();
            if (line != null && !line.trim().isEmpty()) {
                paramFilterMode = Integer.parseInt(line.trim());
            }
        } catch (Exception e) {
            paramFilterMode = 0;
        }
        
        // 加载白名单
        loadParamList(whitelistParams, "/xia_SQL_whitelist.ini");
        
        // 加载黑名单
        loadParamList(blacklistParams, "/xia_SQL_blacklist.ini");
        
    //     callbacks.printOutput("已加载参数过滤配置: 模式=" + paramFilterMode + 
    //                         ", 白名单=" + whitelistParams.size() + "个" +
    //                         ", 黑名单=" + blacklistParams.size() + "个");
    // }
    }
    
    /**
     * 加载参数列表
     */
    private void loadParamList(List<String> list, String filename) {
        list.clear();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(configDirectory + filename))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty()) {
                    list.add(line);
                }
            }
        } catch (Exception e) {
            // 文件不存在或读取失败，使用空列表
        }
    }
    
    /**
     * 保存时间阈值配置（包含响应时间阈值和请求超时时间）
     */
    public void saveTimeThresholdConfig(int responseThreshold, int timeout) {
        this.responseTimeThreshold = responseThreshold;
        this.requestTimeout = timeout;
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(
                configDirectory + "/xia_SQL_time_threshold.ini"))) {
            writer.write("# 时间阈值配置文件");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# responseTimeThreshold - 响应时间阈值(毫秒)");
            writer.newLine();
            writer.write("#   用途：检测时间盲注，当响应时间超过此阈值时标记为TIME");
            writer.newLine();
            writer.write("#   默认：2000毫秒(2秒)");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# requestTimeout - 请求超时时间(毫秒)");
            writer.newLine();
            writer.write("#   用途：请求超时控制，超过此时间直接丢弃请求");
            writer.newLine();
            writer.write("#   默认：30000毫秒(30秒)");
            writer.newLine();
            writer.write("#   说明：超时的请求会被标记为timeout>xx秒");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.newLine();
            writer.write("responseTimeThreshold=" + responseThreshold);
            writer.newLine();
            writer.write("requestTimeout=" + timeout);
            writer.newLine();
            
            callbacks.printOutput("时间阈值配置已保存:");
            callbacks.printOutput("  响应时间阈值: " + responseThreshold + "毫秒 (" + (responseThreshold/1000.0) + "秒)");
            callbacks.printOutput("  请求超时时间: " + timeout + "毫秒 (" + (timeout/1000.0) + "秒)");
        } catch (IOException e) {
            callbacks.printError("保存时间阈值配置失败: " + e.getMessage());
        }
    }
    
    /**
     * 保存响应时间阈值（兼容旧方法）
     */
    @Deprecated
    public void saveResponseTimeThreshold(int threshold) {
        saveTimeThresholdConfig(threshold, this.requestTimeout);
    }
    
    /**
     * 保存长度差异阈值
     */
    public void saveLengthDiffThreshold(int threshold) {
        this.lengthDiffThreshold = threshold;
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(
                configDirectory + "/xia_SQL_length_diff_threshold.ini"))) {
            writer.write(String.valueOf(threshold));
            callbacks.printOutput("长度差异阈值已保存: " + threshold + "字节");
        } catch (IOException e) {
            callbacks.printError("保存长度差异阈值失败: " + e.getMessage());
        }
    }
    
    /**
     * 保存错误关键字
     */
    public void saveErrorKeywords(List<String> keywords) {
        this.errorKeywords.clear();
        this.errorKeywords.addAll(keywords);
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(
                configDirectory + "/xia_SQL_diy_error.ini"))) {
            for (String keyword : keywords) {
                writer.write(keyword);
                writer.newLine();
            }
            callbacks.printOutput("错误关键字已保存，共" + keywords.size() + "条");
            
            // 调试：显示保存的关键字
            callbacks.printOutput("=== 保存的错误关键字 ===");
            for (int i = 0; i < keywords.size(); i++) {
                callbacks.printOutput("  [" + i + "] " + keywords.get(i));
            }
            callbacks.printOutput("=== 保存完成 ===");
        } catch (IOException e) {
            callbacks.printError("保存错误关键字失败: " + e.getMessage());
        }
    }
    
    /**
     * 测试错误关键字检测 - 调试方法
     */
    public boolean testErrorKeywordDetection(String testString) {
        callbacks.printOutput("=== 测试错误关键字检测 ===");
        callbacks.printOutput("测试字符串: " + testString);
        callbacks.printOutput("关键字数量: " + errorKeywords.size());
        
        if (errorKeywords.isEmpty()) {
            callbacks.printOutput("错误关键字列表为空");
            return false;
        }
        
        for (String keyword : errorKeywords) {
            try {
                boolean matched = false;
                
                // 检查是否是正则表达式模式
                if (keyword.contains("\\") || keyword.contains(".*") || keyword.contains("\\d") || 
                    keyword.contains("[") || keyword.contains("]") || keyword.contains("^") || keyword.contains("$")) {
                    // 正则表达式匹配
                    try {
                        matched = testString.matches(".*" + keyword + ".*");
                        callbacks.printOutput("  正则匹配 '" + keyword + "': " + matched);
                    } catch (Exception regexException) {
                        // 正则表达式错误，降级为普通字符串匹配
                        matched = testString.toLowerCase().contains(keyword.toLowerCase());
                        callbacks.printOutput("  正则失败，普通匹配 '" + keyword + "': " + matched);
                    }
                } else {
                    // 普通字符串匹配（不区分大小写）
                    matched = testString.toLowerCase().contains(keyword.toLowerCase());
                
                }
                
                if (matched) {
                    callbacks.printOutput("✓ 匹配成功: " + keyword);
                    return true;
                }
            } catch (Exception e) {
                callbacks.printOutput("  匹配异常 '" + keyword + "': " + e.getMessage());
            }
        }
        
        callbacks.printOutput("未匹配到任何关键字");
        callbacks.printOutput("=== 测试完成 ===");
        return false;
    }
    
    /**
     * 测试阈值配置 - 调试方法
     */
    public void testThresholdConfiguration() {
        callbacks.printOutput("=== 测试阈值配置 ===");
        callbacks.printOutput("响应时间阈值: " + responseTimeThreshold + "毫秒 (" + (responseTimeThreshold/1000.0) + "秒)");
        callbacks.printOutput("长度差异阈值: " + lengthDiffThreshold + "字节");
        
        // 测试时间阈值检测
        long testTime1 = 1500; // 1.5秒
        long testTime2 = 3000; // 3秒
        boolean time1Exceeded = testTime1 >= responseTimeThreshold;
        boolean time2Exceeded = testTime2 >= responseTimeThreshold;
        
        callbacks.printOutput("测试时间1: " + testTime1 + "ms -> 超过阈值: " + time1Exceeded);
        callbacks.printOutput("测试时间2: " + testTime2 + "ms -> 超过阈值: " + time2Exceeded);
        
        // 测试长度差异检测
        int testDiff1 = 50;  // 50字节差异
        int testDiff2 = 150; // 150字节差异
        boolean diff1Exceeded = Math.abs(testDiff1) >= lengthDiffThreshold;
        boolean diff2Exceeded = Math.abs(testDiff2) >= lengthDiffThreshold;
        
        callbacks.printOutput("测试长度差异1: " + testDiff1 + "字节 -> 超过阈值: " + diff1Exceeded);
        callbacks.printOutput("测试长度差异2: " + testDiff2 + "字节 -> 超过阈值: " + diff2Exceeded);
        callbacks.printOutput("=== 阈值测试完成 ===");
    }
    
    // Getter方法
    public String getConfigDirectory() { return configDirectory; }
    public int getResponseTimeThreshold() { return responseTimeThreshold; }
    public int getRequestTimeout() { return requestTimeout; } // 请求超时时间(毫秒)
    public int getLengthDiffThreshold() { return lengthDiffThreshold; }
    public List<String> getErrorKeywords() { return new ArrayList<>(errorKeywords); }
    public List<String> getWhitelistParams() { return new ArrayList<>(whitelistParams); }
    public List<String> getBlacklistParams() { return new ArrayList<>(blacklistParams); }
    public int getParamFilterMode() { return paramFilterMode; }
    
    // 延时配置getter
    public int getDelayMode() { return delayMode; }
    public int getFixedDelay() { return fixedDelay; }
    public int getRandomDelayMin() { return randomDelayMin; }
    public int getRandomDelayMax() { return randomDelayMax; }
    
    // 追加参数配置getter
    public boolean isAppendParamsEnabled() { return appendParamsEnabled; }
    public Map<String, String> getAppendParams() { return new HashMap<>(appendParams); }
    public Set<String> getTestableAppendParams() { return new HashSet<>(testableAppendParams); }
    
    // URL黑名单配置getter
    public List<String> getUrlBlacklist() { return new ArrayList<>(urlBlacklist); }
    
    // Setter方法
    public void setResponseTimeThreshold(int threshold) { this.responseTimeThreshold = threshold; }
    public void setLengthDiffThreshold(int threshold) { this.lengthDiffThreshold = threshold; }
    public void setParamFilterMode(int mode) { this.paramFilterMode = mode; }
    
    /**
     * 保存参数过滤配置
     */
    public void saveParamFilterConfig(int mode, List<String> whitelistParams, List<String> blacklistParams) {
        this.paramFilterMode = mode;
        this.whitelistParams.clear();
        this.whitelistParams.addAll(whitelistParams);
        this.blacklistParams.clear();
        this.blacklistParams.addAll(blacklistParams);
        
        // 保存到文件
        saveParamFilterMode();
        saveParamList(this.whitelistParams, "/xia_SQL_whitelist.ini");
        saveParamList(this.blacklistParams, "/xia_SQL_blacklist.ini");
        
        callbacks.printOutput("参数过滤配置已保存: 模式=" + mode + 
                            ", 白名单=" + this.whitelistParams.size() + "个" +
                            ", 黑名单=" + this.blacklistParams.size() + "个");
    }
    
    /**
     * 保存参数过滤模式
     */
    private void saveParamFilterMode() {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(
                configDirectory + "/xia_SQL_param_filter_mode.ini"))) {
            writer.write(String.valueOf(paramFilterMode));
        } catch (IOException e) {
            callbacks.printError("保存参数过滤模式失败: " + e.getMessage());
        }
    }
    
    /**
     * 保存参数列表到文件
     */
    private void saveParamList(List<String> list, String filename) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(configDirectory + filename))) {
            for (String param : list) {
                writer.write(param);
                writer.newLine();
            }
        } catch (IOException e) {
            callbacks.printError("保存参数列表失败 [" + filename + "]: " + e.getMessage());
        }
    }
    
    /**
     * 加载延时配置 - 不从文件加载，始终使用默认值（无延时）
     */
    private void loadDelayConfig() {
        // 延时配置不持久化，始终使用默认值
        delayMode = 0; // 默认无延时
        fixedDelay = 1000;
        randomDelayMin = 1000;
        randomDelayMax = 5000;
        
        callbacks.printOutput("延时配置初始化: 模式=0(无延时), 固定延时=" + fixedDelay + "ms (仅内存配置，不持久化)");
    }
    
    /**
     * 设置延时配置 - 仅内存配置，不持久化
     */
    public void setDelayConfig(int mode, int fixed, int minRandom, int maxRandom) {
        this.delayMode = mode;
        this.fixedDelay = fixed;
        this.randomDelayMin = minRandom;
        this.randomDelayMax = maxRandom;
        
        callbacks.printOutput("延时配置已更新（仅内存）: 模式=" + mode + ", 固定延时=" + fixed + "ms");
    }
    
    /**
     * 加载追加参数配置 - 简化版本，不从文件加载，默认禁用
     */
    private void loadAppendParamsConfig() {
        // 追加参数功能默认禁用，不进行持久化
        appendParamsEnabled = false;
        appendParams.clear();
        testableAppendParams.clear();
        
        // callbacks.printOutput("=== 追加参数配置初始化 ===");
        // callbacks.printOutput("追加参数功能默认禁用（不持久化保存）");
        // callbacks.printOutput("启用状态: " + appendParamsEnabled);
        // callbacks.printOutput("参数数量: " + appendParams.size());
        // callbacks.printOutput("可测试参数数量: " + testableAppendParams.size());
        // callbacks.printOutput("=== 追加参数配置初始化完成 ===");
    }
    
    /**
     * 加载URL黑名单配置
     */
    private void loadUrlBlacklist() {
        urlBlacklist.clear();
        
        try (BufferedReader reader = new BufferedReader(new FileReader(
                configDirectory + "/xia_SQL_blacklist_urls.ini"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("#")) {
                    urlBlacklist.add(line);
                }
            }
           // callbacks.printOutput("已加载URL黑名单，共" + urlBlacklist.size() + "条");
        } catch (Exception e) {
            callbacks.printOutput("URL黑名单配置文件不存在或读取失败，使用默认配置");
            // 使用默认黑名单
            loadDefaultUrlBlacklist();
        }
    }
    
    /**
     * 加载默认URL黑名单
     */
    private void loadDefaultUrlBlacklist() {
        urlBlacklist.addAll(Arrays.asList(
            "*/admin/*",
            "*/static/*",
            "*/assets/*",
            "*/js/*",
            "*/css/*",
            "*/images/*",
            "*/upload/*",
            "*/download/*",
            "*.jpg",
            "*.png",
            "*.gif",
            "*.css",
            "*.js",
            "*.ico",
            "*.woff*"
        ));
    }
    
    /**
     * 设置追加参数配置 - 仅内存配置，不持久化
     */
    public void saveAppendParamsConfig(boolean enabled, Map<String, String> params, Set<String> testableParams) {
        callbacks.printOutput("=== 保存追加参数配置 ===");
        callbacks.printOutput("请求启用状态: " + enabled);
        callbacks.printOutput("请求参数数量: " + params.size());
        callbacks.printOutput("请求可测试参数数量: " + testableParams.size());
        
        this.appendParamsEnabled = enabled;
        this.appendParams.clear();
        this.appendParams.putAll(params);
        this.testableAppendParams.clear();
        this.testableAppendParams.addAll(testableParams);
        
        callbacks.printOutput("实际启用状态: " + this.appendParamsEnabled);
        callbacks.printOutput("实际参数数量: " + this.appendParams.size());
        callbacks.printOutput("实际可测试参数数量: " + this.testableAppendParams.size());
        
        if (!this.appendParams.isEmpty()) {
            callbacks.printOutput("参数详情:");
            for (Map.Entry<String, String> entry : this.appendParams.entrySet()) {
                boolean isTestable = this.testableAppendParams.contains(entry.getKey());
                callbacks.printOutput("  " + entry.getKey() + "=" + entry.getValue() + " (可测试: " + isTestable + ")");
            }
        }
        
        callbacks.printOutput("追加参数配置已更新（仅内存，不持久化）: 启用=" + enabled + 
                            ", 参数=" + params.size() + "个" +
                            ", 可测试=" + testableParams.size() + "个");
        callbacks.printOutput("=== 保存追加参数配置完成 ===");
    }
    
    /**
     * 清除追加参数配置 - 重置为默认状态
     */
    public void clearAppendParamsConfig() {
        this.appendParamsEnabled = false;
        this.appendParams.clear();
        this.testableAppendParams.clear();
        
        callbacks.printOutput("追加参数配置已清除，恢复默认禁用状态");
    }
    
    /**
     * 强制禁用追加参数功能 - 临时修复方法
     */
    public void forceDisableAppendParams() {
        callbacks.printOutput("=== 强制禁用追加参数功能 ===");
        
        // 清除内存配置
        this.appendParamsEnabled = false;
        this.appendParams.clear();
        this.testableAppendParams.clear();
        
        // 强制删除或重写配置文件
        try {
            // 重写启用状态文件
            File enabledFile = new File(configDirectory + "/xia_SQL_append_params_enabled.ini");
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(enabledFile))) {
                writer.write("false");
            }
            callbacks.printOutput("已强制设置启用状态为false");
            
            // 重写参数文件
            File paramsFile = new File(configDirectory + "/xia_SQL_append_params.ini");
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(paramsFile))) {
                writer.write("# 追加参数功能已强制禁用\n");
                writer.write("# 如需启用，请通过UI配置面板操作\n");
            }
            callbacks.printOutput("已清空参数配置文件");
            
            // 重写可测试参数文件
            File testableFile = new File(configDirectory + "/xia_SQL_append_params_testable.ini");
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(testableFile))) {
                writer.write("# 追加参数功能已强制禁用\n");
            }
            callbacks.printOutput("已清空可测试参数文件");
            
        } catch (Exception e) {
            callbacks.printError("强制禁用失败: " + e.getMessage());
        }
        
        callbacks.printOutput("=== 强制禁用完成 ===");
        callbacks.printOutput("请重启Burp Suite以确保配置生效");
    }
    
    /**
     * 保存URL黑名单配置
     */
    public void saveUrlBlacklist(List<String> blacklistUrls) {
        this.urlBlacklist.clear();
        this.urlBlacklist.addAll(blacklistUrls);
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(
                configDirectory + "/xia_SQL_blacklist_urls.ini"))) {
            writer.write("# URL黑名单配置文件 - 只匹配URL路径部分，不匹配域名");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# 规则说明：");
            writer.newLine();
            writer.write("# 1. 文件扩展名匹配（以*.开头）：");
            writer.newLine();
            writer.write("#    *.js    - 匹配所有.js文件（如 /path/file.js）");
            writer.newLine();
            writer.write("#    *.css   - 匹配所有.css文件");
            writer.newLine();
            writer.write("#    *.png   - 匹配所有.png图片");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# 2. 路径前缀匹配（以/开头）：");
            writer.newLine();
            writer.write("#    /admin/*        - 匹配/admin/下的所有路径");
            writer.newLine();
            writer.write("#    /static/*       - 匹配/static/下的所有路径");
            writer.newLine();
            writer.write("#    /api/v1/public/* - 匹配/api/v1/public/下的所有路径");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# 3. 路径包含匹配（包含/但不以/开头）：");
            writer.newLine();
            writer.write("#    /images/*.jpg - 匹配/images/目录下的所有jpg文件");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# 4. 简单包含匹配（不包含/）：");
            writer.newLine();
            writer.write("#    logout - 匹配路径中包含logout的URL");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# 注意：");
            writer.newLine();
            writer.write("# - 黑名单只匹配URL的路径部分，不会匹配域名");
            writer.newLine();
            writer.write("# - 例如：*.js 不会匹配 xxx.jsxxx.com 域名");
            writer.newLine();
            writer.write("# - 例如：*.si 不会匹配 sina.com 域名");
            writer.newLine();
            writer.write("# ");
            writer.newLine();
            writer.write("# 默认黑名单示例：");
            writer.newLine();
            writer.write("# /admin/*");
            writer.newLine();
            writer.write("# /static/*");
            writer.newLine();
            writer.write("# *.css");
            writer.newLine();
            writer.write("# *.js");
            writer.newLine();
            writer.write("# *.jpg");
            writer.newLine();
            writer.write("# *.png");
            writer.newLine();
            writer.write("# *.gif");
            writer.newLine();
            writer.newLine();
            
            for (String url : blacklistUrls) {
                if (!url.trim().isEmpty() && !url.trim().startsWith("#")) {
                    writer.write(url.trim());
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            callbacks.printError("保存URL黑名单配置失败: " + e.getMessage());
        }
        
        callbacks.printOutput("URL黑名单配置已保存: " + blacklistUrls.size() + "条规则");
    }
    
}