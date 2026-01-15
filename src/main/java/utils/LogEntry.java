package utils;

import burp.IHttpRequestResponse;

/**
 * 日志条目类
 * 用于存储扫描结果和Payload测试详情
 * 3.0.5版本更新：支持保存修复后的中文参数值和正确的工具来源标识
 * 3.0.7版本更新：支持更新扫描结果的响应长度
 */
public class LogEntry {
    private final int id;
    private final String url;
    private final String parameter;
    private final String payload; // 在3.0.5版本中，这里保存的是workingValue（修复后的完整值）
    private final String dataMd5;
    private String state; // 改为可变，支持更新状态
    private final String change;
    private int responseLength; // 改为可变，支持更新响应长度
    private final int responseTime;
    private final String statusCode;
    private final String timestamp;
    private final IHttpRequestResponse requestResponse;
    private final int parameterCount;
    private final int toolFlag; // 保存真实的工具来源标识
    
    // 构造函数 - 扫描结果
    public LogEntry(int id, String url, String state, int parameterCount, String timestamp, 
                   IHttpRequestResponse requestResponse, String dataMd5, int toolFlag) {
        this.id = id;
        this.url = url;
        this.state = state;
        this.parameterCount = parameterCount;
        this.timestamp = timestamp;
        this.requestResponse = requestResponse;
        this.dataMd5 = dataMd5;
        this.toolFlag = toolFlag; // 保存真实的工具标识
        
        // Payload相关字段设为默认值
        this.parameter = "";
        this.payload = "";
        this.change = "";
        this.responseLength = 0;
        this.responseTime = 0;
        this.statusCode = "";
    }
    
    // 构造函数 - Payload详情（3.0.5版本更新）
    public LogEntry(int id, String parameter, String workingValue, String change, 
                   int responseLength, int responseTime, String statusCode,
                   IHttpRequestResponse requestResponse, String dataMd5, int toolFlag) {
        this.id = id;
        this.parameter = parameter;
        this.payload = workingValue; // 保存完整的工作值（修复后的原值+payload）
        this.change = change;
        this.responseLength = responseLength;
        this.responseTime = responseTime;
        this.statusCode = statusCode;
        this.requestResponse = requestResponse;
        this.dataMd5 = dataMd5;
        this.toolFlag = toolFlag; // 保存真实的工具标识
        
        // 扫描结果相关字段设为默认值
        this.url = "";
        this.state = "";
        this.parameterCount = 0;
        this.timestamp = "";
    }
    
    // Getter方法
    public int getId() { return id; }
    public String getUrl() { return url; }
    public String getParameter() { return parameter; }
    public String getPayload() { return payload; } // 3.0.5版本：返回完整的工作值
    public String getDataMd5() { return dataMd5; }
    public String getState() { return state; }
    public String getChange() { return change; }
    public int getResponseLength() { return responseLength; }
    public int getResponseTime() { return responseTime; }
    public String getStatusCode() { return statusCode; }
    public String getTimestamp() { return timestamp; }
    public IHttpRequestResponse getRequestResponse() { return requestResponse; }
    public int getParameterCount() { return parameterCount; }
    public int getToolFlag() { return toolFlag; } // 返回真实的工具标识
    
    // Setter方法 - 3.0.7版本新增
    public void setState(String state) { this.state = state; }
    public void setResponseLength(int responseLength) { this.responseLength = responseLength; }
    
    /**
     * 获取工具来源名称
     * 基于daimabak.txt中的实现
     */
    public String getToolName() {
        switch (toolFlag) {
            case 4: return "Proxy";
            case 16: return "Scanner";
            case 32: return "Intruder";
            case 64: return "Repeater";
            case 1024: return "Menu";
            default: return String.valueOf(toolFlag);
        }
    }
    
    /**
     * 获取显示用的payload值
     * 3.0.5版本新增：用于UI显示，确保中文字符正确显示
     */
    public String getDisplayPayload() {
        if (payload == null) return "";
        
        // 如果payload过长，截取显示
        if (payload.length() > 100) {
            return payload.substring(0, 97) + "...";
        }
        
        return payload;
    }
}