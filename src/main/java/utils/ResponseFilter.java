package utils;

import burp.IBurpExtenderCallbacks;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import config.ResponseFilterConfig;
import config.ResponseFilterConfig.FilterCondition;
import config.ResponseFilterConfig.FilterType;
import config.ResponseFilterConfig.CompareOperator;

import java.util.List;

/**
 * 响应过滤器
 */
public class ResponseFilter {
    private final IBurpExtenderCallbacks callbacks;
    private final IExtensionHelpers helpers;
    
    public ResponseFilter(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
        this.callbacks = callbacks;
        this.helpers = helpers;
    }
    
    /**
     * 检查响应是否符合过滤条件
     * @param requestResponse HTTP请求响应对象
     * @param config 响应过滤配置
     * @return true 如果符合条件（应该进行测试），false 如果不符合条件（跳过测试）
     */
    public boolean shouldProcessResponse(IHttpRequestResponse requestResponse, ResponseFilterConfig config) {
        if (!config.isEnabled()) {
            return true; // 过滤器未启用，允许所有响应
        }
        
        if (requestResponse.getResponse() == null) {
            callbacks.printOutput("响应为空，跳过过滤检查");
            return false;
        }
        
        List<FilterCondition> conditions = config.getConditions();
        if (conditions.isEmpty()) {
            return true; // 没有配置条件，允许所有响应
        }
        
        callbacks.printOutput("=== 响应过滤检查开始 ===");
        callbacks.printOutput("过滤模式: " + (config.isMatchAll() ? "所有条件都满足(AND)" : "任一条件满足(OR)"));
        
        boolean result;
        if (config.isMatchAll()) {
            // AND 模式：所有启用的条件都必须满足
            result = checkAllConditions(requestResponse, conditions);
        } else {
            // OR 模式：任一启用的条件满足即可
            result = checkAnyCondition(requestResponse, conditions);
        }
        
        callbacks.printOutput("响应过滤结果: " + (result ? "通过" : "不通过"));
        callbacks.printOutput("=== 响应过滤检查结束 ===");
        
        return result;
    }
    
    /**
     * 检查所有条件（AND 模式）
     */
    private boolean checkAllConditions(IHttpRequestResponse requestResponse, List<FilterCondition> conditions) {
        int enabledCount = 0;
        int passedCount = 0;
        
        for (FilterCondition condition : conditions) {
            if (!condition.isEnabled()) {
                continue;
            }
            
            enabledCount++;
            boolean conditionResult = checkSingleCondition(requestResponse, condition);
            callbacks.printOutput("条件检查: " + condition.toString() + " -> " + (conditionResult ? "通过" : "不通过"));
            
            if (conditionResult) {
                passedCount++;
            } else {
                // AND 模式下，任一条件不满足就返回 false
                callbacks.printOutput("AND 模式：条件不满足，停止检查");
                return false;
            }
        }
        
        callbacks.printOutput("AND 模式：" + passedCount + "/" + enabledCount + " 条件通过");
        return enabledCount > 0 && passedCount == enabledCount;
    }
    
    /**
     * 检查任一条件（OR 模式）
     */
    private boolean checkAnyCondition(IHttpRequestResponse requestResponse, List<FilterCondition> conditions) {
        int enabledCount = 0;
        int passedCount = 0;
        
        for (FilterCondition condition : conditions) {
            if (!condition.isEnabled()) {
                continue;
            }
            
            enabledCount++;
            boolean conditionResult = checkSingleCondition(requestResponse, condition);
            callbacks.printOutput("条件检查: " + condition.toString() + " -> " + (conditionResult ? "通过" : "不通过"));
            
            if (conditionResult) {
                passedCount++;
                // OR 模式下，任一条件满足就返回 true
                callbacks.printOutput("OR 模式：条件满足，通过检查");
                return true;
            }
        }
        
        callbacks.printOutput("OR 模式：" + passedCount + "/" + enabledCount + " 条件通过");
        return false;
    }
    
    /**
     * 检查单个条件
     */
    private boolean checkSingleCondition(IHttpRequestResponse requestResponse, FilterCondition condition) {
        try {
            switch (condition.getType()) {
                case STATUS_CODE:
                    return checkStatusCode(requestResponse, condition);
                case RESPONSE_HEADER:
                    return checkResponseHeader(requestResponse, condition);
                case RESPONSE_BODY:
                    return checkResponseBody(requestResponse, condition);
                case RESPONSE_SIZE:
                    return checkResponseSize(requestResponse, condition);
                default:
                    callbacks.printError("未知的过滤条件类型: " + condition.getType());
                    return false;
            }
        } catch (Exception e) {
            callbacks.printError("检查条件时发生异常: " + e.getMessage());
            return false;
        }
    }
    
    /**
     * 检查状态码条件
     */
    private boolean checkStatusCode(IHttpRequestResponse requestResponse, FilterCondition condition) {
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
        int actualStatusCode = responseInfo.getStatusCode();
        
        try {
            int expectedStatusCode = Integer.parseInt(condition.getValue());
            return compareNumbers(actualStatusCode, expectedStatusCode, condition.getOperator());
        } catch (NumberFormatException e) {
            callbacks.printError("状态码条件值格式错误: " + condition.getValue());
            return false;
        }
    }
    
    /**
     * 检查响应头条件
     */
    private boolean checkResponseHeader(IHttpRequestResponse requestResponse, FilterCondition condition) {
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
        List<String> headers = responseInfo.getHeaders();
        
        String headerName = condition.getHeaderName();
        if (headerName == null || headerName.trim().isEmpty()) {
            callbacks.printError("响应头条件缺少头名称");
            return false;
        }
        
        String headerValue = null;
        for (String header : headers) {
            if (header.toLowerCase().startsWith(headerName.toLowerCase() + ":")) {
                headerValue = header.substring(headerName.length() + 1).trim();
                break;
            }
        }
        
        if (headerValue == null) {
            // 头不存在的情况
            return condition.getOperator() == CompareOperator.NOT_EQUALS || 
                   condition.getOperator() == CompareOperator.NOT_CONTAINS;
        }
        
        return compareStrings(headerValue, condition.getValue(), condition.getOperator());
    }
    
    /**
     * 检查响应体条件
     */
    private boolean checkResponseBody(IHttpRequestResponse requestResponse, FilterCondition condition) {
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
        int bodyOffset = responseInfo.getBodyOffset();
        
        if (bodyOffset >= requestResponse.getResponse().length) {
            // 没有响应体
            return condition.getOperator() == CompareOperator.NOT_EQUALS || 
                   condition.getOperator() == CompareOperator.NOT_CONTAINS;
        }
        
        String responseBody = new String(requestResponse.getResponse(), bodyOffset, 
                                       requestResponse.getResponse().length - bodyOffset);
        
        return compareStrings(responseBody, condition.getValue(), condition.getOperator());
    }
    
    /**
     * 检查响应大小条件
     */
    private boolean checkResponseSize(IHttpRequestResponse requestResponse, FilterCondition condition) {
        IResponseInfo responseInfo = helpers.analyzeResponse(requestResponse.getResponse());
        int bodyOffset = responseInfo.getBodyOffset();
        int actualSize = requestResponse.getResponse().length - bodyOffset; // 只计算响应体大小
        
        try {
            int expectedSize = Integer.parseInt(condition.getValue());
            return compareNumbers(actualSize, expectedSize, condition.getOperator());
        } catch (NumberFormatException e) {
            callbacks.printError("响应大小条件值格式错误: " + condition.getValue());
            return false;
        }
    }
    
    /**
     * 比较数字
     */
    private boolean compareNumbers(int actual, int expected, CompareOperator operator) {
        switch (operator) {
            case EQUALS:
                return actual == expected;
            case NOT_EQUALS:
                return actual != expected;
            case GREATER_THAN:
                return actual > expected;
            case LESS_THAN:
                return actual < expected;
            case GREATER_EQUAL:
                return actual >= expected;
            case LESS_EQUAL:
                return actual <= expected;
            default:
                callbacks.printError("数字比较不支持的操作符: " + operator);
                return false;
        }
    }
    
    /**
     * 比较字符串
     */
    private boolean compareStrings(String actual, String expected, CompareOperator operator) {
        if (actual == null) actual = "";
        if (expected == null) expected = "";
        
        switch (operator) {
            case EQUALS:
                return actual.equals(expected);
            case NOT_EQUALS:
                return !actual.equals(expected);
            case CONTAINS:
                return actual.contains(expected);
            case NOT_CONTAINS:
                return !actual.contains(expected);
            default:
                callbacks.printError("字符串比较不支持的操作符: " + operator);
                return false;
        }
    }
}