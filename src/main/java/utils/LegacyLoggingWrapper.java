package utils;

import burp.IBurpExtenderCallbacks;

/**
 * Legacy API日志包装器
 * 将Legacy Burp API的日志功能包装成Montoya API兼容的接口
 */
public class LegacyLoggingWrapper {
    private final IBurpExtenderCallbacks callbacks;
    
    public LegacyLoggingWrapper(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
    }
    
    /**
     * 输出普通日志
     */
    public void logToOutput(String message) {
        callbacks.printOutput(message);
    }
    
    /**
     * 输出错误日志
     */
    public void logToError(String message) {
        callbacks.printError(message);
    }
}