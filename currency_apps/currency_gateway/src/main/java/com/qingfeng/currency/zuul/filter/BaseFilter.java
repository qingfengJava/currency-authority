package com.qingfeng.currency.zuul.filter;

import cn.hutool.core.util.StrUtil;
import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.qingfeng.currency.base.R;
import com.qingfeng.currency.common.adapter.IgnoreTokenConfig;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;

import javax.servlet.http.HttpServletRequest;

/**
 * 基础网关过滤器
 *
 * @author 清风学Java
 * @version 1.0.0
 * @date 2022/9/19
 */
@Slf4j
public abstract class BaseFilter extends ZuulFilter {

    /**
     * 动态的获取请求路径  /api
     */
    @Value("${server.servlet.context-path}")
    protected String zuulPrefix;

    /**
     * 判断当前请求uri是否需要忽略（直接放行）
     */
    protected boolean isIgnoreToken() {
        //动态获取当前的url
        HttpServletRequest request =
                RequestContext.getCurrentContext().getRequest();
        String uri = request.getRequestURI();
        uri = StrUtil.subSuf(uri, zuulPrefix.length());
        uri = StrUtil.subSuf(uri, uri.indexOf("/", 1));
        boolean ignoreToken = IgnoreTokenConfig.isIgnoreToken(uri);
        return ignoreToken;
    }

    /**
     * 网关抛异常，不再进行路由，而是直接返回到前端
     * @param errMsg
     * @param errCode
     * @param httpStatusCode
     */
    protected void errorResponse(String errMsg, int errCode, int httpStatusCode) {
        R tokenError = R.fail(errCode, errMsg);
        RequestContext ctx = RequestContext.getCurrentContext();
        // 返回错误码
        ctx.setResponseStatusCode(httpStatusCode);
        ctx.addZuulResponseHeader(
                "Content-Type", "application/json;charset=UTF-8");
        if (ctx.getResponseBody() == null) {
            // 返回错误内容
            ctx.setResponseBody(tokenError.toString());
            // 过滤该请求，不对其进行路由
            ctx.setSendZuulResponse(false);
        }
    }
}
