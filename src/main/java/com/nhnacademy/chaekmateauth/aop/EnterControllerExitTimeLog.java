package com.nhnacademy.chaekmateauth.aop;

import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import shop.chaekmate.common.log.logging.Log;

@Aspect
@Component
public class EnterControllerExitTimeLog {
    @Around("@within(org.springframework.web.bind.annotation.RestController) && within(com.nhnacademy.chaekmateauth..*)")
    public Object logControllerExecutionTime(ProceedingJoinPoint joinPoint) throws Throwable {
        long start = System.currentTimeMillis();
        String className = joinPoint.getSignature().getDeclaringType().getSimpleName();
        String methodName = joinPoint.getSignature().getName();

        Log.InfoWithClassMethod(className, methodName, "traffic: methodName:{}", methodName);

        Object result = joinPoint.proceed();

        Long responseTime = System.currentTimeMillis() - start;
        Log.ResponseTimeWithClassMethod(responseTime, className, methodName, "responseTime: methodName:{}", methodName);
        return result;
    }
}
