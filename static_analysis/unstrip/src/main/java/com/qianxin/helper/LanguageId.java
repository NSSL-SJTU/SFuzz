package com.qianxin.helper;

import java.lang.annotation.*;

@Target(ElementType.TYPE)   
@Retention(RetentionPolicy.RUNTIME) 
public @interface LanguageId {
    String processor() default "x86";
    int size() default 32;
}