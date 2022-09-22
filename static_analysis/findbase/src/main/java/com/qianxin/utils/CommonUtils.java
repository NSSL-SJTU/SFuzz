package com.qianxin.utils;

import java.util.UUID;

public class CommonUtils {

    public static String createUUID() {
        String uuid = UUID.randomUUID().toString();
        uuid = uuid.replace("-", "");

        return uuid;
    }
}
