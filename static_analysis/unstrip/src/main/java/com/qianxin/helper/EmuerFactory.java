package com.qianxin.helper;

import com.qianxin.identifier.BaseFunc;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ConfigurationBuilder;

import java.lang.reflect.Constructor;
import java.util.HashSet;
import java.util.Set;

public class EmuerFactory {

    public static Class<BaseEmuer> buildEmuer(Program program, Set<Class<?>> emuClasses) {
        String langIdStr = program.getLanguageID().getIdAsString();
        //like ARM:LE:32:v7
        String[] langIdDetails = langIdStr.split(":");
        String arch = langIdDetails[0];
        int pointerSize = Integer.parseInt(langIdDetails[2]);

        for(Class<?> item: emuClasses) {
            if (BaseEmuer.class.isAssignableFrom(item)) {
                Class<BaseEmuer> realClass = (Class<BaseEmuer>) item;
                LanguageId langIdAnno = realClass.getAnnotation(LanguageId.class);

                if (langIdAnno.processor().compareToIgnoreCase(arch) == 0
                        && langIdAnno.size() == pointerSize) {
                    return realClass;
                }
            }
        }
        return null;
    }
}
