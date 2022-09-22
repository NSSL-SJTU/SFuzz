package com.qianxin.core;

import com.qianxin.utils.ColoredPrint;
import com.qianxin.utils.CommonUtils;
import ghidra.GhidraApplicationLayout;
import ghidra.GhidraJarApplicationLayout;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.util.importer.AutoImporter;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.Application;
import ghidra.framework.LoggingInitialization;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.framework.data.TransientDataManager;
import ghidra.framework.model.DomainFile;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectLocator;
import ghidra.framework.project.DefaultProjectManager;
import ghidra.framework.store.LockException;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Language;
import ghidra.program.model.lang.LanguageID;
import ghidra.program.model.listing.Program;
import ghidra.program.util.DefaultLanguageService;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.util.task.TaskMonitor;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class ProgramInfo {

    private Program program;
    private String filename;
    private Project project;
    private DomainFolder domainFolder;
    private AutoAnalysisManager mgr;
    private boolean isCreate;
    private boolean isWrite;
    private boolean isSingle;
    private ProjectLocator locator;

    public Program getProgram() {
        return program;
    }

    public ProgramInfo(String filePath, String languageId, Long baseAddr, String projectFileName, boolean isCreate, boolean isWrite, String projectPath) throws IOException {

        this.isCreate = isCreate;
        this.isWrite = isWrite;

        try {
            filePath = new File(filePath).getCanonicalPath();
        } catch (IOException e) {
            ColoredPrint.errorPrint("Get absolute dir path failed.");
            System.exit(1);
        }


        ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();

        if (!Application.isInitialized()) {

            try{
                Application.initializeApplication(getApplicationLayout(),configuration);
            } catch (Exception e) {
                //Unparseable date: "01-Jan-1904 00:00:00"
                //just ignore
            }
            LoggingInitialization.initializeLoggingSystem();
        }

        HeadlessGhidraProjectManager projectManager = new HeadlessGhidraProjectManager();

        File rawFile = new File(filePath);


        if (projectFileName == null) {
            this.isSingle = true;
            Path finalProjectPath =  Files.createTempDirectory(CommonUtils.createUUID());
            if (isCreate) {
                if (projectPath != null) {
                    File pf = new File(projectPath);
                    if (!pf.exists()) {
                        pf.mkdirs();
                    }
                    finalProjectPath = pf.toPath();
                } else {
                    File tmpDir = new File("tmp");
                    if (!tmpDir.exists()) {
                        tmpDir.mkdir();
                    }
                    finalProjectPath = tmpDir.toPath();
                }
            }
            this.filename = rawFile.getName();
            File projectDir = finalProjectPath.toFile();
            this.locator = new ProjectLocator(projectDir.getAbsolutePath(), this.filename);
            this.project = projectManager.createProject(locator,null,false);
            this.domainFolder = project.getProjectData().getRootFolder();


            try {
                MessageLog messageLog = new MessageLog();

                if(languageId == null || languageId.equals("")) {
   
                    program = AutoImporter.importByUsingBestGuess(rawFile, null, this, messageLog, TaskMonitor.DUMMY);
                } else {
                    Language language = DefaultLanguageService.getLanguageService().getLanguage(new LanguageID(languageId));
                    program = AutoImporter.importByLookingForLcs(rawFile, null, language, language.getDefaultCompilerSpec(), this,
                            messageLog, TaskMonitor.DUMMY);
                }
            }catch (Exception e) {
                System.out.println("Error when import binary.");
                System.exit(1);
            }

            if (baseAddr != null) {
                Address address = new FlatProgramAPI(program).toAddr(baseAddr);
                int txId = program.startTransaction("ChangeImageBase");
                try {
                    program.setImageBase(address, true);
                } catch (Exception e) {
                    System.out.println(String.format("Set Image base failed."));
                    System.exit(1);
                }finally {
                    program.endTransaction(txId, true);
                }
            }

            mgr = AutoAnalysisManager.getAnalysisManager(program);
            mgr.initializeOptions();

            // Start a new transaction in order to make changes to this domain object.
            int txId = program.startTransaction("Analysis");
            try{

                mgr.reAnalyzeAll(null);
 
                mgr.startAnalysis(TaskMonitor.DUMMY);
                GhidraProgramUtilities.setAnalyzedFlag(program, true);
            }finally {
                program.endTransaction(txId, true);
            }
        } else {
            this.isSingle = false;

            this.filename = projectFileName;
            String projectDir = rawFile.getParent();
            String projectName = rawFile.getName();

            projectName = projectName.substring(0,projectName.lastIndexOf("."));
            this.locator = new ProjectLocator(projectDir, projectName);
            try {
                this.project = projectManager.openProject(locator,true,false);
                this.domainFolder = project.getProjectData().getRootFolder();
                this.program = (Program)domainFolder.getFile(filename).getDomainObject(this,true,false, TaskMonitor.DUMMY);
            } catch (LockException e) {
                System.out.println("Project is used by other ghidra instance.");
                System.exit(1);
            } catch (Exception e) {
                System.out.println("Error when open ghidra project.");
                System.exit(1);
            }
        }
    }


    public void close() {
        if (this.isCreate) {
            try {
                DomainFile df = domainFolder.createFile(filename, program, TaskMonitor.DUMMY);
                df.save(TaskMonitor.DUMMY);
                project.save();
            } catch (Exception e) {
                e.printStackTrace();
                this.isCreate = false;
            }
        }

        if (!this.isSingle && this.isWrite) {
            try {
                DomainFile df = this.program.getDomainFile();
                df.save(TaskMonitor.DUMMY);
                project.save();
            } catch (Exception e) {
                e.printStackTrace();
                this.isCreate = false;
            }
        }

        List<DomainFile> domainFileContainer = new ArrayList<>();
        TransientDataManager.getTransients(domainFileContainer);
        if (domainFileContainer.size() > 0) {
            TransientDataManager.releaseFiles(this);
        }

        if (mgr != null) {
            mgr.dispose();
        }

        this.project.close();
        try {
            if (!isCreate && this.isSingle) {
                FileUtils.deleteDirectory(locator.getProjectDir());
                locator.getMarkerFile().delete();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private GhidraApplicationLayout getApplicationLayout() throws IOException {
        GhidraApplicationLayout layout;
        try {
            layout = new GhidraApplicationLayout();
        }
        catch (IOException e) {
            layout = new GhidraJarApplicationLayout();

        }
        return layout;
    }


    private static class HeadlessGhidraProjectManager extends DefaultProjectManager {
        // this exists just to allow access to the constructor
    }
}
