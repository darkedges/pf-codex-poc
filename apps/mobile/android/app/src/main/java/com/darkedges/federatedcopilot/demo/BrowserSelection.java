package com.darkedges.federatedcopilot.demo;
import java.util.ArrayList;import java.util.List;import java.util.LinkedHashSet;

/** Only system-described, exported generic HTTPS browser activities are eligible. */
final class BrowserSelection {
    static final class Candidate {
        final String packageName;final boolean browser,exported,enabled;
        Candidate(String packageName,boolean browser,boolean exported,boolean enabled){this.packageName=packageName;this.browser=browser;this.exported=exported;this.enabled=enabled;}
    }
    static boolean genericHttps(boolean https,int authorities,int paths,int specificParts){return https&&authorities==0&&paths==0&&specificParts==0;}
    static List<String> packages(List<Candidate> candidates,String ownPackage){
        LinkedHashSet<String> packages=new LinkedHashSet<>();
        for(Candidate c:candidates)if(c!=null&&c.browser&&c.exported&&c.enabled&&c.packageName!=null&&c.packageName.matches("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")&&!"android".equals(c.packageName)&&!c.packageName.equals(ownPackage))packages.add(c.packageName);
        return new ArrayList<>(packages);
    }
}
