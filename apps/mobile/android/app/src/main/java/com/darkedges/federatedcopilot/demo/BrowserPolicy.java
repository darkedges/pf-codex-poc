package com.darkedges.federatedcopilot.demo;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Base64;

final class BrowserPolicy {
    private BrowserPolicy() {}
    private static String decode(String value) {
        try { return URLDecoder.decode(value, StandardCharsets.UTF_8.name()); }
        catch(Exception ignored) { throw new IllegalArgumentException("invalid_browser_link"); }
    }
    private static URI uri(String value) {
        try {
            if(value==null || value.length()>4096) throw new IllegalArgumentException();
            URI u=new URI(value);
            if(!"https".equals(u.getScheme()) || u.getRawUserInfo()!=null || u.getRawFragment()!=null || u.getPort()!=-1) throw new IllegalArgumentException();
            return u;
        } catch(Exception ignored) { throw new IllegalArgumentException("invalid_browser_link"); }
    }
    static String authorization(String value) {
        URI u=uri(value);
        if(!"pf-a.copilot.darkedges.com".equals(u.getHost()) || !"/as/authorization.oauth2".equals(u.getRawPath())) throw new IllegalArgumentException();
        HashMap<String,String> query=new HashMap<>();
        if(u.getRawQuery()==null) throw new IllegalArgumentException();
        for(String part:u.getRawQuery().split("&",-1)) {
            String[] pair=part.split("=",2); if(pair.length!=2) throw new IllegalArgumentException();
            String name=decode(pair[0]), text=decode(pair[1]);
            if(query.put(name,text)!=null) throw new IllegalArgumentException();
        }
        if(query.size()!=2 || !query.containsKey("client_id") || !query.containsKey("request_uri") || !query.get("client_id").matches("[A-Za-z0-9_.-]{1,128}") || !query.get("request_uri").matches("urn:[A-Za-z0-9:._~-]{1,1024}")) throw new IllegalArgumentException();
        return value;
    }
    static String handoff(String value) {
        URI u=uri(value);
        if(!"agent.copilot.darkedges.com".equals(u.getHost()) || !"/mobile/return".equals(u.getRawPath()) || u.getRawQuery()==null || !u.getRawQuery().matches("handoff=[A-Za-z0-9_-]{43}")) throw new IllegalArgumentException();
        String code=u.getRawQuery().substring(8);
        if(!PendingLogin.encode(Base64.getUrlDecoder().decode(code)).equals(code)) throw new IllegalArgumentException();
        return code;
    }
}
