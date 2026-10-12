package com.local.privatevault;

import android.app.Activity;
import android.os.Bundle;
import android.os.Build;
import android.os.Handler;
import android.os.Looper;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebResourceResponse;
import android.webkit.JavascriptInterface;
import android.webkit.WebSettings;
import android.widget.FrameLayout;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowInsets;
import android.view.WindowInsetsController;
import android.graphics.Insets;
import android.graphics.Color;
import android.content.Context;
import android.content.MutableContextWrapper;
import android.content.Intent;
import android.content.ClipboardManager;
import android.content.ClipData;
import android.net.Uri;
import android.util.AtomicFile;
import android.util.Base64;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import org.json.JSONObject;
import org.json.JSONArray;
import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.charset.CodingErrorAction;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.*;
import java.util.function.Consumer;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class MainActivity extends Activity {
    private static final String ORIGIN="https://appassets.androidplatform.net";
    private static final String PAGE=ORIGIN+"/assets/ui/index.html";
    private static final int LIMIT=8*1024*1024;
    private static final int CIPHERTEXT_LIMIT=4*1024*1024;
    private static final int IMPORT_DOCUMENT=4101, EXPORT_DOCUMENT=4102;
    private Session session;

    @Override public void onCreate(Bundle state){
        super.onCreate(state);
        Object retained=getLastNonConfigurationInstance();
        session=retained instanceof Session?(Session)retained:new Session(getApplicationContext());
        session.activity=this;
        FrameLayout frame=new FrameLayout(this);frame.setBackgroundColor(Color.rgb(245,246,243));
        if(session.webView==null){
            session.webContext=new MutableContextWrapper(this);
            session.webView=new WebView(session.webContext);
            WebSettings settings=session.webView.getSettings();
            settings.setJavaScriptEnabled(true);settings.setDomStorageEnabled(false);
            settings.setAllowFileAccess(false);settings.setAllowContentAccess(false);
            settings.setMixedContentMode(WebSettings.MIXED_CONTENT_NEVER_ALLOW);settings.setCacheMode(WebSettings.LOAD_NO_CACHE);
            settings.setJavaScriptCanOpenWindowsAutomatically(false);settings.setSupportMultipleWindows(false);
            WebView.setWebContentsDebuggingEnabled(false);
            session.webView.addJavascriptInterface(new Bridge(session),"AndroidVault");
        } else {
            session.webContext.setBaseContext(this);
            ViewGroup parent=(ViewGroup)session.webView.getParent();if(parent!=null)parent.removeView(session.webView);
        }
        frame.addView(session.webView,new FrameLayout.LayoutParams(-1,-1));setContentView(frame);
        getWindow().setStatusBarColor(Color.rgb(245,246,243));getWindow().setNavigationBarColor(Color.rgb(245,246,243));
        if(Build.VERSION.SDK_INT>=30){
            getWindow().setDecorFitsSystemWindows(false);
            frame.setOnApplyWindowInsetsListener((view,insets)->{Insets bounds=insets.getInsets(WindowInsets.Type.systemBars()|WindowInsets.Type.displayCutout()|WindowInsets.Type.ime());view.setPadding(bounds.left,bounds.top,bounds.right,bounds.bottom);return insets;});
            WindowInsetsController controller=getWindow().getInsetsController();
            if(controller!=null)controller.setSystemBarsAppearance(WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS|WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS,WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS|WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS);
        } else {frame.setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR|View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);}
        session.webView.setWebViewClient(new WebViewClient(){
            @Override public boolean shouldOverrideUrlLoading(WebView view,WebResourceRequest request){return !request.isForMainFrame() || !PAGE.equals(request.getUrl().toString());}
            @Override public void onPageStarted(WebView view,String url,android.graphics.Bitmap favicon){session.pageReady=false;}
            @Override public void onPageFinished(WebView view,String url){
                if(!PAGE.equals(url) || !PAGE.equals(view.getUrl()))return;
                // evaluateJavascript runs in the main frame; subframes never receive this capability.
                view.evaluateJavascript("window.__vaultInstallHost&&window.__vaultInstallHost("+JSONObject.quote(session.bridgeNonce)+")",ignored->{session.pageReady=true;session.flushReplies();});
            }
            @Override public WebResourceResponse shouldInterceptRequest(WebView view,WebResourceRequest request){
                Uri uri=request.getUrl();if(!isLocalAsset(uri))return blocked();
                String relative=uri.getPath().substring("/assets/".length());
                if(relative.endsWith(".html") && (!request.isForMainFrame() || !"ui/index.html".equals(relative)))return blocked();
                try{
                    String mime=relative.endsWith(".html")?"text/html":relative.endsWith(".js")?"text/javascript":relative.endsWith(".css")?"text/css":"image/svg+xml";
                    Map<String,String> headers=new HashMap<>();headers.put("Cache-Control","no-store");
                    headers.put("Content-Security-Policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'none'; frame-src 'none'; child-src 'none'; worker-src 'none'; frame-ancestors 'none'; object-src 'none'; base-uri 'none'; form-action 'none'");
                    return new WebResourceResponse(mime,"UTF-8",200,"OK",headers,getAssets().open(relative));
                }catch(Exception error){return blocked();}
            }
        });
        if(session.webView.getUrl()==null)session.webView.loadUrl(PAGE);
        session.flushUiActions();session.flushReplies();
    }

    private static boolean isLocalAsset(Uri u){String p=u.getPath();return "https".equals(u.getScheme()) && "appassets.androidplatform.net".equals(u.getHost()) && u.getPort()==-1 && u.getQuery()==null && u.getUserInfo()==null && p!=null && !p.contains("..") && !p.contains("\\") && (p.startsWith("/assets/ui/")||p.startsWith("/assets/core/"));}
    private static WebResourceResponse blocked(){return new WebResourceResponse("text/plain","UTF-8",403,"Forbidden",Collections.emptyMap(),new ByteArrayInputStream(new byte[0]));}
    private static byte[] readBytes(InputStream input,int limit)throws IOException{
        if(input==null)throw new IOException("文件无法读取");
        try(InputStream stream=input;ByteArrayOutputStream output=new ByteArrayOutputStream()){byte[] buf=new byte[8192];int count;while((count=stream.read(buf))!=-1){if(output.size()+count>limit)throw new IOException("数据过大");output.write(buf,0,count);}return output.toByteArray();}
    }
    private static String utf8(byte[] bytes)throws IOException{return StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT).onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();}
    private static String readText(InputStream input)throws IOException{return utf8(readBytes(input,LIMIT));}
    private static JSONObject cloneObject(JSONObject value)throws Exception{return new JSONObject(value.toString());}
    private static void exact(JSONObject value,String...fields)throws IOException{
        if(value.length()!=fields.length)throw new IOException("数据格式无效");
        for(String field:fields)if(!value.has(field))throw new IOException("数据格式无效");
    }
    private static String string(JSONObject value,String field)throws Exception{Object item=value.get(field);if(!(item instanceof String))throw new IOException("数据格式无效");return (String)item;}
    private static boolean validId(String value){return value.matches("[A-Za-z0-9_-]{1,80}") && !Arrays.asList("__proto__","prototype","constructor").contains(value);}
    private static byte[] base64(JSONObject value,String field,int minimum,int maximum)throws Exception{
        String encoded=string(value,field);
        if(encoded.length()==0 || encoded.length()%4!=0 || encoded.length()>((maximum+2)/3)*4 || !encoded.matches("[A-Za-z0-9+/]*={0,2}"))throw new IOException("加密数据格式无效");
        byte[] bytes=Base64.decode(encoded,Base64.NO_WRAP);
        if(bytes.length<minimum || bytes.length>maximum || !Base64.encodeToString(bytes,Base64.NO_WRAP).equals(encoded))throw new IOException("加密数据格式无效");return bytes;
    }
    private static JSONObject validateConfig(JSONObject value)throws Exception{
        // deviceLabel is display metadata supplied by the Host, never persisted.
        if(value.has("deviceLabel")){value=cloneObject(value);value.remove("deviceLabel");}
        exact(value,"vaultId","keyB64","token","endpoint","mode");
        if(!validId(string(value,"vaultId")) || !string(value,"token").matches("[A-Za-z0-9_-]{20,200}"))throw new IOException("配置无效");
        base64(value,"keyB64",32,32);
        String mode=string(value,"mode");if(!Arrays.asList("file","server").contains(mode))throw new IOException("同步模式无效");
        if(!value.isNull("endpoint")){
            String endpoint=string(value,"endpoint");if(endpoint.length()>2048)throw new IOException("地址过长");URI uri=new URI(endpoint);
            if(!"https".equals(uri.getScheme()) || uri.getHost()==null || uri.getUserInfo()!=null || uri.getQuery()!=null || uri.getFragment()!=null || (uri.getPort()!=-1 && (uri.getPort()<1 || uri.getPort()>65535)) || (!uri.getRawPath().equals("")&&!uri.getRawPath().equals("/")))throw new IOException("需要 HTTPS 根地址");
        }
        // A server-mode profile may be unconfigured. Core keeps it offline until an endpoint is supplied.
        return cloneObject(value);
    }
    private static void validateEnvelope(JSONObject envelope,String vaultId)throws Exception{
        exact(envelope,"v","vaultId","alg","nonce","data");Object version=envelope.get("v");String actualId=string(envelope,"vaultId");
        if(!(version instanceof Number) || ((Number)version).doubleValue()!=1 || !"A256GCM".equals(string(envelope,"alg")) || !validId(actualId) || (vaultId!=null&&!vaultId.equals(actualId)))throw new IOException("密文格式无效");
        base64(envelope,"nonce",12,12);base64(envelope,"data",16,CIPHERTEXT_LIMIT);
    }
    private static void validateLocal(JSONObject value,String vaultId)throws Exception{
        exact(value,"deviceId","envelope");if(!validId(string(value,"deviceId")))throw new IOException("设备标识无效");validateEnvelope(value.getJSONObject("envelope"),vaultId);
        if(value.toString().getBytes(StandardCharsets.UTF_8).length>LIMIT)throw new IOException("本地数据过大");
    }
    private static JSONObject decryptVault(JSONObject envelope,JSONObject profile)throws Exception{
        String vaultId=string(profile,"vaultId");validateEnvelope(envelope,vaultId);
        Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,new SecretKeySpec(base64(profile,"keyB64",32,32),"AES"),new GCMParameterSpec(128,base64(envelope,"nonce",12,12)));
        cipher.updateAAD(("private-vault/v1/"+vaultId).getBytes(StandardCharsets.UTF_8));byte[] plain=cipher.doFinal(base64(envelope,"data",16,CIPHERTEXT_LIMIT));
        if(plain.length>CIPHERTEXT_LIMIT-16)throw new IOException("密码库过大");JSONObject vault=new JSONObject(utf8(plain));exact(vault,"schema","vaultId","records");
        Object schema=vault.get("schema");if(!(schema instanceof Number) || ((Number)schema).doubleValue()!=1 || !vaultId.equals(string(vault,"vaultId")) || !(vault.get("records") instanceof JSONObject))throw new IOException("密码库无法验证");return vault;
    }

    /** Only the state executor mutates this store. Network requests take a committed profile snapshot. */
    private static final class Store {
        private static final String KEY_ALIAS="private-vault-profile-v2";
        private static final byte[] PROFILE_AAD="private-vault/android/profile/v2".getBytes(StandardCharsets.UTF_8);
        private final AtomicFile stateFile,legacyFile;
        private volatile JSONObject config;
        private JSONObject local;
        private boolean loaded;
        Store(Context context){stateFile=new AtomicFile(new File(context.getFilesDir(),"state.json"));legacyFile=new AtomicFile(new File(context.getFilesDir(),"vault.json"));}
        private SecretKey key(boolean create)throws Exception{
            KeyStore store=KeyStore.getInstance("AndroidKeyStore");store.load(null);java.security.Key existing=store.getKey(KEY_ALIAS,null);if(existing instanceof SecretKey)return (SecretKey)existing;
            if(!create)throw new IOException("本地保护密钥无法读取");KeyGenerator generator=KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES,"AndroidKeyStore");
            generator.init(new KeyGenParameterSpec.Builder(KEY_ALIAS,KeyProperties.PURPOSE_ENCRYPT|KeyProperties.PURPOSE_DECRYPT).setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(false).build());return generator.generateKey();
        }
        private JSONObject wrap(JSONObject value)throws Exception{
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.ENCRYPT_MODE,key(true));cipher.updateAAD(PROFILE_AAD);
            return new JSONObject().put("v",1).put("nonce",Base64.encodeToString(cipher.getIV(),Base64.NO_WRAP)).put("data",Base64.encodeToString(cipher.doFinal(value.toString().getBytes(StandardCharsets.UTF_8)),Base64.NO_WRAP));
        }
        private JSONObject unwrap(JSONObject value)throws Exception{
            exact(value,"v","nonce","data");Object v=value.get("v");if(!(v instanceof Number)||((Number)v).doubleValue()!=1)throw new IOException("保护格式无效");
            Cipher cipher=Cipher.getInstance("AES/GCM/NoPadding");cipher.init(Cipher.DECRYPT_MODE,key(false),new GCMParameterSpec(128,base64(value,"nonce",12,12)));cipher.updateAAD(PROFILE_AAD);
            return validateConfig(new JSONObject(utf8(cipher.doFinal(base64(value,"data",16,8192)))));
        }
        private boolean exists(AtomicFile file){return file.getBaseFile().exists() || new File(file.getBaseFile().getPath()+".bak").exists() || new File(file.getBaseFile().getPath()+".new").exists();}
        private void load()throws Exception{
            if(loaded)return;
            if(exists(stateFile)){
                JSONObject value=new JSONObject(readText(stateFile.openRead()));exact(value,"schema","profile","local");Object schema=value.get("schema");if(!(schema instanceof Number)||((Number)schema).doubleValue()!=2)throw new IOException("本地状态格式无效");
                JSONObject nextConfig=unwrap(value.getJSONObject("profile"));JSONObject nextLocal=value.isNull("local")?null:value.getJSONObject("local");if(nextLocal!=null)validateLocal(nextLocal,string(nextConfig,"vaultId"));config=nextConfig;local=nextLocal;
            }else if(exists(legacyFile)){
                // Never generate a replacement key for a pre-v2 encrypted library.
                local=new JSONObject(readText(legacyFile.openRead()));validateLocal(local,null);config=null;
            }else{
                SecureRandom random=new SecureRandom();byte[] aes=new byte[32],token=new byte[32];random.nextBytes(aes);random.nextBytes(token);
                JSONObject fresh=new JSONObject().put("vaultId",UUID.randomUUID().toString()).put("keyB64",Base64.encodeToString(aes,Base64.NO_WRAP)).put("token",Base64.encodeToString(token,Base64.URL_SAFE|Base64.NO_WRAP|Base64.NO_PADDING)).put("endpoint",JSONObject.NULL).put("mode","file");commit(validateConfig(fresh),null);
            }
            loaded=true;
        }
        private void commit(JSONObject nextConfig,JSONObject nextLocal)throws Exception{
            JSONObject state=new JSONObject().put("schema",2).put("profile",wrap(nextConfig)).put("local",nextLocal==null?JSONObject.NULL:nextLocal);byte[] bytes=state.toString().getBytes(StandardCharsets.UTF_8);if(bytes.length>LIMIT)throw new IOException("本地数据过大");FileOutputStream stream=null;
            try{stream=stateFile.startWrite();stream.write(bytes);stateFile.finishWrite(stream);}catch(Exception error){if(stream!=null)stateFile.failWrite(stream);throw new IOException("本地保存失败，请重试");}
            // Profile and ciphertext become visible together only after the atomic commit.
            config=cloneObject(nextConfig);local=nextLocal==null?null:cloneObject(nextLocal);
        }
        JSONObject getConfig()throws Exception{load();return config==null?null:cloneObject(config).put("deviceLabel","Android");}
        JSONObject readLocal()throws Exception{load();return local==null?null:cloneObject(local);}
        void writeLocal(JSONObject value)throws Exception{load();if(config==null)throw new IOException("请先恢复旧密码库");writeState(config,value);}
        void writeState(JSONObject nextConfig,JSONObject nextLocal)throws Exception{
            load();nextConfig=validateConfig(nextConfig);validateLocal(nextLocal,string(nextConfig,"vaultId"));
            // Never persist ciphertext that cannot be opened with its committed profile.
            decryptVault(nextLocal.getJSONObject("envelope"),nextConfig);
            if(local!=null){
                if(!string(local,"deviceId").equals(string(nextLocal,"deviceId")))throw new IOException("不能替换本机设备标识");
                if(config==null){
                    if(!string(nextConfig,"vaultId").equals(string(local.getJSONObject("envelope"),"vaultId")))throw new IOException("导入文件不属于旧密码库");
                    // Prove the recovery key can open the existing ciphertext before migration.
                    decryptVault(local.getJSONObject("envelope"),nextConfig);
                }else if(string(config,"vaultId").equals(string(nextConfig,"vaultId"))){
                    if(!string(config,"keyB64").equals(string(nextConfig,"keyB64")))throw new IOException("不能替换现有密码库的密钥");
                }else{
                    JSONObject oldVault=decryptVault(local.getJSONObject("envelope"),config);
                    if(oldVault.getJSONObject("records").length()!=0)throw new IOException("已有记录或删除标记，不能替换密码库");
                }
            }
            commit(nextConfig,cloneObject(nextLocal));legacyFile.delete();
        }
        JSONObject network(String method,String route,Object body)throws Exception{
            JSONObject current=config;if(current==null || !"server".equals(string(current,"mode")))throw new IOException("当前为文件同步模式");current=cloneObject(current);
            if(current.isNull("endpoint"))throw new IOException("云同步地址未配置");
            if(!Arrays.asList("GET","PUT").contains(method) || !"/v1/vault".equals(route))throw new IOException("无效同步请求");if("GET".equals(method) && body!=null && body!=JSONObject.NULL)throw new IOException("GET 请求不能包含数据");byte[] bytes=null;
            if("PUT".equals(method)){
                if(!(body instanceof JSONObject))throw new IOException("密文请求无效");JSONObject data=(JSONObject)body;exact(data,"expectedRevision","envelope");Object revision=data.get("expectedRevision");
                if(!(revision instanceof Number) || ((Number)revision).doubleValue()<0 || ((Number)revision).doubleValue()>9007199254740991d || Math.floor(((Number)revision).doubleValue())!=((Number)revision).doubleValue())throw new IOException("版本号无效");validateEnvelope(data.getJSONObject("envelope"),string(current,"vaultId"));bytes=data.toString().getBytes(StandardCharsets.UTF_8);if(bytes.length>LIMIT)throw new IOException("同步请求过大");
            }
            URL target=new URL(new URL(string(current,"endpoint")),route);HttpURLConnection connection=(HttpURLConnection)target.openConnection();
            try{connection.setConnectTimeout(10000);connection.setReadTimeout(10000);connection.setInstanceFollowRedirects(false);connection.setRequestMethod(method);connection.setRequestProperty("Authorization","Bearer "+string(current,"token"));connection.setRequestProperty("Content-Type","application/json");if(bytes!=null){connection.setDoOutput(true);connection.setFixedLengthStreamingMode(bytes.length);try(OutputStream output=connection.getOutputStream()){output.write(bytes);}}
                int status=connection.getResponseCode();if(status>=300 && status<400)throw new IOException("同步地址发生重定向");InputStream input=status>=400?connection.getErrorStream():connection.getInputStream();String text=input==null?"{}":readText(input);return new JSONObject().put("status",status).put("body",new JSONObject(text.isEmpty()?"{}":text));
            }finally{connection.disconnect();}
        }
    }

    private static final class Choice {final int id,kind;final String text;Choice(int id,int kind,String text){this.id=id;this.kind=kind;this.text=text;}}
    /** Keep the WebView and its JS Promises across Activity recreation, including an open picker. */
    private static final class Session {
        final Store store;final Handler handler=new Handler(Looper.getMainLooper());final ExecutorService stateExecutor=Executors.newSingleThreadExecutor(),networkExecutor=Executors.newFixedThreadPool(2);final String bridgeNonce;
        final List<JSONObject> replies=new ArrayList<>();final List<Consumer<MainActivity>> uiActions=new ArrayList<>();volatile MainActivity activity;WebView webView;MutableContextWrapper webContext;Choice choice;boolean pageReady,closed;
        Session(Context context){store=new Store(context);byte[] nonce=new byte[32];new SecureRandom().nextBytes(nonce);bridgeNonce=Base64.encodeToString(nonce,Base64.NO_WRAP);}
        void ui(Consumer<MainActivity> action){handler.post(()->{if(closed)return;MainActivity a=activity;if(a==null)uiActions.add(action);else action.accept(a);});}
        void flushUiActions(){if(activity==null)return;List<Consumer<MainActivity>> queued=new ArrayList<>(uiActions);uiActions.clear();for(Consumer<MainActivity> action:queued)action.accept(activity);}
        void reply(int id,Object value,String error){try{JSONObject result=new JSONObject().put("id",id).put("value",value==null?JSONObject.NULL:value).put("error",error==null?JSONObject.NULL:error);handler.post(()->{if(!closed){replies.add(result);flushReplies();}});}catch(Exception ignored){}}
        void flushReplies(){if(activity==null || !pageReady || webView==null || !PAGE.equals(webView.getUrl()))return;List<JSONObject> queued=new ArrayList<>(replies);replies.clear();for(JSONObject result:queued){String data=result.toString().replace("\u2028","\\u2028").replace("\u2029","\\u2029");webView.evaluateJavascript("window.__vaultNativeResponse&&window.__vaultNativeResponse("+data+")",null);}}
    }
    public static final class Bridge {
        private final Session session;Bridge(Session session){this.session=session;}
        @JavascriptInterface public void request(String text){
            int requestId=-1;
            try{
                if(text==null || text.length()>2*LIMIT+4096)throw new IOException("请求过大");JSONObject data=new JSONObject(text);
                // addJavascriptInterface is visible in every frame, so require the main-frame capability.
                if(!MessageDigest.isEqual(string(data,"bridgeNonce").getBytes(StandardCharsets.UTF_8),session.bridgeNonce.getBytes(StandardCharsets.UTF_8)))return;
                requestId=data.getInt("id");if(requestId<0)throw new IOException("请求无效");String method=string(data,"method");JSONArray args=data.getJSONArray("args");final int id=requestId;final JSONArray values=args;
                if(method.equals("chooseImportFile") || method.equals("saveExportFile")){
                    final String value=method.equals("saveExportFile")?values.getString(0):null;if(value!=null && value.getBytes(StandardCharsets.UTF_8).length>LIMIT)throw new IOException("导出文件过大");session.ui(a->a.chooseDocument(id,method.equals("chooseImportFile")?IMPORT_DOCUMENT:EXPORT_DOCUMENT,value));return;
                }
                if(method.equals("copyText") || method.equals("openExternal")){
                    final String value=values.getString(0);session.ui(a->{try{if(method.equals("copyText")){if(value.length()>20000)throw new IOException("复制内容过大");ClipboardManager manager=(ClipboardManager)a.getSystemService(CLIPBOARD_SERVICE);if(manager==null)throw new IOException("剪贴板不可用");manager.setPrimaryClip(ClipData.newPlainText("密码",value));}else{Uri uri=Uri.parse(value);if(!Arrays.asList("https","http").contains(uri.getScheme()) || uri.getUserInfo()!=null || uri.getHost()==null)throw new IOException("链接无效");a.startActivity(new Intent(Intent.ACTION_VIEW,uri));}session.reply(id,null,null);}catch(Exception error){session.reply(id,null,"操作未完成，请重试");}});return;
                }
                ExecutorService executor=method.equals("request")?session.networkExecutor:session.stateExecutor;
                executor.execute(()->{try{Object value;switch(method){case "getConfig":value=session.store.getConfig();break;case "readLocal":value=session.store.readLocal();break;case "writeLocal":session.store.writeLocal(values.getJSONObject(0));value=null;break;case "writeState":session.store.writeState(values.getJSONObject(0),values.getJSONObject(1));value=null;break;case "request":value=session.store.network(values.getString(0),values.getString(1),values.opt(2));break;default:throw new IOException("无效操作");}session.reply(id,value,null);}catch(Exception error){String message=method.equals("request")?"联网同步未完成，请检查模式、网络或服务器配置":method.equals("writeLocal")||method.equals("writeState")?"本地保存或旧库验证失败，原数据已保留":"本地密码库无法读取，已停止以防覆盖数据";session.reply(id,null,message);}});
            }catch(Exception error){if(requestId>=0)session.reply(requestId,null,"请求无法处理");}
        }
    }
    private void chooseDocument(int id,int kind,String text){
        if(session.choice!=null){session.reply(id,null,"请先完成当前文件选择");return;}
        Intent intent=new Intent(kind==IMPORT_DOCUMENT?Intent.ACTION_OPEN_DOCUMENT:Intent.ACTION_CREATE_DOCUMENT);intent.addCategory(Intent.CATEGORY_OPENABLE);
        if(kind==IMPORT_DOCUMENT){intent.setType("*/*");intent.putExtra(Intent.EXTRA_MIME_TYPES,new String[]{"application/json","text/plain","application/octet-stream"});intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);}
        else{intent.setType("application/json");intent.putExtra(Intent.EXTRA_TITLE,"PrivateVault.pvault");intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION);}
        session.choice=new Choice(id,kind,text);try{startActivityForResult(intent,kind);}catch(Exception error){session.choice=null;session.reply(id,null,"系统文件选择器无法打开");}
    }
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){
        super.onActivityResult(requestCode,resultCode,data);Choice current=session.choice;if(current==null || current.kind!=requestCode)return;session.choice=null;
        if(resultCode!=RESULT_OK || data==null || data.getData()==null){session.reply(current.id,current.kind==EXPORT_DOCUMENT?false:null,null);return;}
        Uri uri=data.getData();if(!"content".equals(uri.getScheme())){session.reply(current.id,null,"请选择系统文件提供器中的文件");return;}final Context context=getApplicationContext();
        session.stateExecutor.execute(()->{try{if(current.kind==IMPORT_DOCUMENT){session.reply(current.id,readText(context.getContentResolver().openInputStream(uri)),null);}else{byte[] bytes=current.text.getBytes(StandardCharsets.UTF_8);if(bytes.length>LIMIT)throw new IOException("导出文件过大");try(OutputStream output=context.getContentResolver().openOutputStream(uri,"wt")){if(output==null)throw new IOException("文件无法写入");output.write(bytes);output.flush();}session.reply(current.id,true,null);}}catch(Exception error){session.reply(current.id,null,current.kind==IMPORT_DOCUMENT?"文件无法读取、不是 UTF-8 或超过 8 MiB":"文件未能完整导出，请重试");}});
    }
    @Override public Object onRetainNonConfigurationInstance(){return session;}
    @Override protected void onResume(){super.onResume();if(session!=null && session.webView!=null && PAGE.equals(session.webView.getUrl()))session.webView.evaluateJavascript("window.dispatchEvent(new Event('vault-resume'))",null);}
    @Override public void onBackPressed(){if(session==null || session.webView==null){super.onBackPressed();return;}session.webView.evaluateJavascript("window.dispatchEvent(new Event('vault-back',{cancelable:true}))",value->{if("true".equals(value)||"null".equals(value))finish();});}
    @Override protected void onDestroy(){if(session!=null){if(session.activity==this)session.activity=null;if(isChangingConfigurations()){session.webContext.setBaseContext(getApplicationContext());}else{session.closed=true;session.stateExecutor.shutdown();session.networkExecutor.shutdownNow();session.choice=null;session.replies.clear();session.uiActions.clear();if(session.webView!=null){session.webView.removeJavascriptInterface("AndroidVault");session.webView.destroy();}}}super.onDestroy();}
}
