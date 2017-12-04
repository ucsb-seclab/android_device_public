package com.example.login_defense;

import android.content.ComponentName;
import android.content.ContentProvider;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.os.Binder;
import android.os.Bundle;
import android.os.SystemClock;
import android.os.UserHandle;
import android.telephony.SmsMessage;
import android.util.Log;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import android.content.pm.Signature;

import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import de.robv.android.xposed.IXposedHookLoadPackage;
import de.robv.android.xposed.XC_MethodHook;
import de.robv.android.xposed.XposedBridge;
import de.robv.android.xposed.callbacks.XC_LoadPackage;


public class XposedHook implements IXposedHookLoadPackage {

    public static String TAG = "LOGIN_DEFENSE";

    @Override
    public void handleLoadPackage(XC_LoadPackage.LoadPackageParam loadedPackage) throws Throwable {

        String pname = loadedPackage.appInfo.packageName;
        String dexname = loadedPackage.packageName;
        ClassLoader classloader = loadedPackage.classLoader;
        String current_cl_name = String.valueOf(pname) + ":" + String.valueOf(dexname)+ ":" + String.valueOf(classloader);

        try {
            Class loaded_class;
            loaded_class = classloader.loadClass("com.android.providers.settings.SettingsProvider");
            XposedBridge.hookAllMethods(loaded_class,"call",new AndroidIDHook());

        }catch(ClassNotFoundException e){
            ;
        }

        try {
            Class loaded_class;
            loaded_class = classloader.loadClass("com.android.internal.telephony.InboundSmsHandler");
            XposedBridge.hookAllMethods(loaded_class, "dispatchIntent", new SMSDispatcherHook());
        }catch(ClassNotFoundException e){
            ;
        }

        try {
            Class loaded_class;
            loaded_class = classloader.loadClass("com.android.providers.telephony.SmsProvider");
            Set s = XposedBridge.hookAllMethods(loaded_class, "query", new SMSProviderHook());
        }catch(ClassNotFoundException e){
            ;
        }

    }


    private static String limitStr(String str){
        int len = str.length();
        int max_len = 100;
        if(len > max_len){
            len = max_len;
        }
        str = str.substring(0, len);
        return str;
    }

    private static String objToString(Object o){
        if(o==null){
            return "null";
        }
        String tstr = String.valueOf(o.getClass())+":"+String.valueOf(o);
        if(o != null){
            if(o.getClass().getName().equals("[B")){
                byte[] casted = (byte[])o;
                tstr += " (length="+String.valueOf(casted.length)+")";
            }
        }
        return tstr;
    }


    public class SMSProviderHook extends XC_MethodHook {
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG, "===> SMSProviderHook hooked method called: " + param.method);

            //----------
            long time1 = SystemClock.elapsedRealtimeNanos();

            Method caller_method = param.thisObject.getClass().getSuperclass().getMethod("getCallingPackage", new Class[]{});
            String pname = (String) caller_method.invoke(param.thisObject, new Object[]{});
            //Log.d(TAG,"caller:" + pname);

            Method context_method = param.thisObject.getClass().getSuperclass().getMethod("getContext", new Class[]{});
            Context cx = (Context) context_method.invoke(param.thisObject, new Object[]{});
            PackageManager pm = cx.getPackageManager();
            PackageInfo pi = pm.getPackageInfo(pname, PackageManager.GET_SIGNATURES);
            String fingerprint = bytesToHex(getCertificateSHA1Fingerprint(pi));
            param.args[2] = "((body not like 'AUTHCODE:%') or (body like 'AUTHCODE: " + fingerprint + "%'))";

            long time2 = SystemClock.elapsedRealtimeNanos();
            Log.d(TAG, "time: " + String.valueOf(time2 - time1));
            //----------
        }

        //https://stackoverflow.com/questions/9293019/get-certificate-fingerprint-from-android-app
        private byte[] getCertificateSHA1Fingerprint(PackageInfo packageInfo) {
            Signature[] signatures = packageInfo.signatures;
            byte[] cert = signatures[0].toByteArray();
            InputStream input = new ByteArrayInputStream(cert);
            CertificateFactory cf = null;
            try {
                cf = CertificateFactory.getInstance("X509");
            } catch (CertificateException e) {
                e.printStackTrace();
            }
            X509Certificate c = null;
            try {
                c = (X509Certificate) cf.generateCertificate(input);
            } catch (CertificateException e) {
                e.printStackTrace();
            }
            byte[] publicKey = null;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA1");
                publicKey = md.digest(c.getEncoded());
                //hexString = byte2HexFormatted(publicKey);
            } catch (NoSuchAlgorithmException e1) {
                e1.printStackTrace();
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            }
            return publicKey;
        }
    }


    public class SMSDispatcherHook extends XC_MethodHook {
        private String SMSTAG = "AUTHCODE: ";
        private Map<String,String> fingerprintMap = null;

        void setFingerprintMap(PackageManager pm){
            List<PackageInfo> packages = pm.getInstalledPackages(PackageManager.GET_META_DATA | PackageManager.GET_SIGNATURES);
            fingerprintMap = new HashMap<>();

            for (PackageInfo packageInfo : packages) {
                String fingerprint = bytesToHex(getCertificateSHA1Fingerprint(packageInfo));
                //Log.d(TAG, "Installed package :" + packageInfo.packageName + " fingerprint: " + fingerprint);
                if(! packageInfo.packageName.equals("com.example.login_defense")){
                    fingerprintMap.put(fingerprint, packageInfo.packageName);
                }
            }
        }

        @Override
        protected void beforeHookedMethod(MethodHookParam param) throws Throwable {
            Log.d(TAG, "===> hooked method called: " + param.method);

            //----------
            long time1= SystemClock.elapsedRealtimeNanos();
            long time2;
            if(fingerprintMap == null){
                Class this_class = param.thisObject.getClass().getClassLoader().loadClass("com.android.internal.telephony.InboundSmsHandler");
                Field ff = null;
                for(Field f : this_class.getDeclaredFields()){
                    if(f.getName().equals("mContext")){
                        ff = f;
                        ff.setAccessible(true);
                        break;
                    }
                }
                Context cx = (Context) ff.get(param.thisObject);
                PackageManager pm = cx.getPackageManager();
                setFingerprintMap(pm);
            }

            Intent ii = new Intent((Intent) param.args[0]);
            if(ii.getComponent()==null){
                time2 = SystemClock.elapsedRealtimeNanos();
                Log.d(TAG, "time: " + String.valueOf(time2 - time1));
                return;
            }

            Bundle extras = ii.getExtras();
            Object[] pdus = (Object[]) extras.get("pdus");
            SmsMessage mm = SmsMessage.createFromPdu((byte[]) pdus[0]);
            String text = mm.getMessageBody();
            String code = null;
            if(text.startsWith(SMSTAG)){
                code = text.substring(SMSTAG.length(),SMSTAG.length()+40+1).trim();
            }else{
                time2 = SystemClock.elapsedRealtimeNanos();
                Log.d(TAG, "time: " + String.valueOf(time2 - time1));
                return;
            }
            String pname = fingerprintMap.get(code);
            ii.setPackage(pname);
            param.args[0] = ii;
            time2 = SystemClock.elapsedRealtimeNanos();
            Log.d(TAG, "time: " + String.valueOf(time2 - time1));
            //----------
        }
    }

    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    public class AndroidIDHook extends XC_MethodHook {
        @Override
        protected void afterHookedMethod(MethodHookParam param) throws Throwable {
            if(!param.args[1].equals("android_id")){
                return;
            }
            Log.d(TAG,"===> hooked method called: "+param.method);

            //-----------
            long time1= SystemClock.elapsedRealtimeNanos();

            int uid = Binder.getCallingUid();
            //Log.d(TAG,"caller: " + String.valueOf(Binder.getCallingUid()));

            Context cx = ((ContentProvider)param.thisObject).getContext();
            PackageManager pm = cx.getPackageManager();
            String caller_pname = pm.getPackagesForUid(uid)[0];
            //Log.d(TAG, "caller_pname: " + String.valueOf(caller_pname));

            int flags = PackageManager.GET_SIGNATURES;
            PackageInfo packageInfo = null;
            try {
                packageInfo = pm.getPackageInfo(caller_pname, flags);
            } catch (PackageManager.NameNotFoundException e) {
                e.printStackTrace();
            }
            if((packageInfo.applicationInfo.flags & ApplicationInfo.FLAG_SYSTEM) != 0){
                Log.d(TAG,"system package");
                return;
            }

            byte[] sig = getCertificateSHA1Fingerprint(packageInfo);
            Bundle boriginal = (Bundle) param.getResult();
            String serial_hmac = hmacSha1(sig, boriginal.getString("value"));
            Log.d(TAG, "serial_hmac: " + String.valueOf(serial_hmac));

            Bundle binjected = new Bundle();
            binjected.putString("value", serial_hmac);
            param.setResult(binjected);

            long time2 = SystemClock.elapsedRealtimeNanos();
            Log.d(TAG, "time: " + String.valueOf(time2 - time1));
            //---------
        }
    }

    //https://stackoverflow.com/questions/6026339/how-to-generate-hmac-sha1-signature-in-android
    private static String hmacSha1(byte[] value, String key){
        String type = "HmacSHA1";
        SecretKeySpec secret = new SecretKeySpec(key.getBytes(), type);
        Mac mac = null;
        try {
            mac = Mac.getInstance(type);
            mac.init(secret);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        byte[] bytes = mac.doFinal(value);
        return bytesToHex8(bytes);
    }

    //https://stackoverflow.com/questions/9293019/get-certificate-fingerprint-from-android-app
    private byte[] getCertificateSHA1Fingerprint(PackageInfo packageInfo) {
        Signature[] signatures = packageInfo.signatures;
        byte[] cert = signatures[0].toByteArray();
        InputStream input = new ByteArrayInputStream(cert);
        CertificateFactory cf = null;
        try {
            cf = CertificateFactory.getInstance("X509");
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        X509Certificate c = null;
        try {
            c = (X509Certificate) cf.generateCertificate(input);
        } catch (CertificateException e) {
            e.printStackTrace();
        }
        byte[] publicKey = null;
        try {
            MessageDigest md = MessageDigest.getInstance("SHA1");
            publicKey = md.digest(c.getEncoded());
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        } catch (CertificateEncodingException e) {
            e.printStackTrace();
        }
        return publicKey;
    }

    //https://stackoverflow.com/questions/9655181/how-to-convert-a-byte-array-to-a-hex-string-in-java
    final protected static char[] hexArray = "0123456789abcdef".toCharArray();
    public static String bytesToHex8(byte[] bytes) {
        char[] hexChars = new char[8 * 2];
        for ( int j = 0; j < 8; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }
}



