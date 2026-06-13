Java.perform(function () {
    var TAG = "[MALMON]";

    function log(tag, msg) {
        console.log(tag + " " + msg);
        Java.use("android.util.Log").i(tag, msg);
    }

    // ── Network: HTTP calls ──
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.implementation = function () {
            log(TAG, "URL.openConnection -> " + this.toString());
            return this.openConnection();
        };

        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.getInputStream.implementation = function () {
            log(TAG, "HttpURLConnection.getInputStream -> " + this.getURL());
            return this.getInputStream();
        };
        HttpURLConnection.getOutputStream.implementation = function () {
            log(TAG, "HttpURLConnection.getOutputStream -> " + this.getURL());
            return this.getOutputStream();
        };

        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        if (OkHttpClient) {
            OkHttpClient.newCall.implementation = function (request) {
                log(TAG, "OkHttp newCall -> " + request.url());
                return this.newCall(request);
            };
        }
    } catch (e) { /* lib not present */ }

    // ── SMS (malware exfiltrates data via SMS) ──
    try {
        var SmsManager = Java.use("android.telephony.SmsManager");
        SmsManager.sendTextMessage.overload(
            "java.lang.String", "java.lang.String",
            "java.lang.String", "android.app.PendingIntent",
            "android.app.PendingIntent"
        ).implementation = function (dest, sc, text, sent, deliv) {
            log(TAG, "SMS sendTextMessage -> to=" + dest + " body=" + text);
            return this.sendTextMessage(dest, sc, text, sent, deliv);
        };
    } catch (e) {}

    // ── Crypto (malware encrypts before exfiltrating) ──
    try {
        var Cipher = Java.use("javax.crypto.Cipher");
        Cipher.doFinal.overload("[B").implementation = function (input) {
            log(TAG, "Cipher.doFinal bytes=" + input.length);
            return this.doFinal(input);
        };

        var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
        SecretKeySpec.$init.overload("[B", "java.lang.String").implementation = function (key, algo) {
            log(TAG, "SecretKeySpec algo=" + algo + " key=" + bytesToHex(key));
            return this.$init(key, algo);
        };
    } catch (e) {}

    // ── File I/O (malware reads/writes to storage) ──
    try {
        var FileOutputStream = Java.use("java.io.FileOutputStream");
        FileOutputStream.write.overload("[B").implementation = function (b) {
            log(TAG, "FileOutputStream.write -> " + this.getFD());
            return this.write(b);
        };

        var FileInputStream = Java.use("java.io.FileInputStream");
        FileInputStream.read.overload("[B").implementation = function (b) {
            var ret = this.read(b);
            log(TAG, "FileInputStream.read -> " + this.getFD() + " bytes=" + ret);
            return ret;
        };
    } catch (e) {}

    // ── Process execution (malware runs shell commands) ──
    try {
        var Runtime = Java.use("java.lang.Runtime");
        Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
            log(TAG, "Runtime.exec -> " + cmd);
            return this.exec(cmd);
        };

        var ProcessBuilder = Java.use("java.lang.ProcessBuilder");
        ProcessBuilder.start.implementation = function () {
            log(TAG, "ProcessBuilder.start -> " + this.command());
            return this.start();
        };
    } catch (e) {}

    // ── Contacts / Location (data theft) ──
    try {
        var Cursor = Java.use("android.database.Cursor");
        Cursor.getString.implementation = function (col) {
            var val = this.getString(col);
            log(TAG, "Cursor.getString col=" + col + " val=" + (val ? val.substring(0, Math.min(val.length, 100)) : "null"));
            return val;
        };
    } catch (e) {}

    // ── Device admin (ransomware / lock) ──
    try {
        var DevicePolicyManager = Java.use("android.app.admin.DevicePolicyManager");
        DevicePolicyManager.lockNow.implementation = function () {
            log(TAG, "DevicePolicyManager.lockNow");
            return this.lockNow();
        };
        DevicePolicyManager.wipeData.overload("int").implementation = function (flags) {
            log(TAG, "DevicePolicyManager.wipeData flags=" + flags);
            return this.wipeData(flags);
        };
    } catch (e) {}

    // ── Notification listener (steals 2FA codes) ──
    try {
        var NotificationListenerService = Java.use("android.service.notification.NotificationListenerService");
        NotificationListenerService.onNotificationPosted.implementation = function (sbn) {
            var pkg = sbn.getPackageName();
            var text = sbn.getNotification().tickerText;
            log(TAG, "Notification posted from " + pkg + " text=" + text);
            return this.onNotificationPosted(sbn);
        };
    } catch (e) {}

    log(TAG, "Hooks installed — monitoring " + Java.vm.getLoadedClasses().length + " classes");
});

function bytesToHex(bytes) {
    if (!bytes) return "null";
    var hex = [];
    for (var i = 0; i < Math.min(bytes.length, 32); i++) {
        hex.push(("0" + (bytes[i] & 0xFF).toString(16)).slice(-2));
    }
    return hex.join("");
}
