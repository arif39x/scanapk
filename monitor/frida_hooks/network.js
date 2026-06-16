Java.perform(function () {
    try {
        var URL = Java.use("java.net.URL");
        URL.openConnection.implementation = function () {
            log("URL.openConnection -> " + this.toString());
            return this.openConnection();
        };
    } catch (e) {}

    try {
        var HttpURLConnection = Java.use("java.net.HttpURLConnection");
        HttpURLConnection.getInputStream.implementation = function () {
            log("HttpURLConnection.getInputStream -> " + this.getURL());
            return this.getInputStream();
        };
        HttpURLConnection.getOutputStream.implementation = function () {
            log("HttpURLConnection.getOutputStream -> " + this.getURL());
            return this.getOutputStream();
        };
    } catch (e) {}

    try {
        var OkHttpClient = Java.use("okhttp3.OkHttpClient");
        OkHttpClient.newCall.implementation = function (request) {
            log("OkHttp.newCall -> " + request.url());
            return this.newCall(request);
        };
    } catch (e) {}

    try {
        var Socket = Java.use("java.net.Socket");
        Socket.connect.implementation = function (addr, timeout) {
            log("Socket.connect -> " + addr.toString());
            return this.connect(addr, timeout);
        };
    } catch (e) {}
});
