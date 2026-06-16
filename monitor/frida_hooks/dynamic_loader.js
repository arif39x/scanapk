Java.perform(function () {
    try {
        var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
        DexClassLoader.$init.overload(
            "java.lang.String", "java.lang.String",
            "java.lang.String", "java.lang.ClassLoader"
        ).implementation = function (dexPath, optDir, libDir, parent) {
            log("DexClassLoader.<init> -> " + dexPath);
            return this.$init(dexPath, optDir, libDir, parent);
        };
    } catch (e) {}

    try {
        var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
        PathClassLoader.$init.overload(
            "java.lang.String", "java.lang.ClassLoader"
        ).implementation = function (path, parent) {
            log("PathClassLoader.<init> -> " + path);
            return this.$init(path, parent);
        };
    } catch (e) {}
});
