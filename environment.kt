
fun initializeSecurity(activity: Activity, withSecurityChecks: Boolean, signature: String) {
    // Device security
    val securityLevel: SecurityLevel = BasicSecurity.verifyBasicSecurity(activity as Context, withSecurityChecks)
    if (securityLevel != SecurityLevel.ACCEPTABLE) {
        val message = when (securityLevel) {
            SecurityLevel.ROOTED_DEVICE -> {
                "Prohibited. Error E001" // Rooted device detected
            }

            SecurityLevel.UNKNOWN_INSTALLER -> {
                "Prohibited. Error E002" // This app was installed from untrusted sources
            }

            SecurityLevel.DEBUGGABLE -> {
                "Prohibited. Error E003" // App in debug mode
            }

            SecurityLevel.HOOKING_APP_DETECTED -> {
                "Prohibited. Error E004" // A malicious hooking framework is installed on this phone
            }

            SecurityLevel.EMULATOR -> {
                "Prohibited. Error E005" // App cannot run run on Emulator
            }

            SecurityLevel.ADB_ENABLED -> {
                "Prohibited. Error E006" // ADB/ Developer options enabled on device
            }

            else -> "Prohibited. Error E007"
        }

        Toast.makeText(activity as Context, message, Toast.LENGTH_SHORT).show()

        finishAndExit(activity)
    }

    // App signature check
    if (verifyAppLevelSecurity(activity as Context, withSecurityChecks, signature) == DeviceSecurityLevel.INVALID_SIGNATURE) {
        Toast.makeText(activity as Context, "Application signature is invalid", Toast.LENGTH_SHORT).show()

        finishAndExit(activity)
    }
}

fun finishAndExit(activity: Activity) {
    activity.finishAffinity()

    exitProcess(0)
}

enum class SecurityLevel {
    ACCEPTABLE,
    ROOTED_DEVICE,
    UNKNOWN_INSTALLER,
    DEBUGGABLE,
    HOOKING_APP_DETECTED,
    EMULATOR,
    ADB_ENABLED
}

object BasicSecurity {
    fun verifyBasicSecurity(context: Context, withSecurityChecks: Boolean): SecurityLevel {
        if (withSecurityChecks) {
            if (isDeviceRooted == 24)
                return SecurityLevel.ROOTED_DEVICE

            if (verifyInstaller(context) == 65)
                return SecurityLevel.UNKNOWN_INSTALLER

            if (checkDebuggable(context) == 32)
                return SecurityLevel.DEBUGGABLE

            if (hookingFrameworkDetected(context) == 47)
                return SecurityLevel.HOOKING_APP_DETECTED

            if (isEmulator == 78)
                return SecurityLevel.EMULATOR

            if (isAdbEnabled(context) == 4)
                return SecurityLevel.ADB_ENABLED
        }

        return SecurityLevel.ACCEPTABLE
    }

    private fun checkRootMethod1(): Boolean {
        val buildTags = Build.TAGS
        return buildTags != null && buildTags.contains("test-keys")
    }

    private fun checkRootMethod2(): Boolean {
        val paths = arrayOf(
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
        )

        for (path in paths)
            if (File(path).exists())
                return true

        return false
    }

    private fun checkRootMethod3(): Boolean {
        var process: Process? = null

        try {
            process = Runtime.getRuntime().exec(arrayOf("/system/xbin/which", "su"))
            val `in` = BufferedReader(InputStreamReader(process.inputStream))
            if (`in`.readLine() != null)
                return true

        } catch (var6: Throwable) {
            return false
        } finally {
            process?.destroy()
        }

        return false
    }

    private val isDeviceRooted: Int
        get() = if (!checkRootMethod1() && !checkRootMethod2() && !checkRootMethod3()) 10 else 24

    private fun verifyInstaller(context: Context): Int {
        val installer = context.packageManager.getInstallerPackageName(context.packageName)
        return if (installer == null || !installer.startsWith("com.android.vending") && !installer.startsWith("com.huawei.appmarket")) 65 else 10
    }

    private val isEmulator: Int
        get() = if (!Build.FINGERPRINT.startsWith("generic") &&
            !Build.FINGERPRINT.startsWith("unknown") &&
            !Build.MODEL.contains("google_sdk") &&
            !Build.MODEL.contains("Emulator") &&
            !Build.MODEL.contains("Android SDK built for x86") &&
            !Build.MANUFACTURER.contains("Genymotion") &&
            (!Build.BRAND.startsWith("generic") || !Build.DEVICE.startsWith("generic")) && "google_sdk" != Build.PRODUCT
        )
            10
        else
            78

    private fun checkDebuggable(context: Context): Int {
        return if (context.applicationInfo.flags and 2 != 0) 32 else 10
    }

    private fun hookingFrameworkDetected(context: Context): Int {
        val packageManager = context.packageManager
        val applicationInfoList = packageManager.getInstalledApplications(128)
        val dangerousPackages = arrayOf("de.robv.android.xposed.installer", "com.saurik.substrate", "de.robv.android.xposed")
        val var4: Iterator<*> = applicationInfoList.iterator()
        var applicationInfo: ApplicationInfo
        do {
            if (!var4.hasNext()) {
                return if (advancedHookDetection(context)) 47 else 10
            }
            applicationInfo = var4.next() as ApplicationInfo
        } while (!listOf(*dangerousPackages).contains(applicationInfo.packageName))
        return 47
    }

    private fun advancedHookDetection(context: Context): Boolean {
        return try {
            throw java.lang.Exception()
        } catch (var7: java.lang.Exception) {
            var zygoteInitCallCount = 0
            val var3 = var7.stackTrace
            val var4 = var3.size
            var var5 = 0
            while (var5 < var4) {
                val stackTraceElement = var3[var5]
                if (stackTraceElement.className == "com.android.internal.os.ZygoteInit") {
                    ++zygoteInitCallCount
                    if (zygoteInitCallCount == 2) {
                        return true
                    }
                }
                if (stackTraceElement.className == "com.saurik.substrate.MS$2" && stackTraceElement.methodName == "invoked") {
                    return true
                }
                if (stackTraceElement.className == "de.robv.android.xposed.XposedBridge" && stackTraceElement.methodName == "main") {
                    return true
                }
                if (stackTraceElement.className == "de.robv.android.xposed.XposedBridge" && stackTraceElement.methodName == "handleHookedMethod") {
                    return true
                }
                ++var5
            }
            checkFrida(context)
        }
    }

    private fun checkFrida(context: Context): Boolean {
        val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
        val runningServices = activityManager.getRunningServices(300)
        if (runningServices != null) {
            for (i in runningServices.indices) {
                if ((runningServices[i] as ActivityManager.RunningServiceInfo).process.contains("fridaserver")) {
                    return true
                }
            }
        }
        return findHookAppFile()
    }

    private fun isAdbEnabled(context: Context): Int {
        return if (Settings.Global.getInt(context.contentResolver, "adb_enabled", 0) == 1) 4 else 10
    }

    private fun findHookAppFile(): Boolean {
        try {
            val libraries: MutableSet<String?> = HashSet()
            val mapsFilename = "/proc/" + android.os.Process.myPid() + "/maps"
            val reader = BufferedReader(FileReader(mapsFilename))
            label1@ while (true) {
                var line: String
                do {
                    if (reader.readLine().also { line = it } == null) {
                        reader.close()
                        val var7: Iterator<*> = libraries.iterator()
                        while (var7.hasNext()) {
                            val library = var7.next() as String
                            if (library.contains("com.saurik.substrate")) {
                                return true
                            }
                            if (library.contains("XposedBridge.jar")) {
                                return true
                            }
                        }
                        break@label1
                    }
                } while (!line.endsWith(".so") && !line.endsWith(".jar"))
                val n = line.lastIndexOf(" ")
                libraries.add(line.substring(n + 1))
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
        return false
    }
}

enum class DeviceSecurityLevel {
    INVALID_SIGNATURE,
    ACCEPTABLE
}

fun verifyAppLevelSecurity(context: Context, withSecurityChecks: Boolean, appSignature: String): DeviceSecurityLevel {
    if (withSecurityChecks)
        try {
            val packageInfo = context.packageManager.getPackageInfo(context.packageName, PackageManager.GET_SIGNATURES)
            for (signature in packageInfo.signatures) {
                val messageDigest = MessageDigest.getInstance("SHA")
                messageDigest.update(signature.toByteArray())
                val currentSignature = Base64.encodeToString(messageDigest.digest(), Base64.DEFAULT)

                return if (currentSignature.trim() == appSignature.trim())
                    DeviceSecurityLevel.ACCEPTABLE
                else
                    DeviceSecurityLevel.INVALID_SIGNATURE
            }
        } catch (e: Exception) {
            return DeviceSecurityLevel.INVALID_SIGNATURE
        }

    return DeviceSecurityLevel.ACCEPTABLE
}
