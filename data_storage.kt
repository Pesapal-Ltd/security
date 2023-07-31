  public static SharedPreferences getSharedPreferences(){
        SharedPreferences encryptedSharedPreferences;
        try {
            MasterKey masterKey = new MasterKey.Builder(getAppContext())
                    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                    .build();

            encryptedSharedPreferences = EncryptedSharedPreferences.create(
                    getAppContext(),
                    PREF_KEY,
                    masterKey,
                    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
            );

        }catch (Exception e){
            encryptedSharedPreferences = null;
        }

        return encryptedSharedPreferences;
    }
