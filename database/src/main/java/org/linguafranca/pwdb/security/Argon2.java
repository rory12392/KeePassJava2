package org.linguafranca.pwdb.security;

import org.bouncycastle.crypto.generators.Argon2BytesGenerator;
import org.bouncycastle.crypto.params.Argon2Parameters;

import java.security.SecureRandom;
import java.util.UUID;

import static org.linguafranca.pwdb.security.Argon2.VariantDictionaryKeys.*;


/**
 * KDBX V4 files may use Argon2 for key derivation, either in its Argon2d or its Argon2id variant.
 * KeePass identifies the two variants by different KDF UUIDs, the parameters are the same.
 * <p>
 * Two singletons, see {@link #getInstance()} and {@link #getArgon2idInstance()}
 */
public class Argon2 implements KeyDerivationFunction {

    /**
     * UUID indicating that Argon2d is being used as the KDF
     */
    private static final UUID argon2_kdf = UUID.fromString("EF636DDF-8C29-444B-91F7-A9A403E30A0C");

    /**
     * UUID indicating that Argon2id is being used as the KDF
     */
    private static final UUID argon2id_kdf = UUID.fromString("9E298B19-56DB-4773-B23D-FC3EC6F0A1E6");

    private final UUID kdfUuid;
    private final String name;
    private final int argon2Type;

    /**
     * hide constructor
     */
    private Argon2(UUID kdfUuid, String name, int argon2Type) {
        this.kdfUuid = kdfUuid;
        this.name = name;
        this.argon2Type = argon2Type;
    }

    private static final Argon2 instance = new Argon2(argon2_kdf, "Argon2", Argon2Parameters.ARGON2_d);

    private static final Argon2 argon2idInstance = new Argon2(argon2id_kdf, "Argon2id", Argon2Parameters.ARGON2_id);

    /**
     * @return the Argon2d variant
     */
    public static Argon2 getInstance() {
        return instance;
    }

    /**
     * @return the Argon2id variant
     */
    public static Argon2 getArgon2idInstance() {
        return argon2idInstance;
    }


    /**
     * keys into the variant dictionary supplied as a KDBX header
     */
    @SuppressWarnings("WeakerAccess")
    public static class VariantDictionaryKeys {
        static final String paramSalt = "S"; // Byte[]
        static final String paramParallelism = "P"; // UInt32
        static final String paramMemory = "M"; // UInt64
        static final String paramIterations = "I"; // UInt64
        static final String paramVersion = "V"; // UInt32
        static final String paramSecretKey = "K"; // Byte[]
        static final String paramAssocData = "A"; // Byte[]
    }


    @Override
    public UUID getKdfUuid() {
        return kdfUuid;
    }

    @Override
    public String getName() {
        return name;
    }

    @Override
    public byte[] getTransformedKey(byte[] digest, VariantDictionary argonParameterKeys) {
        int version = argonParameterKeys.mustGet(paramVersion).asInteger();
        byte[] salt = argonParameterKeys.mustGet(paramSalt).asByteArray();
        int parallelism = argonParameterKeys.mustGet(paramParallelism).asInteger();
        int memoryCost = (int) argonParameterKeys.mustGet(paramMemory).asLong();
        int timeCost = (int) argonParameterKeys.mustGet(paramIterations).asLong();

        Argon2Parameters.Builder builder = new Argon2Parameters.Builder(argon2Type)
                .withVersion(version)
                .withIterations(timeCost)
                .withMemoryAsKB(memoryCost/1024)
                .withParallelism(parallelism)
                .withSalt(salt);

        Argon2BytesGenerator gen = new Argon2BytesGenerator();
        gen.init(builder.build());
        byte[] result = new byte[32];
        gen.generateBytes(digest, result, 0, result.length);
        return result;
    }

    static final SecureRandom random = new SecureRandom();

    @Override
    public VariantDictionary createKdfParameters() {
        VariantDictionary vd = new VariantDictionary((short) 1);
        vd.putUInt("P", 2);
        vd.putUInt("V", 19);
        vd.putULong("I", 2);
        vd.putULong("M", 64 * 1024 * 1024);
        vd.putUuid("$UUID", kdfUuid);
        vd.put("S", VariantDictionary.EntryType.ARRAY, random.generateSeed(32));
        return vd;
    }
}
