package org.linguafranca.pwdb.kdbx;

import com.google.common.io.CharStreams;
import org.junit.Test;
import org.linguafranca.pwdb.Credentials;
import org.linguafranca.pwdb.security.Argon2;
import org.linguafranca.pwdb.security.Encryption;
import org.linguafranca.pwdb.security.VariantDictionary;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Scanner;
import java.util.UUID;

import static org.junit.Assert.*;

/**
 * KDBX 4 files whose key derivation function is Argon2id rather than Argon2d
 */
public class Argon2idTest {

    /**
     * Created by KeePassXC: KDBX 4.1, AES-256, Argon2id (64 MiB, 2 iterations, parallelism 4), password "probe1234"
     */
    static final String ARGON2ID_RESOURCE = "V4-AES-Argon2id-probe1234.kdbx";
    static final Credentials ARGON2ID_CREDS = new KdbxCreds("probe1234".getBytes());

    static final UUID ARGON2D_UUID = UUID.fromString("EF636DDF-8C29-444B-91F7-A9A403E30A0C");
    static final UUID ARGON2ID_UUID = UUID.fromString("9E298B19-56DB-4773-B23D-FC3EC6F0A1E6");

    @Test
    public void kdfUuids() {
        assertEquals(ARGON2D_UUID, Encryption.KeyDerivationFunction.ARGON2.getKdfUuid());
        assertEquals(ARGON2ID_UUID, Encryption.KeyDerivationFunction.ARGON2ID.getKdfUuid());
        assertEquals(Encryption.KeyDerivationFunction.ARGON2ID, Encryption.KeyDerivationFunction.getKdf(ARGON2ID_UUID));
        assertEquals("Argon2id", Encryption.KeyDerivationFunction.ARGON2ID.getName());
    }

    @Test
    public void createKdfParametersUsesOwnUuid() {
        assertEquals(ARGON2D_UUID, Encryption.KeyDerivationFunction.ARGON2.createKdfParameters().mustGet("$UUID").asUuid());
        assertEquals(ARGON2ID_UUID, Encryption.KeyDerivationFunction.ARGON2ID.createKdfParameters().mustGet("$UUID").asUuid());
    }

    /**
     * The same parameters must give different keys for the two variants, i.e. Argon2id is not Argon2d under another name
     */
    @Test
    public void variantsGiveDifferentKeys() {
        VariantDictionary parameters = Argon2.getInstance().createKdfParameters();
        parameters.putULong("M", 1024 * 1024);
        parameters.putULong("I", 1);
        byte[] digest = new byte[32];
        byte[] argon2d = Argon2.getInstance().getTransformedKey(digest, parameters);
        byte[] argon2id = Argon2.getArgon2idInstance().getTransformedKey(digest, parameters);
        assertEquals(32, argon2id.length);
        assertFalse(Arrays.equals(argon2d, argon2id));
    }

    @Test
    public void loadArgon2idHeader() throws IOException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(ARGON2ID_RESOURCE)) {
            KdbxHeader header = KdbxSerializer.readOuterHeader(inputStream, new KdbxHeader());
            assertEquals(4, header.getVersion());
            assertEquals(Encryption.KeyDerivationFunction.ARGON2ID, header.getKeyDerivationFunction());
        }
    }

    /**
     * Decrypt a file written by KeePassXC with Argon2id
     */
    @Test
    public void decryptKeePassXcArgon2id() throws IOException {
        KdbxHeader header = new KdbxHeader();
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(ARGON2ID_RESOURCE);
             InputStream decrypted = KdbxSerializer.createUnencryptedInputStream(ARGON2ID_CREDS, header, inputStream)) {
            String xml = CharStreams.toString(new InputStreamReader(decrypted, StandardCharsets.UTF_8));
            assertTrue(xml.contains("<KeePassFile>"));
        }
        assertEquals(Encryption.KeyDerivationFunction.ARGON2ID, header.getKeyDerivationFunction());
    }

    @Test(expected = IllegalStateException.class)
    public void wrongPasswordFails() throws IOException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(ARGON2ID_RESOURCE)) {
            KdbxSerializer.createUnencryptedInputStream(new KdbxCreds("wrong".getBytes()), new KdbxHeader(), inputStream);
        }
    }

    /**
     * Write a KDBX 4 stream using Argon2id and read it back
     */
    @Test
    public void writeAndReadArgon2id() throws IOException {
        Credentials credentials = new KdbxCreds("123".getBytes());
        KdbxHeader kdbxHeader = new KdbxHeader(4);
        kdbxHeader.setKeyDerivationFunction(Encryption.KeyDerivationFunction.ARGON2ID);
        assertEquals(ARGON2ID_UUID, kdbxHeader.getKdfParameters().mustGet("$UUID").asUuid());

        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        try (OutputStream outputStream = KdbxSerializer.createEncryptedOutputStream(credentials, kdbxHeader, bytes)) {
            outputStream.write("Hello World\n".getBytes());
        }

        KdbxHeader readHeader = new KdbxHeader();
        try (InputStream inputStream = KdbxSerializer.createUnencryptedInputStream(credentials, readHeader, new ByteArrayInputStream(bytes.toByteArray()))) {
            assertEquals(Encryption.KeyDerivationFunction.ARGON2ID, readHeader.getKeyDerivationFunction());
            assertEquals(ARGON2ID_UUID, readHeader.getKdfParameters().mustGet("$UUID").asUuid());
            Scanner scanner = new Scanner(inputStream);
            assertEquals("Hello World", scanner.nextLine());
        }
    }
}
