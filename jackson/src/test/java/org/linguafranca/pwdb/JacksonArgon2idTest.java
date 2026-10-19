package org.linguafranca.pwdb;

import org.junit.Test;
import org.linguafranca.pwdb.kdbx.KdbxCreds;
import org.linguafranca.pwdb.kdbx.KdbxHeader;
import org.linguafranca.pwdb.kdbx.KdbxStreamFormat;
import org.linguafranca.pwdb.kdbx.jackson.JacksonDatabase;
import org.linguafranca.pwdb.kdbx.jackson.JacksonEntry;
import org.linguafranca.pwdb.security.Encryption;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;

/**
 * Open and save KDBX 4 databases whose key derivation function is Argon2id
 */
public class JacksonArgon2idTest {

    /**
     * Created by KeePassXC: KDBX 4.1, AES-256, Argon2id (64 MiB, 2 iterations, parallelism 4), password "probe1234"
     */
    static final String ARGON2ID_RESOURCE = "V4-AES-Argon2id-probe1234.kdbx";
    static final Credentials ARGON2ID_CREDS = new KdbxCreds("probe1234".getBytes());

    private JacksonDatabase loadResource() throws IOException {
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream(ARGON2ID_RESOURCE)) {
            return JacksonDatabase.load(ARGON2ID_CREDS, inputStream);
        }
    }

    private static KdbxHeader header(JacksonDatabase database) {
        return (KdbxHeader) database.getStreamFormat().getStreamConfiguration();
    }

    private static List<String> contents(JacksonDatabase database) {
        List<String> result = new ArrayList<>();
        for (JacksonEntry entry : database.findEntries("")) {
            result.add(entry.getUuid() + "|" + entry.getTitle() + "|" + entry.getUsername() + "|"
                    + entry.getPassword() + "|" + entry.getUrl() + "|" + entry.getNotes());
        }
        return result;
    }

    @Test
    public void openKeePassXcArgon2id() throws IOException {
        JacksonDatabase database = loadResource();
        assertEquals(Encryption.KeyDerivationFunction.ARGON2ID, header(database).getKeyDerivationFunction());
        assertFalse(contents(database).isEmpty());
    }

    /**
     * Saving a database loaded from an Argon2id file keeps Argon2id and the content
     */
    @Test
    public void saveKeepsArgon2id() throws IOException {
        JacksonDatabase database = loadResource();
        List<String> before = contents(database);

        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        database.save(ARGON2ID_CREDS, outputStream);

        JacksonDatabase reloaded = JacksonDatabase.load(ARGON2ID_CREDS, new ByteArrayInputStream(outputStream.toByteArray()));
        assertEquals(Encryption.KeyDerivationFunction.ARGON2ID, header(reloaded).getKeyDerivationFunction());
        assertEquals(before, contents(reloaded));
    }

    /**
     * A new database saved with Argon2id chosen explicitly
     */
    @Test
    public void saveNewDatabaseWithArgon2id() throws IOException {
        JacksonDatabase database = new JacksonDatabase();
        JacksonEntry entry = database.newEntry();
        entry.setTitle("Argon2id entry");
        entry.setPassword("secret");
        database.getRootGroup().addEntry(entry);

        KdbxHeader kdbxHeader = new KdbxHeader(4);
        kdbxHeader.setKeyDerivationFunction(Encryption.KeyDerivationFunction.ARGON2ID);
        Credentials credentials = new KdbxCreds("123".getBytes());
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        database.save(new KdbxStreamFormat(kdbxHeader), credentials, outputStream);

        JacksonDatabase reloaded = JacksonDatabase.load(credentials, new ByteArrayInputStream(outputStream.toByteArray()));
        assertEquals(Encryption.KeyDerivationFunction.ARGON2ID, header(reloaded).getKeyDerivationFunction());
        assertEquals("secret", reloaded.findEntries("Argon2id entry").get(0).getPassword());
    }
}
