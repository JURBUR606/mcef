/*
 *     MCEF (Minecraft Chromium Embedded Framework)
 *     Copyright (C) 2023 CinemaMod Group
 *
 *     This library is free software; you can redistribute it and/or
 *     modify it under the terms of the GNU Lesser General Public
 *     License as published by the Free Software Foundation; either
 *     version 2.1 of the License, or (at your option) any later version.
 *
 *     This library is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *     Lesser General Public License for more details.
 *
 *     You should have received a copy of the GNU Lesser General Public
 *     License along with this library; if not, write to the Free Software
 *     Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301
 *     USA
 */

package com.cinemamod.mcef;

import com.cinemamod.mcef.internal.MCEFDownloadListener;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.Properties;

/**
 * Downloads the java-cef build for the current platform and installs it into mcef-libraries.
 * <p>
 * The archive is only trusted if its SHA-256 equals the hash pinned in this jar
 * ({@code mcef-hashes.properties}); a hash served next to the download is never used,
 * so a compromised or spoofed mirror cannot get native code executed.
 */
public class MCEFDownloader {
    private static final String JAVA_CEF_DOWNLOAD_URL = "${host}/jcef-${java-cef-commit}/${platform}.tar.gz";
    private static final String PINNED_HASHES = "/mcef-hashes.properties";

    private final String host;
    private final String javaCefCommitHash;
    private final MCEFPlatform platform;

    public MCEFDownloader(String host, String javaCefCommitHash, MCEFPlatform platform) {
        this.host = host;
        this.javaCefCommitHash = javaCefCommitHash;
        this.platform = platform;
    }

    public String getHost() {
        return host;
    }

    public String getJavaCefDownloadUrl() {
        return JAVA_CEF_DOWNLOAD_URL
                .replace("${host}", host)
                .replace("${java-cef-commit}", javaCefCommitHash)
                .replace("${platform}", platform.getNormalizedName());
    }

    private static File librariesDir() {
        return new File(System.getProperty("mcef.libraries.path"));
    }

    /** Marker written after a verified install; holds the pinned hash of the archive it came from. */
    private File installedMarker() {
        return new File(librariesDir(), platform.getNormalizedName() + ".installed");
    }

    /** @return the SHA-256 (lowercase hex) this jar expects for the current platform's archive */
    public String getPinnedHash() throws IOException {
        Properties p = new Properties();
        try (InputStream in = MCEFDownloader.class.getResourceAsStream(PINNED_HASHES)) {
            if (in == null) throw new IOException("Missing " + PINNED_HASHES + " in the MCEF jar");
            p.load(in);
        }
        String commit = p.getProperty("java-cef-commit");
        if (commit != null && !commit.equals(javaCefCommitHash))
            throw new IOException("Pinned hashes are for java-cef " + commit + ", not " + javaCefCommitHash);
        String hash = p.getProperty(platform.getNormalizedName());
        if (hash == null || !hash.matches("[0-9a-fA-F]{64}"))
            throw new IOException("No pinned hash for platform " + platform.getNormalizedName());
        return hash.toLowerCase();
    }

    /** @return true if the build in mcef-libraries was installed from exactly the pinned archive */
    public boolean isInstalled() {
        try {
            File marker = installedMarker();
            File jcefDir = new File(librariesDir(), platform.getNormalizedName());
            return marker.isFile() && jcefDir.isDirectory()
                    && Files.readString(marker.toPath(), StandardCharsets.US_ASCII).trim().equals(getPinnedHash());
        } catch (IOException e) {
            return false;
        }
    }

    /** Downloads, verifies and extracts the build. Nothing is extracted unless the hash matches. */
    public void downloadAndInstall() throws IOException {
        String expected = getPinnedHash();
        File archive = new File(librariesDir(), platform.getNormalizedName() + ".tar.gz");
        // An archive put there by hand (downloaded in a browser / over a VPN) is used if it is the pinned one
        if (archive.isFile() && sha256(archive).equals(expected)) {
            MCEF.getLogger().info("Using the already present " + archive.getName());
        } else {
            archive.delete();
            File part = new File(librariesDir(), platform.getNormalizedName() + ".tar.gz.part");
            MCEFDownloadListener.INSTANCE.setTask("Downloading Chromium");
            IOException last = null;
            for (int attempt = 1; attempt <= 5; attempt++) {
                try {
                    downloadResumable(getJavaCefDownloadUrl(), part);
                    last = null;
                    break;
                } catch (IOException e) {
                    last = e;
                    MCEF.getLogger().warn("Download attempt " + attempt + " failed (" + e.getMessage() + "), resuming");
                    try { Thread.sleep(2000L * attempt); } catch (InterruptedException ie) { throw new IOException(ie); }
                }
            }
            if (last != null) throw last;
            if (!part.renameTo(archive)) throw new IOException("Could not rename " + part);
        }

        MCEFDownloadListener.INSTANCE.setTask("Verifying");
        String actual = sha256(archive);
        if (!actual.equals(expected)) {
            archive.delete();
            throw new IOException("Checksum mismatch for " + archive.getName() + ": expected " + expected + ", got " + actual);
        }

        installedMarker().delete();
        File jcefDir = new File(librariesDir(), platform.getNormalizedName());
        deleteRecursively(jcefDir); // never mix files of an old build with the new one
        extractTarGz(archive, librariesDir());
        archive.delete();
        Files.writeString(installedMarker().toPath(), expected, StandardCharsets.US_ASCII);
    }

    private static String sha256(File file) throws IOException {
        try (InputStream in = new BufferedInputStream(new FileInputStream(file))) {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) != -1) md.update(buf, 0, n);
            return HexFormat.of().formatHex(md.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new IOException(e);
        }
    }

    private static void deleteRecursively(File f) {
        File[] children = f.listFiles();
        if (children != null) for (File c : children) deleteRecursively(c);
        f.delete();
    }

    /**
     * Downloads into |part|, continuing after whatever it already holds (HTTP Range), so a dropped
     * connection or a game restart does not start the ~150 MB download over. Shows MB done and speed.
     */
    private static void downloadResumable(String urlString, File part) throws IOException {
        long have = part.isFile() ? part.length() : 0;
        MCEF.getLogger().info(urlString + " -> " + part.getCanonicalPath() + (have > 0 ? " (resuming at " + have + ")" : ""));
        URL url = new URL(urlString);
        if (!url.getProtocol().equals("https")) throw new IOException("Refusing non-HTTPS download: " + urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setInstanceFollowRedirects(true); // GitHub release assets redirect to their CDN (https only)
        connection.setConnectTimeout(15_000);
        connection.setReadTimeout(30_000);
        if (have > 0) connection.setRequestProperty("Range", "bytes=" + have + "-");
        try {
            int code = connection.getResponseCode();
            boolean append = code == 206;
            if (code == 416 && have > 0) return; // already complete
            if (code != 200 && code != 206) throw new IOException("HTTP " + code + " for " + urlString);
            if (!append) have = 0; // server ignored the range: start over
            long remaining = connection.getContentLengthLong();
            long total = remaining > 0 ? have + remaining : -1;
            try (InputStream in = new BufferedInputStream(connection.getInputStream(), 1 << 20);
                 OutputStream out = new BufferedOutputStream(new FileOutputStream(part, append), 1 << 20)) {
                byte[] buffer = new byte[1 << 16];
                int count;
                long done = have, windowStart = System.nanoTime(), windowBytes = 0;
                while ((count = in.read(buffer)) != -1) {
                    out.write(buffer, 0, count);
                    done += count;
                    windowBytes += count;
                    long now = System.nanoTime();
                    if (now - windowStart > 1_000_000_000L) {
                        double mbps = windowBytes / 1048576.0 / ((now - windowStart) / 1e9);
                        MCEFDownloadListener.INSTANCE.setStatus(String.format(java.util.Locale.ROOT,
                            "Downloading Chromium: %d / %s MB, %.1f MB/s", done >> 20, total > 0 ? Long.toString(total >> 20) : "?", mbps));
                        windowStart = now;
                        windowBytes = 0;
                    }
                    if (total > 0) MCEFDownloadListener.INSTANCE.setProgress((float) done / total);
                }
            }
        } finally {
            connection.disconnect();
        }
    }

    private static void extractTarGz(File tarGzFile, File outputDirectory) throws IOException {
        MCEFDownloadListener.INSTANCE.setTask("Extracting");
        outputDirectory.mkdirs();
        String root = outputDirectory.getCanonicalPath() + File.separator;
        long fileSize = tarGzFile.length();
        long totalBytesRead = 0;
        try (TarArchiveInputStream tarInput = new TarArchiveInputStream(new GzipCompressorInputStream(new FileInputStream(tarGzFile)))) {
            TarArchiveEntry entry;
            while ((entry = tarInput.getNextTarEntry()) != null) {
                if (!entry.isFile() || entry.isSymbolicLink() || entry.isLink()) {
                    continue;
                }
                File outputFile = new File(outputDirectory, entry.getName());
                // reject entries like "../../x" that would escape mcef-libraries
                if (!outputFile.getCanonicalPath().startsWith(root))
                    throw new IOException("Archive entry outside the target directory: " + entry.getName());
                outputFile.getParentFile().mkdirs();
                try (OutputStream outputStream = new FileOutputStream(outputFile)) {
                    byte[] buffer = new byte[65536];
                    int bytesRead;
                    while ((bytesRead = tarInput.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                        totalBytesRead += bytesRead;
                        float percentComplete = (((float) totalBytesRead / fileSize) / 2.6158204f); // Roughly the compression ratio
                        MCEFDownloadListener.INSTANCE.setProgress(percentComplete);
                    }
                }
                if ((entry.getMode() & 0100) != 0) outputFile.setExecutable(true, false);
            }
        }
        MCEFDownloadListener.INSTANCE.setProgress(1.0f);
    }
}
