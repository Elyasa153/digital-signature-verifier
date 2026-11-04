package com.trustlayer.dsv.web;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

/** MockMvc yükleme sınırını uygulamaz; gerçek sunucuya gerçek istek atılır. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class UploadLimitTest {

    @TempDir
    static Path runtime;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry r) {
        r.add("dsv.runtime-dir", runtime::toString);
        r.add("dsv.keystore-password", () -> "test-parola");
    }

    @LocalServerPort
    int port;

    @Test
    void uploadOverLimitShowsMessage() throws Exception {
        HttpResponse<String> r = upload(25 * 1024 * 1024);
        assertEquals(413, r.statusCode());
        assertTrue(r.body().contains("en fazla 20 MB"), r.body());
    }

    @Test
    void uploadUnderLimitIsVerified() throws Exception {
        HttpResponse<String> r = upload(1024);
        assertEquals(200, r.statusCode());
        assertTrue(r.body().contains("Belgede elektronik imza bulunamadı"), r.body());
    }

    private HttpResponse<String> upload(int bytes) throws Exception {
        String boundary = "sinir";
        ByteArrayOutputStream body = new ByteArrayOutputStream();
        body.write(("--" + boundary + "\r\nContent-Disposition: form-data; name=\"pdf\"; filename=\"buyuk.pdf\"\r\n"
                + "Content-Type: application/pdf\r\n\r\n").getBytes(StandardCharsets.US_ASCII));
        body.write(new byte[bytes]);
        body.write(("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.US_ASCII));
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/dogrula"))
                .header("Content-Type", "multipart/form-data; boundary=" + boundary)
                .POST(HttpRequest.BodyPublishers.ofByteArray(body.toByteArray()))
                .build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }
}
