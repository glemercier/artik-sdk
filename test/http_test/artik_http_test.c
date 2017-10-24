/*
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <openssl/md5.h>

#include <artik_module.h>
#include <artik_http.h>
#include <artik_loop.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

#define IMAGE_MD5 "a27095e7727c70909c910cefe16d30de"

static const char *httpbin_root_ca =
	"-----BEGIN CERTIFICATE-----\n"
	"MIIDSjCCAjKgAwIBAgIQRK+wgNajJ7qJMDmGLvhAazANBgkqhkiG9w0BAQUFADA/\r\n"
	"MSQwIgYDVQQKExtEaWdpdGFsIFNpZ25hdHVyZSBUcnVzdCBDby4xFzAVBgNVBAMT\r\n"
	"DkRTVCBSb290IENBIFgzMB4XDTAwMDkzMDIxMTIxOVoXDTIxMDkzMDE0MDExNVow\r\n"
	"PzEkMCIGA1UEChMbRGlnaXRhbCBTaWduYXR1cmUgVHJ1c3QgQ28uMRcwFQYDVQQD\r\n"
	"Ew5EU1QgUm9vdCBDQSBYMzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n"
	"AN+v6ZdQCINXtMxiZfaQguzH0yxrMMpb7NnDfcdAwRgUi+DoM3ZJKuM/IUmTrE4O\r\n"
	"rz5Iy2Xu/NMhD2XSKtkyj4zl93ewEnu1lcCJo6m67XMuegwGMoOifooUMM0RoOEq\r\n"
	"OLl5CjH9UL2AZd+3UWODyOKIYepLYYHsUmu5ouJLGiifSKOeDNoJjj4XLh7dIN9b\r\n"
	"xiqKqy69cK3FCxolkHRyxXtqqzTWMIn/5WgTe1QLyNau7Fqckh49ZLOMxt+/yUFw\r\n"
	"7BZy1SbsOFU5Q9D8/RhcQPGX69Wam40dutolucbY38EVAjqr2m7xPi71XAicPNaD\r\n"
	"aeQQmxkqtilX4+U9m5/wAl0CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAOBgNV\r\n"
	"HQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMSnsaR7LHH62+FLkHX/xBVghYkQMA0GCSqG\r\n"
	"SIb3DQEBBQUAA4IBAQCjGiybFwBcqR7uKGY3Or+Dxz9LwwmglSBd49lZRNI+DT69\r\n"
	"ikugdB/OEIKcdBodfpga3csTS7MgROSR6cz8faXbauX+5v3gTt23ADq1cEmv8uXr\r\n"
	"AvHRAosZy5Q6XkjEGB5YGV8eAlrwDPGxrancWYaLbumR9YbK+rlmM6pZW87ipxZz\r\n"
	"R8srzJmwN0jP41ZL9c8PDHIyh8bwRLtTcm1D9SZImlJnt1ir/md2cXjbDaJWFBM5\r\n"
	"JDGFoqgCWjBH4d1QB7wCCZAA62RjYJsWvIjJEubSfZGL+T0yjWW06XyxV3bqxbYo\r\n"
	"Ob8VZRzI9neWagqNdwvYkQsEjgfbKbYK7p2CNTUQ\r\n"
	"-----END CERTIFICATE-----\n";

static void sig_handler(int sig)
{
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	loop->quit();
}

int download_image(char *data, unsigned int len, void *user_data)
{
	FILE *fp = (FILE *)user_data;

	int written = fwrite(data, sizeof(char), len, fp);

	return written;
}

void http_response_callback(artik_error ret, int status, char *response,
							void *user_data)
{
	if (ret != S_OK)
		fprintf(stderr, "error = %s\n", error_msg(ret));
	else
		fprintf(stdout, "response = %s\nstatus = %d\n", response,
								status);
}

void http_stream_response_callback(artik_error ret, int status, char *response,
								void *user_data)
{
	FILE *fp = (FILE *)user_data;
	char outfilename[FILENAME_MAX] = "./image.jpeg";
	int i;
	int bytes;
	MD5_CTX mdContext;
	unsigned char c[MD5_DIGEST_LENGTH];
	unsigned char data[1024];
	char file_MD5[(MD5_DIGEST_LENGTH*2)+1];

	if (ret != S_OK) {
		fprintf(stderr, "error = %s\n", error_msg(ret));
		return;
	}

	fprintf(stdout, "stream done - status = %d\n", status);

	if (fp)
		fclose(fp);

	fp = fopen(outfilename, "rb");
	if (!fp) {
		fprintf(stdout, "TEST: %s failed to open %s (err=%d)\n", __func__,
				outfilename, errno);
		return;
	}

	MD5_Init(&mdContext);

	while ((bytes = fread(data, 1, 1024, fp)) != 0)
		MD5_Update(&mdContext, data, bytes);

	MD5_Final(c, &mdContext);

	memset(file_MD5, 0, sizeof(file_MD5));
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		snprintf(&(file_MD5[i*2]), 3, "%02x", c[i]);

	fprintf(stdout, "MD5 of downloaded file = %s\n", file_MD5);
	fprintf(stdout, "MD5 expected = %s\n", IMAGE_MD5);

	if (strcmp(file_MD5, IMAGE_MD5) == 0)
		fprintf(stdout, "Image correctly donwloaded\n");
	else
		fprintf(stdout, "Image no correctly donwloaded\n");

	if (fp)
		fclose(fp);
}

artik_error test_http_get_stream(bool verify, bool secure)
{
	artik_http_module *http = (artik_http_module *)
					artik_request_api_module("http");
	artik_error ret = S_OK;
	FILE *fp = NULL;
	char outfilename[FILENAME_MAX] = "./image.jpeg";
	int i = 0;
	int bytes = 0;
	MD5_CTX mdContext;
	unsigned char c[MD5_DIGEST_LENGTH];
	unsigned char data[1024];
	char file_MD5[(MD5_DIGEST_LENGTH*2)+1];
	artik_ssl_config ssl_config = { 0 };
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"user-agent", "Artik browser"},
		{"Accept-Language", "en-US,en;q=0.8"},
	};

	fp = fopen(outfilename, "wb");
	if (!fp) {
		fprintf(stdout, "TEST: %s failed to open %s (err=%d)\n", __func__,
				outfilename, errno);
		return ret;
	}

	memset(&ssl_config, 0, sizeof(ssl_config));

	ssl_config.ca_cert.data = (char *)httpbin_root_ca;
	ssl_config.ca_cert.len = strlen(httpbin_root_ca);

	if (verify)
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	fprintf(stdout, "TEST: %s starting\n", __func__);

	if (secure)
		ret = http->get_stream("https://httpbin.org/image/jpeg",
			&headers, NULL, download_image, (void *)fp,
			&ssl_config);
	else
		ret = http->get_stream("http://httpbin.org/image/jpeg",
			&headers, NULL, download_image, (void *)fp, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	if (fp)
		fclose(fp);

	fp = fopen(outfilename, "rb");
	if (!fp) {
		fprintf(stdout, "TEST: %s failed to open %s (err=%d)\n", __func__,
				outfilename, errno);
		return ret;
	}

	MD5_Init(&mdContext);

	while (1) {
		bytes = fread(data, 1, 1024, fp);
		if (!bytes) {
			if (feof(fp)) {
				break;
			} else if (ferror(fp)) {
				fclose(fp);
				fprintf(stdout, "TEST: %s failed to read data from %s\n",
					__func__, outfilename);
				return ret;
			}
		}

		MD5_Update(&mdContext, data, bytes);
	}


	MD5_Final(c, &mdContext);

	memset(file_MD5, 0, sizeof(file_MD5));
	for (i = 0; i < MD5_DIGEST_LENGTH; i++)
		snprintf(&(file_MD5[i*2]), 3, "%02x", c[i]);

	fprintf(stdout, "MD5 of downloaded file = %s\n", file_MD5);
	fprintf(stdout, "MD5 expected = %s\n", IMAGE_MD5);

	if (strcmp(file_MD5, IMAGE_MD5) == 0) {
		fprintf(stdout, "Image correctly donwloaded\n");
		fprintf(stdout, "TEST: %s succeeded\n", __func__);
	} else{
		fprintf(stdout, "Image no correctly donwloaded\n");
		fprintf(stdout, "TEST: %s failed\n", __func__);
	}

	artik_release_api_module(http);

	if (fp)
		fclose(fp);

	return ret;
}

artik_error test_http_get(bool verify, bool secure)
{
	artik_http_module *http = (artik_http_module *)
					artik_request_api_module("http");
	artik_error ret = S_OK;
	char *response = NULL;
	artik_ssl_config ssl_config = { 0 };
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"user-agent", "Artik browser"},
		{"Accept-Language", "en-US,en;q=0.8"},
	};

	memset(&ssl_config, 0, sizeof(ssl_config));

	ssl_config.ca_cert.data = (char *)httpbin_root_ca;
	ssl_config.ca_cert.len = strlen(httpbin_root_ca);

	if (verify)
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	fprintf(stdout, "TEST: %s starting\n", __func__);

	if (secure)
		ret = http->get("https://httpbin.org/get", &headers, &response,
							NULL, &ssl_config);
	else
		ret = http->get("http://httpbin.org/get", &headers, &response,
							NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
							response);
		free(response);
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(http);

	return ret;
}


artik_error test_http_post(bool verify, bool secure)
{
	artik_http_module *http = (artik_http_module *)
					artik_request_api_module("http");
	artik_error ret = S_OK;
	char *response = NULL;
	artik_ssl_config ssl_config = { 0 };
	char body[] = "name=samsung&project=artik";
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"user-agent", "Artik browser"},
		{"Accept-Language", "en-US,en;q=0.8"},
	};

	memset(&ssl_config, 0, sizeof(ssl_config));

	ssl_config.ca_cert.data = (char *)httpbin_root_ca;
	ssl_config.ca_cert.len = strlen(httpbin_root_ca);

	if (verify)
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	fprintf(stdout, "TEST: %s starting\n", __func__);

	if (secure)
		ret = http->post("https://httpbin.org/post", &headers, body,
						&response, NULL, &ssl_config);
	else
		ret = http->post("http://httpbin.org/post", &headers, body,
						&response, NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
						response);
		free(response);
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(http);

	return ret;
}

artik_error test_http_put(bool verify, bool secure)
{
	artik_http_module *http = (artik_http_module *)
					artik_request_api_module("http");
	artik_error ret = S_OK;
	char *response = NULL;
	artik_ssl_config ssl_config = { 0 };
	char body[] = "name=samsung&project=artik";
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"user-agent", "Artik browser"},
		{"Accept-Language", "en-US,en;q=0.8"},
	};

	memset(&ssl_config, 0, sizeof(ssl_config));

	ssl_config.ca_cert.data = (char *)httpbin_root_ca;
	ssl_config.ca_cert.len = strlen(httpbin_root_ca);

	if (verify)
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	fprintf(stdout, "TEST: %s starting\n", __func__);

	if (secure)
		ret = http->put("https://httpbin.org/put", &headers, body,
						&response, NULL, &ssl_config);
	else
		ret = http->put("http://httpbin.org/put", &headers, body,
						&response, NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
						response);
		free(response);
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(http);

	return ret;

}

artik_error test_http_del(bool verify, bool secure)
{
	artik_http_module *http = (artik_http_module *)
					artik_request_api_module("http");
	artik_error ret = S_OK;
	char *response = NULL;
	artik_ssl_config ssl_config = { 0 };
	artik_http_headers headers;
	artik_http_header_field fields[] = {
		{"user-agent", "Artik browser"},
		{"Accept-Language", "en-US,en;q=0.8"},
	};

	memset(&ssl_config, 0, sizeof(ssl_config));

	ssl_config.ca_cert.data = (char *)httpbin_root_ca;
	ssl_config.ca_cert.len = strlen(httpbin_root_ca);

	if (verify)
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	fprintf(stdout, "TEST: %s starting\n", __func__);

	if (secure)
		ret = http->del("https://httpbin.org/delete", &headers,
						&response, NULL, &ssl_config);
	else
		ret = http->del("http://httpbin.org/delete", &headers,
						&response, NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (err=%d)\n", __func__, ret);
		return ret;
	}

	if (response) {
		fprintf(stdout, "TEST: %s response data: %s\n", __func__,
								response);
		free(response);
	}

	fprintf(stdout, "TEST: %s succeeded\n", __func__);

	artik_release_api_module(http);

	return ret;
}

artik_error test_http_async(bool verify, bool secure)
{
	artik_http_module *http = (artik_http_module *)
					artik_request_api_module("http");
	artik_loop_module *loop = (artik_loop_module *)
					artik_request_api_module("loop");
	artik_error ret = S_OK;
	FILE *fp;
	char outfilename[FILENAME_MAX] = "./image.jpeg";
	artik_ssl_config ssl_config = { 0 };
	artik_http_headers headers;
	char body[] = "name=samsung&project=artik";
	artik_http_header_field fields[] = {
		{"user-agent", "Artik browser"},
		{"Accept-Language", "en-US,en;q=0.8"},
	};

	fp = fopen(outfilename, "wb");

	memset(&ssl_config, 0, sizeof(ssl_config));

	ssl_config.ca_cert.data = (char *)httpbin_root_ca;
	ssl_config.ca_cert.len = strlen(httpbin_root_ca);

	if (verify)
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	fprintf(stdout, "TEST: %s starting\n", __func__);

	if (secure)
		ret = http->get_stream_async("https://httpbin.org/image/jpeg",
			&headers, download_image, http_stream_response_callback,
			(void *)fp, &ssl_config);
	else
		ret = http->get_stream_async("http://httpbin.org/image/jpeg",
			&headers, download_image, http_stream_response_callback,
			(void *)fp, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (get_stream) (err=%d)\n",
			__func__, ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded (get_stream)\n", __func__);

	if (secure)
		ret = http->get_async("https://httpbin.org/get", &headers,
			http_response_callback, NULL, &ssl_config);
	else
		ret = http->get_async("https://httpbin.org/get", &headers,
			http_response_callback, NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (get) (err=%d)\n", __func__,
			ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded (get)\n", __func__);

	if (secure)
		ret = http->post_async("https://httpbin.org/post", &headers,
			body, http_response_callback, NULL, &ssl_config);
	else
		ret = http->post_async("https://httpbin.org/post", &headers,
			body, http_response_callback, NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (post) (err=%d)\n", __func__,
			ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded (post)\n", __func__);

	if (secure)
		ret = http->put_async("https://httpbin.org/put", &headers,
			body, http_response_callback, NULL, &ssl_config);
	else
		ret = http->put_async("https://httpbin.org/put", &headers,
			body, http_response_callback, NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (put)\n", __func__);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded (put)\n", __func__);

	if (secure)
		ret = http->del_async("https://httpbin.org/delete", &headers,
			http_response_callback, NULL, &ssl_config);
	else
		ret = http->del_async("https://httpbin.org/delete", &headers,
			http_response_callback, NULL, NULL);

	if (ret != S_OK) {
		fprintf(stdout, "TEST: %s failed (get) (err=%d)\n", __func__,
			ret);
		return ret;
	}

	fprintf(stdout, "TEST: %s succeeded (del)\n", __func__);

	signal(SIGINT, sig_handler);

	loop->run();

	fprintf(stdout, "TEST: %s finished\n", __func__);

	artik_release_api_module(http);
	artik_release_api_module(loop);

	return ret;
}

int main(int argc, char *argv[])
{
	int opt;
	artik_error ret = S_OK;
	bool verify = false;
	bool secure = false;

	if (!artik_is_module_available(ARTIK_MODULE_HTTP)) {
		fprintf(stdout,
			"TEST: HTTP module is not available,"\
			" skipping test...\n");
		return -1;
	}

	while ((opt = getopt(argc, argv, "vs")) != -1) {
		switch (opt) {
		case 'v':
			verify = true;
			break;
		case 's':
			secure = true;
			break;
		default:
			printf("Usage: http-test"\
				" [-v (for enabling verify root CA)]"\
				" [-s (for using HTTPS)]\r\n");
			return 0;
		}
	}

	ret = test_http_get_stream(verify, secure);
	if (ret != S_OK)
		goto exit;

	ret = test_http_get(verify, secure);
	if (ret != S_OK)
		goto exit;

	ret = test_http_post(verify, secure);
	if (ret != S_OK)
		goto exit;

	ret = test_http_put(verify, secure);
	if (ret != S_OK)
		goto exit;

	ret = test_http_del(verify, secure);
	if (ret != S_OK)
		goto exit;

	ret = test_http_async(verify, secure);

exit:
	return (ret == S_OK) ? 0 : -1;

}
