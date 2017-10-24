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
#include <errno.h>
#include <sys/stat.h>

#include <artik_module.h>
#include <artik_http.h>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define MAX_LONG 0x7FFFFFFF

artik_error test_http_get(char *root_ca, char *client_cert, char *client_key,
				char *ip_address, char *port, bool verify)
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
	char *url = NULL;

	memset(&ssl_config, 0, sizeof(ssl_config));

	if (root_ca) {
		ssl_config.ca_cert.data = root_ca;
		ssl_config.ca_cert.len = strlen(root_ca);
	}

	if (client_cert) {
		ssl_config.client_cert.data = client_cert;
		ssl_config.client_cert.len = strlen(client_cert);
	}

	if (client_key) {
		ssl_config.client_key.data = client_key;
		ssl_config.client_key.len = strlen(client_key);
	}

	if (verify)
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_REQUIRED;
	else
		ssl_config.verify_cert = ARTIK_SSL_VERIFY_NONE;

	if (ip_address && port) {
		int len = 8 + strlen(ip_address) + 1 + strlen(port) + 1;

		url = malloc(len);
		snprintf(url, len, "https://%s:%s", ip_address, port);
	} else if (ip_address && !port) {
		printf("Error: You must define the port.\n");
		printf("Usage: http-openssl-test"\
			" [-r <file of Root CA certificate>] ");
		printf("[-c <file of client certificate>]"\
			" [-k <file of client key>] ");
		printf("[-i <ip address of the server>]"\
			" [-p <port of the server>] ");
		printf("[-v (for enabling verify root CA)]\r\n");
		ret = E_BAD_ARGS;
	} else if (!ip_address && port) {
		printf("Error: You must define the IP address.\n");
		printf("Usage: http-openssl-test"\
			" [-r <file of Root CA certificate>] ");
		printf("[-c <file of client certificate>]"\
			" [-k <file of client key>] ");
		printf("[-i <ip address of the server>]"\
			" [-p <port of the server>] ");
		printf("[-v (for enabling verify root CA)]\r\n");
		ret = E_BAD_ARGS;
	} else {
		printf("Error: You must define the IP address and the port.\n");
		printf("Usage: http-openssl-test"\
			" [-r <file of Root CA certificate>] ");
		printf("[-c <file of client certificate>]"\
			" [-k <file of client key>] ");
		printf("[-i <ip address of the server>]"\
			" [-p <port of the server>] ");
		printf("[-v (for enabling verify root CA)]\r\n");
		ret = E_BAD_ARGS;
	}

	if (ret == E_BAD_ARGS)
		return ret;

	headers.fields = fields;
	headers.num_fields = ARRAY_SIZE(fields);

	fprintf(stdout, "TEST: %s starting\n", __func__);

	ret = http->get(url, &headers, &response, NULL, &ssl_config);

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

	free(url);

	artik_release_api_module(http);

	return ret;
}

int main(int argc, char *argv[])
{
	int opt;
	artik_error ret = S_OK;
	bool verify = false;

	char *root_ca = NULL; // Root CA certificate
	char *client_cert = NULL; // Client certificate
	char *client_key = NULL; // Client key
	char *ip_address = NULL; // IP Address of server
	char *port = NULL; // Port
	struct stat st;
	FILE *f;

	if (!artik_is_module_available(ARTIK_MODULE_HTTP)) {
		fprintf(stdout,
			"TEST: HTTP module is not available,"\
			" skipping test...\n");
		return -1;
	}

	while ((opt = getopt(argc, argv, "r:c:k:i:p:v")) != -1) {
		switch (opt) {
		case 'r':
			f = fopen(optarg, "rb");
			if (!f) {
				printf("File not found for parameter -r\n");
				ret = E_BAD_ARGS;
				goto exit;
			}
			if (fstat(fileno(f), &st) < 0) {
				printf("Failed to get file size");
				fclose(f);
				ret = E_BAD_ARGS;
				goto exit;
			}

			if (root_ca)
				free(root_ca);

			root_ca = malloc(st.st_size + 1);
			if (!root_ca) {
				fclose(f);
				ret = E_NO_MEM;
				goto exit;
			}

			if (!fread(root_ca, st.st_size, 1, f)) {
				fclose(f);
				printf("Failed to read root CA file\n");
				ret = E_BAD_ARGS;
				goto exit;
			}

			fclose(f);
			break;
		case 'c':
			f = fopen(optarg, "rb");
			if (!f) {
				printf("File not found for parameter -c\n");
				ret = E_BAD_ARGS;
				goto exit;
			}
			if (fstat(fileno(f), &st) < 0) {
				printf("Failed to get file size");
				fclose(f);
				ret = E_BAD_ARGS;
				goto exit;
			}

			if (client_cert)
				free(client_cert);

			client_cert = malloc(st.st_size + 1);
			if (!client_cert) {
				fclose(f);
				ret = E_NO_MEM;
				goto exit;
			}

			if (!fread(client_cert, st.st_size, 1, f)) {
				fclose(f);
				printf("Failed to read client certificate file\n");
				ret = E_BAD_ARGS;
				goto exit;
			}

			fclose(f);
			break;
		case 'k':
			f = fopen(optarg, "rb");
			if (!f) {
				printf("File not found for parameter -k\n");
				ret = E_BAD_ARGS;
				goto exit;
			}
			if (fstat(fileno(f), &st) < 0) {
				printf("Failed to get file size");
				fclose(f);
				ret = E_BAD_ARGS;
				goto exit;
			}

			if (client_key)
				free(client_key);

			client_key = malloc(st.st_size + 1);
			if (!client_key) {
				fclose(f);
				ret = E_NO_MEM;
				goto exit;
			}

			if (!fread(client_key, st.st_size, 1, f)) {
				fclose(f);
				printf("Failed to read client key file\n");
				ret = E_BAD_ARGS;
				goto exit;
			}

			fclose(f);
			break;
		case 'i':
			if (ip_address)
				free(ip_address);

			ip_address = strdup(optarg);
			break;
		case 'p':
			if (port)
				free(port);

			port = strdup(optarg);
			break;
		case 'v':
			verify = true;
			break;
		default:
			printf("Usage: http-openssl-test"\
				" [-r <file of Root CA certificate>] ");
			printf("[-c <file of client certificate>]"\
				" [-k <file of client key>] ");
			printf("[-i <ip address of the server>]"\
				" [-p <port of the server>] ");
			printf("[-v (for enabling verify root CA)]\r\n");
			ret = E_BAD_ARGS;
			goto exit;
		}
	}

	ret = test_http_get(root_ca, client_cert, client_key, ip_address, port,
									verify);
exit:
	if (client_key)
		free(client_key);
	if (client_cert)
		free(client_cert);
	if (root_ca)
		free(root_ca);
	if (ip_address)
		free(ip_address);
	if (port)
		free(port);

	return (ret == S_OK) ? 0 : -1;
}
