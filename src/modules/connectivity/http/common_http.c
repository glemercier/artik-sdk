#include "common_http.h"

artik_ssl_config *copy_ssl_config(artik_ssl_config *from)
{
	artik_ssl_config *to = NULL;

	if (!from)
		return NULL;

	to = malloc(sizeof(artik_ssl_config));
	if (!to)
		return NULL;

	memset(to, 0, sizeof(artik_ssl_config));
	memcpy(&to->se_config, &from->se_config, sizeof(artik_ssl_se_config));

	if (from->ca_cert.data) {
		to->ca_cert.len = from->ca_cert.len;
		to->ca_cert.data = strndup(from->ca_cert.data, from->ca_cert.len);
		if (!to->ca_cert.data)
			goto cleanup;
	}

	if (from->client_cert.data) {
		to->client_cert.len = from->client_cert.len;
		to->client_cert.data = strndup(from->client_cert.data, from->client_cert.len);
		if (!to->ca_cert.data)
			goto cleanup;
	}

	if (from->client_key.data) {
		to->client_key.len = from->client_key.len;
		to->client_key.data = strndup(from->client_key.data, from->client_key.len);
		if (!to->ca_cert.data)
			goto cleanup;
	}

	to->verify_cert = from->verify_cert;

	return to;

cleanup:
	free_ssl_config(to);
	return NULL;
}

artik_http_headers *copy_http_headers(artik_http_headers *from)
{
	artik_http_headers *to = malloc(sizeof(artik_http_headers));
	int i;

	if (!to)
		return NULL;

	to->fields = (artik_http_header_field *)malloc(
		sizeof(artik_http_header_field)*from->num_fields);
	if (!to->fields) {
		free(to);
		return NULL;
	}

	memset(to->fields, 0, sizeof(artik_http_header_field)*from->num_fields);

	to->num_fields = from->num_fields;
	for (i = 0; i < from->num_fields; i++) {
		if (from->fields[i].name) {
			to->fields[i].name = strdup(from->fields[i].name);
			if (!to->fields[i].name)
				goto cleanup;
		}

		if (from->fields[i].data) {
			to->fields[i].data = strdup(from->fields[i].data);
			if (!to->fields[i].name)
				goto cleanup;
		}
	}

	return to;

cleanup:
	free_http_headers(to);
	return NULL;
}

void free_ssl_config(artik_ssl_config *ssl)
{
	if (ssl->ca_cert.data)
		free(ssl->ca_cert.data);

	if (ssl->client_cert.data)
		free(ssl->client_cert.data);

	if (ssl->client_key.data)
		free(ssl->client_key.data);

	free(ssl);
}

void free_http_headers(artik_http_headers *headers)
{
	int i;

	for (i = 0; i < headers->num_fields; i++) {
		if (headers->fields[i].name)
			free(headers->fields[i].name);

		if (headers->fields[i].data)
			free(headers->fields[i].data);
	}
	free(headers->fields);
	free(headers);
}
