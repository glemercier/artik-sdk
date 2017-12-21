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
#include <string.h>
#include <errno.h>
#include <time.h>

#include <semaphore.h>

#include <artik_module.h>
#include <artik_log.h>
#include <artik_http.h>
#include <artik_security.h>

#include <apps/netutils/netlib.h>
#include <apps/netutils/webclient.h>

#include "common_http.h"
#include "os_http.h"
#include "tls/see_api.h"
#include "tinyara/tinyara_http.h"

#define ARTIK_HTTP_RESPONSE_MAX_SIZE	4096

#define	_HTTP_PREFIX	"http"
#define	_HTTPS_PREFIX	_HTTP_PREFIX"s"

#define _HTTP_API_TIMEOUT	10

struct _http_param {
	char *url;
	char *body;
	int method;
	artik_http_headers *headers;
	char **response;
	int *status;
	artik_ssl_config *ssl;
	artik_http_stream_callback stream_callback;
	artik_http_response_callback response_callback;
	void *user_data;
};

static int see_generate_random_client(void *ctx, unsigned char *data, size_t len)
{
	artik_security_module *security = NULL;
	artik_security_handle handle;

	if (!data || !len)
		return -1;

	security = (artik_security_module *)artik_request_api_module("security");
	security->request(&handle);
	security->get_random_bytes(handle, data, len);
	security->release(handle);
	artik_release_api_module(security);

	return 0;
}

static void http_tls_debug(void *ctx, int level, const char *file,
						   int line,
						   const char *str)
{
	log_dbg("%s:%04d: %s", file, line, str);
}

#ifdef CONFIG_NET_SECURITY_TLS
struct http_ssl_config_t {
	struct http_client_ssl_config_t *ssl;
	mbedtls_entropy_context *entropy;
	mbedtls_ctr_drbg_context *ctr_drbg;
	mbedtls_x509_crt *cert;
	mbedtls_pk_context *pkey;
	const mbedtls_pk_info_t *pk_info;
};

static void release_http_ssl_config(struct http_ssl_config_t *http_ssl_config)
{
	if (http_ssl_config->ctr_drbg) {
		mbedtls_ctr_drbg_free(http_ssl_config->ctr_drbg);
		free(http_ssl_config->ctr_drbg);
	}
	if (http_ssl_config->entropy) {
		mbedtls_entropy_free(http_ssl_config->entropy);
		free(http_ssl_config->entropy);
	}
	if (http_ssl_config->pkey) {
		mbedtls_pk_free(http_ssl_config->pkey);
		free(http_ssl_config->pkey);
	}
	if (http_ssl_config->cert) {
		mbedtls_x509_crt_free(http_ssl_config->cert);
		free(http_ssl_config->cert);
	}
	if (http_ssl_config->ssl->tls_conf)
		free(http_ssl_config->ssl->tls_conf);
	if (http_ssl_config->ssl->dev_cert)
		free(http_ssl_config->ssl->dev_cert);
	if (http_ssl_config->ssl->private_key)
		free(http_ssl_config->ssl->private_key);
	if (http_ssl_config->ssl)
		free(http_ssl_config->ssl);
}

static artik_error init_client_ssl_config(
			struct http_ssl_config_t **ssl_config,
			artik_ssl_config *a_ssl_config)
{
	int ret = S_OK;
	struct http_ssl_config_t *http_ssl_config =
		(struct http_ssl_config_t *) zalloc(sizeof(struct http_ssl_config_t));
	*ssl_config = http_ssl_config;
	if (http_ssl_config == NULL) {
		ret = E_NO_MEM;
		goto exit;
	}

	http_ssl_config->ssl =
		(struct http_client_ssl_config_t *) zalloc(sizeof(struct http_client_ssl_config_t));
	if (http_ssl_config->ssl == NULL) {
		ret = E_NO_MEM;
		goto exit;
	}

	http_ssl_config->ssl->tls_conf = zalloc(sizeof(mbedtls_ssl_config));
	if (!http_ssl_config->ssl->tls_conf) {
		ret = E_NO_MEM;
		goto exit;
	}

	http_ssl_config->entropy = zalloc(sizeof(mbedtls_entropy_context));
	if (!http_ssl_config->entropy) {
		ret = E_NO_MEM;
		goto exit;
	}

	http_ssl_config->ctr_drbg = zalloc(sizeof(mbedtls_ctr_drbg_context));
	if (!http_ssl_config->ctr_drbg) {
		ret = E_NO_MEM;
		goto exit;
	}

	mbedtls_ssl_config_init(http_ssl_config->ssl->tls_conf);
	mbedtls_ssl_config_defaults(http_ssl_config->ssl->tls_conf, MBEDTLS_SSL_IS_CLIENT,
				    MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_entropy_init(http_ssl_config->entropy);
	mbedtls_ctr_drbg_init(http_ssl_config->ctr_drbg);

	/* Seed the Random Number Generator */
	ret = mbedtls_ctr_drbg_seed(http_ssl_config->ctr_drbg, mbedtls_entropy_func, http_ssl_config->entropy, NULL, 0);
	if (ret) {
		log_err("Failed to seed RNG (err=%d)", ret);
		ret = E_BAD_ARGS;
		goto exit;
	}

	/* Setup default config */
	ret = mbedtls_ssl_config_defaults(http_ssl_config->ssl->tls_conf, MBEDTLS_SSL_IS_CLIENT,
			MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret) {
		log_err("Failed to set configuration defaults (err=%d)", ret);
		ret = E_BAD_ARGS;
		goto exit;
	}

	mbedtls_ssl_conf_dbg(http_ssl_config->ssl->tls_conf, http_tls_debug, stdout);
	mbedtls_ssl_conf_rng(http_ssl_config->ssl->tls_conf, mbedtls_ctr_drbg_random, http_ssl_config->ctr_drbg);
//#define MBED_DEBUG_LEVEL 0
#ifdef MBEDTLS_DEBUG_C
//	mbedtls_debug_set_threshold(MBED_DEBUG_LEVEL);
#endif

	if (a_ssl_config->se_config.use_se) {
		artik_security_handle handle;
		artik_error err = S_OK;
		char *se_cert = NULL;
		char *se_root_ca = NULL;
		artik_security_module *security = NULL;

		security = (artik_security_module *)
				artik_request_api_module("security");
		if (!security) {
			log_err("Security module is not available\n");
			ret = E_NOT_SUPPORTED;
			goto exit;
		}

		http_ssl_config->cert = zalloc(sizeof(mbedtls_x509_crt));
		if (!http_ssl_config->cert) {
			ret = E_NO_MEM;
			goto exit;
		}

		http_ssl_config->pkey = zalloc(sizeof(mbedtls_pk_context));
		if (!http_ssl_config->pkey) {
			ret = E_NO_MEM;
			goto exit;
		}

		err = security->request(&handle);
		if (err != S_OK) {
			log_err("Failed to request security instance (err=%d)\n", err);
			ret = E_NOT_SUPPORTED;
			goto exit;
		}

		err = security->get_certificate(handle, CERT_ID_ARTIK, &se_cert);
		if (err != S_OK || !se_cert) {
			log_err("Failed to get certificate (err=%d)\n", err);
			ret = E_ACCESS_DENIED;
			goto exit;
		}

		security->release(handle);
		artik_release_api_module(security);

		mbedtls_ssl_conf_rng(http_ssl_config->ssl->tls_conf, see_generate_random_client,
				http_ssl_config->ctr_drbg);
		mbedtls_x509_crt_init(http_ssl_config->cert);
		mbedtls_pk_init(http_ssl_config->pkey);

		ret = mbedtls_x509_crt_parse(http_ssl_config->cert, (const unsigned char *)se_cert,
				strlen(se_cert) + 1);
		if (ret) {
			log_err("Failed to parse device certificate (err=%d)", ret);
			free(se_cert);
			free(se_root_ca);
			ret = E_BAD_ARGS;
			goto exit;
		}

		http_ssl_config->pk_info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY);
		if (!http_ssl_config->pk_info) {
			log_err("Failed to get private key info");
			free(se_cert);
			free(se_root_ca);
			ret = E_BAD_ARGS;
			goto exit;
		}

		ret = mbedtls_pk_setup(http_ssl_config->pkey, http_ssl_config->pk_info);
		if (ret) {
			log_err("Failed to setup private key info");
			free(se_cert);
			free(se_root_ca);
			ret = E_BAD_ARGS;
			goto exit;
		}

		((mbedtls_ecdsa_context *)(http_ssl_config->pkey->pk_ctx))->grp.id =
				MBEDTLS_ECP_DP_SECP256R1;
		((mbedtls_ecdsa_context *)(http_ssl_config->pkey->pk_ctx))->key_index =
				FACTORYKEY_ARTIK_DEVICE;

		ret = mbedtls_ssl_conf_own_cert(
			http_ssl_config->ssl->tls_conf, http_ssl_config->cert, http_ssl_config->pkey);
		if (ret) {
			log_err("Failed to configure device cert/key (err=%d)", ret);
			free(se_cert);
			free(se_root_ca);
			ret = E_BAD_ARGS;
			goto exit;
		}

		free(se_cert);
		free(se_root_ca);

	} else {
		/* If not using SE, using optional client cert/key
		 * passed as parameters
		 */
		if (a_ssl_config->client_cert.data && a_ssl_config->client_key.data) {
			http_ssl_config->cert = zalloc(sizeof(mbedtls_x509_crt));
			if (!http_ssl_config->cert) {
				ret = E_NO_MEM;
				goto exit;
			}

			http_ssl_config->pkey = zalloc(sizeof(mbedtls_pk_context));
			if (!http_ssl_config->pkey) {
				ret = E_NO_MEM;
				goto exit;
			}

			mbedtls_x509_crt_init(http_ssl_config->cert);
			mbedtls_pk_init(http_ssl_config->pkey);

			ret = mbedtls_x509_crt_parse(http_ssl_config->cert,
					(const unsigned char *)a_ssl_config->client_cert.data,
					a_ssl_config->client_cert.len);
			if (ret) {
				log_err("Failed to parse device certificate (err=%d)", ret);
				ret = E_BAD_ARGS;
				goto exit;
			}

			ret = mbedtls_pk_parse_key(http_ssl_config->pkey,
					(const unsigned char *)a_ssl_config->client_key.data,
					a_ssl_config->client_key.len, NULL, 0);
			if (ret) {
				log_err("Failed to parse device key (err=%d)", ret);
				ret = E_BAD_ARGS;
				goto exit;
			}

			ret = mbedtls_ssl_conf_own_cert(http_ssl_config->ssl->tls_conf,
											http_ssl_config->cert,
											http_ssl_config->pkey);
			if (ret) {
				log_err("Failed to configure device cert/key (err=%d)", ret);
				ret = E_BAD_ARGS;
				goto exit;
			}
		}

		/* Load root CA if provided */
		if (a_ssl_config->ca_cert.data) {
			if (!http_ssl_config->cert) {
				http_ssl_config->cert = zalloc(sizeof(mbedtls_x509_crt));
				if (!http_ssl_config->cert) {
					ret = E_NO_MEM;
					goto exit;
				}
			}

			ret = mbedtls_x509_crt_parse(http_ssl_config->cert,
					(const unsigned char *)a_ssl_config->ca_cert.data,
					a_ssl_config->ca_cert.len);
			if (ret) {
				log_err("Failed to parse root CA certificate (err=%d)", ret);
				ret = E_BAD_ARGS;
				goto exit;
			}

			mbedtls_ssl_conf_ca_chain(http_ssl_config->ssl->tls_conf, http_ssl_config->cert->next ?
					http_ssl_config->cert->next : http_ssl_config->cert, NULL);
		}
	}

	switch (a_ssl_config->verify_cert) {
	case ARTIK_SSL_VERIFY_NONE:
		mbedtls_ssl_conf_authmode(http_ssl_config->ssl->tls_conf, MBEDTLS_SSL_VERIFY_NONE);
		break;
	case ARTIK_SSL_VERIFY_OPTIONAL:
		mbedtls_ssl_conf_authmode(http_ssl_config->ssl->tls_conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
		break;
	case ARTIK_SSL_VERIFY_REQUIRED:
	default:
		mbedtls_ssl_conf_authmode(http_ssl_config->ssl->tls_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
		break;
	}

	return S_OK;

exit:
	if (http_ssl_config) {
		release_http_ssl_config(http_ssl_config);
		free(http_ssl_config);
	}

	return ret;
}
#endif

static void wget_callback(char **buffer, int offset, int datend, int *buflen, void *user_data)
{
	struct _http_param *param = (struct _http_param *) user_data;

	param->stream_callback(*buffer + offset, datend - offset, param->user_data);
}

static pthread_addr_t _http_method_stream(void *arg)
{
#ifdef CONFIG_NET_SECURITY_TLS
	struct http_ssl_config_t *http_ssl_config = NULL;
#endif
	struct http_client_ssl_config_t *ssl = NULL;
	struct _http_param *param = (struct _http_param *)arg;
	char *buf = NULL;
	int status = 0;
	int ret = 0;

	log_dbg("");

	if (param->ssl) {
#ifdef CONFIG_NET_SECURITY_TLS
		ret = init_client_ssl_config(&http_ssl_config, param->ssl);
		if (ret != S_OK)
			goto exit;

		ssl = http_ssl_config->ssl;
#else
		ret = E_NOT_SUPPORTED;
		goto exit;
#endif
	}

	buf = (char *)malloc(sizeof(char)*4096);
	if (!buf) {
		ret = E_NO_MEM;
		goto exit;
	}

	ret = wget(param->url, &status, buf, 4096, wget_callback, param,
			param->ssl != NULL, ssl->tls_conf);
	if (ret < 0) {
		log_err("error has detected while http process(ret: %d)\n", ret);
		free(buf);
		buf = NULL;
		ret = E_HTTP_ERROR;
		goto exit;
	}

	ret = S_OK;
	free(buf);

exit:
#ifdef CONFIG_NET_SECURITY_TLS
	if (http_ssl_config) {
		release_http_ssl_config(http_ssl_config);
		free(http_ssl_config);
	}
#endif

	if (param->response_callback)
		param->response_callback(ret, status, NULL, param->user_data);

	return (pthread_addr_t)ret;
}

static pthread_addr_t _http_method(void *arg)
{
#ifdef CONFIG_NET_SECURITY_TLS
	struct http_ssl_config_t *http_ssl_config = NULL;
#endif
	struct http_client_ssl_config_t *ssl = NULL;
	struct _http_param *param = (struct _http_param *)arg;
	struct http_client_response_t response;
	struct http_client_request_t request;
	struct http_keyvalue_list_t headers;
	int ret = 0, i = 0;

	log_dbg("");

	memset(&request, 0, sizeof(request));
	request.method = param->method;
	request.url = (char *)param->url;
	request.buflen = ARTIK_HTTP_RESPONSE_MAX_SIZE;
	request.encoding = CONTENT_LENGTH;
	request.entity = (char *)param->body;

	ret = http_keyvalue_list_init(&headers);
	if (ret < 0) {
		log_err("Failed to initialize http_keyvalue_list_t");
		if (param->response_callback)
			param->response_callback(E_NO_MEM, 0, NULL, param->user_data);

		return (pthread_addr_t)E_NO_MEM;
	}

	for (i = 0; i < param->headers->num_fields; i++)
		http_keyvalue_list_add(&headers, param->headers->fields[i].name,
				param->headers->fields[i].data);

	request.headers = &headers;

	if (param->ssl) {
#ifdef CONFIG_NET_SECURITY_TLS
		ret = init_client_ssl_config(&http_ssl_config, param->ssl);
		if (ret != S_OK)
			goto exit;

		ssl = http_ssl_config->ssl;
#else
		ret = E_NOT_SUPPORTED;
		goto exit;
#endif
	}

	ret = http_client_response_init(&response);
	if (ret < 0) {
		log_err("error has detected while initializing response (ret: %d\n", ret);
		ret = E_HTTP_ERROR;
		goto exit;
	}

	ret = http_client_send_request(&request, ssl, &response);
	if (ret < 0 || response.entity_len <= 0) {
		log_err("error has detected while http process(ret: %d, len: %d)\n", ret,
				response.entity_len);
		http_client_response_release(&response);
		ret = E_HTTP_ERROR;
		goto exit;
	}

	if (param->response_callback) {
		char *entity = (char *)malloc(response.entity_len + 1);

		if (entity == NULL) {
			log_err("error has detected while memory allocation\n");
			http_client_response_release(&response);
			ret = E_NO_MEM;
			goto exit;
		}

		/* Copy response */
		memset(entity, 0, response.entity_len);
		memcpy(entity, response.entity, response.entity_len);
		entity[response.entity_len] = '\0';

		param->response_callback(ret, response.status, entity, param->user_data);

		free(entity);
	} else {
		*param->response = (char *)malloc(response.entity_len + 1);
		if (*param->response == NULL) {
			log_err("error has detected while memory allocation\n");
			http_client_response_release(&response);
			ret = E_NO_MEM;
			goto exit;
		}

		/* Copy response */
		memset(*param->response, 0, response.entity_len);
		memcpy(*param->response, response.entity, response.entity_len);
		(*param->response)[response.entity_len] = '\0';

		/* Copy status if pointer was provided */
		if (param->status)
			*param->status = response.status;
	}

	http_client_response_release(&response);
exit:
	http_keyvalue_list_release(&headers);
#ifdef CONFIG_NET_SECURITY_TLS
	if (http_ssl_config) {
		release_http_ssl_config(http_ssl_config);
		free(http_ssl_config);
	}
#endif

	if (ret != S_OK && param->response_callback)
		param->response_callback(ret, 0, NULL, param->user_data);

	return (pthread_addr_t)ret;
}

static pthread_addr_t _http_method_async(void *arg)
{
	struct _http_param *param = (struct _http_param *)arg;
	pthread_addr_t ret;

	if (param->stream_callback)
		ret = _http_method_stream(arg);
	else
		ret = _http_method(arg);

	if (param->body)
		free(param->body);

	if (param->ssl)
		free_ssl_config(param->ssl);

	free_http_headers(param->headers);
	free(param);

	return ret;
}

static artik_error _http_method_thread(struct _http_param *arg)
{
#define WEBCLIENT_STACK_SIZE   4096
#define WEBCLIENT_SCHED_PRI    100
#define WEBCLIENT_SCHED_POLICY SCHED_RR
	pthread_attr_t attr;
	int status;
	struct sched_param sparam;
	pthread_t tid;
	struct _http_param *thread_arg = NULL;

	status = pthread_attr_init(&attr);
	if (status != 0) {
		log_err("failed to start\n");
		return E_HTTP_ERROR;
	}

	sparam.sched_priority = WEBCLIENT_SCHED_PRI;
	(void)pthread_attr_setschedparam(&attr, &sparam);
	(void)pthread_attr_setschedpolicy(&attr, WEBCLIENT_SCHED_POLICY);
	(void)pthread_attr_setstacksize(&attr, WEBCLIENT_STACK_SIZE);

	thread_arg = malloc(sizeof(struct _http_param));
	if (!thread_arg)
		return E_NO_MEM;

	memset(thread_arg, 0, sizeof(struct _http_param));
	thread_arg->url = strdup(arg->url);

	if (arg->body) {
		thread_arg->body = strdup(arg->body);
		if (!thread_arg->body) {
			free(thread_arg);
			return E_NO_MEM;
		}
	}

	thread_arg->method = arg->method;
	thread_arg->headers = copy_http_headers(arg->headers);
	if (!thread_arg->headers) {
		if (thread_arg->body)
			free(thread_arg->body);

		free(thread_arg);
		return E_NO_MEM;
	}

	if (arg->ssl) {
		thread_arg->ssl = copy_ssl_config(arg->ssl);
		if (!thread_arg->ssl) {
			if (thread_arg->body)
				free(thread_arg->body);

			free_http_headers(thread_arg->headers);
			free(thread_arg);
		}
	}

	thread_arg->stream_callback = arg->stream_callback;
	thread_arg->response_callback = arg->response_callback;
	thread_arg->user_data = arg->user_data;

	status = pthread_create(&tid, &attr, _http_method_async, thread_arg);

	if (status < 0) {
		if (thread_arg->body)
			free(thread_arg->body);

		if (thread_arg->ssl)
			free_ssl_config(thread_arg->ssl);

		free_http_headers(thread_arg->headers);
		free(thread_arg);
		return (status == ENOMEM) ? E_NO_MEM : E_HTTP_ERROR;
	}

	pthread_setname_np(tid, __func__);
	pthread_detach(tid);

	return S_OK;

#undef WEBCLIENT_STACK_SIZE
#undef WEBCLIENT_SCHED_PRI
#undef WEBCLIENT_SCHED_POLICY
}

artik_error os_http_get_stream(const char *url, artik_http_headers *headers,
			int *status, artik_http_stream_callback callback, void *user_data,
			artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) NULL, WGET_MODE_GET,
			headers, NULL, status, ssl, callback, NULL, user_data
	};


	return (artik_error)_http_method_stream(&args);
}

artik_error os_http_get(const char *url, artik_http_headers *headers,
		char **response, int *status, artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) NULL, WGET_MODE_GET,
			headers, response, status, ssl, NULL, NULL, NULL
	};

	return (artik_error)_http_method(&args);
}

artik_error os_http_post(const char *url, artik_http_headers *headers,
		const char *body, char **response, int *status, artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) body, WGET_MODE_POST,
			headers, response, status, ssl, NULL, NULL
	};

	return (artik_error)_http_method(&args);
}

artik_error os_http_put(const char *url, artik_http_headers *headers,
		const char *body, char **response, int *status, artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) body, WGET_MODE_PUT,
			headers, response, status, ssl, NULL, NULL
	};

	return (artik_error)_http_method(&args);
}

artik_error os_http_delete(const char *url, artik_http_headers *headers,
		char **response, int *status, artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) NULL, WGET_MODE_DELETE,
			headers, response, status, ssl, NULL, NULL
	};

	return (artik_error)_http_method(&args);
}

artik_error os_http_get_stream_async(const char *url,
		artik_http_headers *headers, artik_http_stream_callback stream_callback,
		artik_http_response_callback response_callback, void *user_data,
		artik_ssl_config *ssl)
{
	struct _http_param args = {
		(char *) url, (char *) NULL, WGET_MODE_GET,
		headers, NULL, NULL, ssl, stream_callback, response_callback,
		user_data
	};

	return _http_method_thread(&args);
}

artik_error os_http_get_async(const char *url, artik_http_headers *headers,
		artik_http_response_callback callback, void *user_data,
		artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) NULL, WGET_MODE_GET,
			headers, NULL, NULL, ssl, NULL, callback, user_data
	};

	return _http_method_thread(&args);
}

artik_error os_http_post_async(const char *url, artik_http_headers *headers,
		const char *body, artik_http_response_callback callback,
		void *user_data, artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) body, WGET_MODE_GET,
			headers, NULL, NULL, ssl, NULL, callback, user_data
	};

	return _http_method_thread(&args);
}

artik_error os_http_put_async(const char *url, artik_http_headers *headers,
		const char *body, artik_http_response_callback callback,
		void *user_data, artik_ssl_config *ssl)
{
	struct _http_param args = {
			(char *) url, (char *) body, WGET_MODE_GET,
			headers, NULL, NULL, ssl, NULL, callback, user_data
	};

	return _http_method_thread(&args);
}

artik_error os_http_delete_async(const char *url, artik_http_headers *headers,
		artik_http_response_callback callback, void *user_data,
		artik_ssl_config *ssl)
{
	struct _http_param args = {
		(char *) url, (char *) NULL, WGET_MODE_GET,
		headers, NULL, NULL, ssl, NULL, callback, user_data
	};

	return _http_method_thread(&args);
}
