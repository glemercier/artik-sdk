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

#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <artik_websocket.h>
#include <artik_security.h>
#include <artik_log.h>
#include <websocket.h>

#include "tls/see_api.h"
#include "os_websocket.h"

#define MBED_DEBUG_LEVEL	0

struct websocket_priv {
	websocket_t *cli;
	artik_websocket_callback rx_cb;
	void *rx_user_data;
	artik_websocket_callback conn_cb;
	void *conn_user_data;
};

static int websocket_parse_uri(const char *uri, char **host, char **path,
		int *port, bool *use_tls)
{
	char *tmp = NULL;
	int idx = 0;

	*host = NULL;

	if (!strncmp(uri, "ws://", strlen("ws://"))) {
		*port = 80;
		*use_tls = false;
		idx += strlen("ws://");
	} else if (!strncmp(uri, "wss://", strlen("wss://"))) {
		*port = 443;
		*use_tls = true;
		idx += strlen("wss://");
	} else {
		log_err("Malformed URI: should start with 'ws://' or 'wss://'");
		return -1;
	}

	tmp = strchr(uri + idx, ':');
	if (tmp) {
		char *end = NULL;
		unsigned long p = strtoul(tmp + 1, &end, 10);

		if (p > 0)
			*port = (int)p;

		*host = strndup(uri + idx, tmp - (uri + idx));
		idx += end - tmp;
	}

	tmp = strchr(uri + idx, '/');
	if (!tmp) {
		log_err("Malformed URI: missing path after hostname");
		return -1;
	}

	if (*host == NULL)
		*host = strndup(uri + idx, tmp - (uri + idx));

	*path = strndup(tmp, strlen(tmp));

	return 0;
}

static ssize_t websocket_recv_cb(websocket_context_ptr ctx, uint8_t *buf,
			size_t len, int flags, void *user_data)
{
	struct websocket_info_t *info = user_data;
	int fd = info->data->fd;
	int retry_cnt = 3;
	ssize_t ret = 0;

	log_dbg("");

retry:
	if (info->data->tls_enabled) {
		ret = TLSRecv(info->data->tls_ssl, buf, len);
		if (!ret) {
			websocket_set_error(info->data,
						WEBSOCKET_ERR_CALLBACK_FAILURE);
		} else if (ret < 0) {
			log_dbg("SSL read error %d", ret);
			if (!retry_cnt) {
				websocket_set_error(info->data,
						WEBSOCKET_ERR_CALLBACK_FAILURE);
				return ret;
			}
			retry_cnt--;
			goto retry;
		}
	} else {
		ret = recv(fd, buf, len, 0);
		if (!ret) {
			websocket_set_error(info->data,
						WEBSOCKET_ERR_CALLBACK_FAILURE);
		} else if (ret > 0) {
			if ((errno == EAGAIN) || (errno == EBUSY)) {
				if (!retry_cnt) {
					websocket_set_error(info->data,
						WEBSOCKET_ERR_CALLBACK_FAILURE);
					return ret;
				}
				retry_cnt--;
				goto retry;
			}
		}
	}

	return ret;
}

ssize_t websocket_send_cb(websocket_context_ptr ctx, const uint8_t *buf,
			size_t len, int flags, void *user_data)
{
	struct websocket_info_t *info = user_data;
	int fd = info->data->fd;
	int retry_cnt = 3;
	ssize_t ret = 0;

	log_dbg("");

retry:
	if (info->data->tls_enabled) {
		ret = TLSSend(info->data->tls_ssl, buf, len);
		if (!ret) {
			websocket_set_error(info->data,
						WEBSOCKET_ERR_CALLBACK_FAILURE);
		} else if (ret < 0) {
			log_dbg("SSL write error %d", ret);
			if (!retry_cnt) {
				websocket_set_error(info->data,
						WEBSOCKET_ERR_CALLBACK_FAILURE);
				return ret;
			}
			retry_cnt--;
			goto retry;
		}
	} else {
		ret = send(fd, buf, len, flags);
		if (ret < 0) {
			if ((errno == EAGAIN) || (errno == EBUSY)) {
				if (!retry_cnt) {
					websocket_set_error(info->data,
						WEBSOCKET_ERR_CALLBACK_FAILURE);
					return ret;
				}
				retry_cnt--;
				goto retry;
			}
		}
	}

	return ret;
}

static int websocket_genmask_cb(websocket_context_ptr ctx, uint8_t *buf,
		size_t len, void *user_data)
{
	memset(buf, rand(), len);

	return 0;
}

void websocket_print_on_msg_cb(websocket_context_ptr ctx,
		const websocket_on_msg_arg *arg, void *user_data)
{
	struct websocket_info_t *info = user_data;
	struct websocket_priv *priv = (struct websocket_priv *)
							info->data->user_data;

	if (!priv)
		return;

	if (WEBSOCKET_CHECK_NOT_CTRL_FRAME(arg->opcode)) {
		if (priv->rx_cb) {
			char *msg = strndup((const char *)arg->msg,
							arg->msg_length);
			if (msg)
				priv->rx_cb(priv->rx_user_data, (void *)msg);
		}
	} else if (WEBSOCKET_CHECK_CTRL_PING(arg->opcode)) {
		log_dbg("MSG: Ping\n");
	} else if (WEBSOCKET_CHECK_CTRL_PONG(arg->opcode)) {
		log_dbg("MSG: Pong\n");
	}
}

void websocket_on_connectivity_change_callback(websocket_context_ptr ctx,
		enum websocket_connection_state state, void *user_data)
{
	struct websocket_info_t *info = user_data;
	struct websocket_priv *priv = (struct websocket_priv *)
							info->data->user_data;

	if (!priv)
		return;

	if (!priv->conn_cb)
		return;

	artik_websocket_connection_state artik_state = ARTIK_WEBSOCKET_CLOSED;
	switch (state) {
	case WEBSOCKET_CONNECTED:
		artik_state = ARTIK_WEBSOCKET_CONNECTED;
		break;
	case WEBSOCKET_CLOSED:
		artik_state = ARTIK_WEBSOCKET_CLOSED;
		break;
	}

	priv->conn_cb(priv->conn_user_data,
				  (void *)artik_state);
}

static websocket_cb_t callbacks = {
	websocket_recv_cb,		/* recv callback */
	websocket_send_cb,		/* send callback */
	websocket_genmask_cb,		/* gen mask callback */
	NULL,				/* recv frame start callback */
	NULL,				/* recv frame chunk callback */
	NULL,				/* recv frame end callback */
	websocket_print_on_msg_cb,	/* recv message callback */
	websocket_on_connectivity_change_callback
};

static void websocket_tls_debug(void *ctx, int level, const char *file,
								int line,
								const char *str)
{
	log_dbg("%s:%04d: %s", file, line, str);
}

static void ssl_cleanup(websocket_t *ws)
{
	log_dbg("");

	if (ws->tls_cred)
		free(ws->tls_cred);

	if (ws->tls_opt)
		free(ws->tls_opt);

	if (ws->tls_cred->ca_cert)
		free((unsigned char *)ws->tls_cred->ca_cert);

	if (ws->tls_cred->dev_cert)
		free((unsigned char *)ws->tls_cred->dev_cert);

	if (ws->tls_cred->dev_key)
		free((unsigned char *)ws->tls_cred->dev_key);

	/* Nullify everything */
	memset(ws->tls_cred, 0, sizeof(tls_cred));
	memset(ws->tls_opt, 0, sizeof(tls_opt));
}

static int see_generate_random_client(void *ctx, unsigned char *data,
								size_t len)
{
	artik_security_module *security = NULL;
	artik_security_handle handle;

	if (!data || !len)
		return -1;

	security = (artik_security_module *)
					artik_request_api_module("security");
	security->request(&handle);
	security->get_random_bytes(handle, data, len);
	security->release(handle);
	artik_release_api_module(security);

	return 0;
}

static artik_error ssl_setup(websocket_t *ws,
						artik_ssl_config *ssl_config){

	int ret = 0;

	log_dbg("");

	if (!ws->tls_enabled)
		return S_OK;

	ws->tls_opt = NULL;

	ws->tls_cred = zalloc(sizeof(tls_cred));
	if (!ws->tls_cred) {
		log_err("Failed to allocate tls_cred");
		return E_NO_MEM;
	}

	ws->tls_opt = zalloc(sizeof(tls_opt));
	if (!ws->tls_opt) {
		log_err("Failed to allocate tls_opt");
		ret = E_NO_MEM;
		goto exit;
	}

	memset(ws->tls_cred, 0, sizeof(tls_cred));
	memset(ws->tls_opt, 0, sizeof(tls_opt));

	if (ssl_config->ca_cert.data) {
		log_dbg("duplicate CA Cert");
		ws->tls_cred->ca_cert = (unsigned char *)strdup(ssl_config->ca_cert.data);
		ws->tls_cred->ca_certlen = ssl_config->ca_cert.len;
		if (!ws->tls_cred->ca_cert) {
			log_err("Failed to allocate ca_cert");
			ret = E_NO_MEM;
			goto exit;
		}
	}

	if (ssl_config->se_config.use_se) {
		artik_security_module *security = (artik_security_module *)
				artik_request_api_module("security");
		artik_security_handle handle;
		ws->tls_cred->use_se = true;

		ret = security->request(&handle);
		if (ret != S_OK) {
			log_err("Failed to load security module (err=%d)", ret);
			artik_release_api_module(handle);
			goto exit;
		}

		ret = security->get_certificate(handle, CERT_ID_ARTIK, (char **)&ws->tls_cred->dev_cert);
		if (ret != S_OK) {
			log_err("Failed to get device certificate (err=%d)", ret);
			artik_release_api_module(handle);
			goto exit;
		}

		security->release(handle);
		artik_release_api_module(security);

		ws->tls_cred->dev_certlen = strlen((char *)ws->tls_cred->dev_cert) + 1;
		ws->tls_cred->dev_key = NULL;
	} else if (ssl_config->client_key.data && ssl_config->client_cert.data) {
		ws->tls_cred->use_se = false;
		ws->tls_cred->dev_cert = (unsigned char *)strdup(ssl_config->client_cert.data);
		ws->tls_cred->dev_certlen = ssl_config->client_cert.len;
		if (!ws->tls_cred->dev_cert) {
			log_err("Failed to allocate device certificate");
			ret = E_NO_MEM;
			goto exit;
		}

		ws->tls_cred->dev_key = (unsigned char *)strdup(ssl_config->client_key.data);
		ws->tls_cred->dev_keylen = ssl_config->client_key.len;
		if (!ws->tls_cred->dev_key) {
			log_err("Failed to allocate device key");
			ret = E_NO_MEM;
			goto exit;
		}
	}

	log_dbg("Translate auth_mode");

	ws->tls_opt->debug_mode = MBED_DEBUG_LEVEL;
	ws->tls_opt->server = MBEDTLS_SSL_IS_CLIENT;
	ws->tls_opt->transport = MBEDTLS_SSL_TRANSPORT_STREAM;
	switch (ssl_config->verify_cert) {
	case ARTIK_SSL_VERIFY_NONE:
		ws->tls_opt->auth_mode = MBEDTLS_SSL_VERIFY_NONE;
		break;
	case ARTIK_SSL_VERIFY_OPTIONAL:
		ws->tls_opt->auth_mode = MBEDTLS_SSL_VERIFY_OPTIONAL;
		break;
	case ARTIK_SSL_VERIFY_REQUIRED:
		ws->tls_opt->auth_mode = MBEDTLS_SSL_VERIFY_REQUIRED;
		break;
	default:
		break;
	}

	log_dbg("Successfully create SSL config.");

	return S_OK;

exit:
	ssl_cleanup(ws);
	return ret;
}

artik_error os_websocket_open_stream(artik_websocket_config *config)
{
	struct websocket_priv *priv = NULL;
	websocket_return_t ret;
	char port_str[16];
	char *host = NULL;
	char *path = NULL;
	int port = 0;
	bool use_tls = false;

	log_dbg("");

	if (!config->uri) {
		log_err("Undefined uri");
		return E_WEBSOCKET_ERROR;
	}

	if (websocket_parse_uri(config->uri, &host, &path, &port, &use_tls)
									< 0) {
		log_err("Failed to parse uri");
		return E_WEBSOCKET_ERROR;
	}

	/* Allocate private data structure */
	priv = (struct websocket_priv *)zalloc(sizeof(struct websocket_priv));
	if (!priv) {
		log_err("Failed to allocate memory for private data");
		return E_NO_MEM;
	}

	priv->cli = (websocket_t *)zalloc(sizeof(websocket_t));
	if (!priv->cli) {
		log_err("Failed to allocate memory");
		free(priv);
		return E_NO_MEM;
	}

	/* Fill up the configuration structure */
	priv->cli->fd = -1;
	priv->cli->cb = &callbacks;
	priv->cli->tls_enabled = use_tls;
	priv->cli->user_data = (void *)priv;

	/* Setup TLS configuration if applicable */
	if (ssl_setup(priv->cli, &(config->ssl_config)) != S_OK) {
		log_err("Failed to configure SSL");
		free(priv->cli);
		free(priv);
		return E_BAD_ARGS;
	}

	/* Convert port integer into a string */
	if (!itoa(port, port_str, 10)) {
		log_err("Invalid port parameter");
		free(priv->cli);
		free(priv);
		return E_BAD_ARGS;
	}

	/* Open the websocket client connection */
	ret = websocket_client_open(priv->cli, host, port_str, path);
	if (ret != WEBSOCKET_SUCCESS) {
		log_err("Failed to open websocket client (ret=%d)", ret);
		free(priv->cli);
		free(priv);
		return E_WEBSOCKET_ERROR;
	}

	config->private_data = (void *)priv;

	return S_OK;
}

artik_error os_websocket_write_stream(artik_websocket_config *config,
							char *message, int len)
{
	struct websocket_priv *priv = (struct websocket_priv *)
							config->private_data;
	websocket_frame_t frame;
	websocket_return_t ret;

	log_dbg("");

	if (!priv)
		return E_NOT_INITIALIZED;

	frame.opcode = WEBSOCKET_TEXT_FRAME;
	frame.msg = (const uint8_t *)message;
	frame.msg_length = len;

	ret = websocket_queue_msg(priv->cli, &frame);
	if (ret != WEBSOCKET_SUCCESS) {
		log_err("Failed to send message (ret=%d)", ret);
		return E_WEBSOCKET_ERROR;
	}

	return S_OK;
}

artik_error os_websocket_set_connection_callback(artik_websocket_config *config,
		artik_websocket_callback callback, void *user_data)
{
	struct websocket_priv *priv = (struct websocket_priv *)
							config->private_data;

	log_dbg("");

	if (!priv)
		return E_NOT_INITIALIZED;

	priv->conn_cb = callback;
	priv->conn_user_data = user_data;

	/* If we are already connected, trigger the connected callback */
	if (priv->conn_cb && (priv->cli->state == WEBSOCKET_RUN_CLIENT))
		priv->conn_cb(priv->conn_user_data,
					(void *)ARTIK_WEBSOCKET_CONNECTED);

	return S_OK;
}

artik_error os_websocket_set_receive_callback(artik_websocket_config *config,
		artik_websocket_callback callback, void *user_data)
{
	struct websocket_priv *priv = (struct websocket_priv *)
							config->private_data;

	log_dbg("");

	if (!priv)
		return E_NOT_INITIALIZED;

	priv->rx_cb = callback;
	priv->rx_user_data = user_data;

	return S_OK;
}

artik_error os_websocket_close_stream(artik_websocket_config *config)
{
	struct websocket_priv *priv = (struct websocket_priv *)
							config->private_data;

	log_dbg("");

	if (!priv)
		return E_NOT_INITIALIZED;

	websocket_queue_close(priv->cli, NULL);
	ssl_cleanup(priv->cli);
	free(priv->cli);
	free(priv);

	return S_OK;
}



